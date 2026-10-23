"""MCP 协议层测试（T05）：帧格式、方法分发、错误码、stdout 纯净性、runtime.json。

三条最容易「看着绿其实假」的地方，这里都用硬断言堵住了：
  1. **帧格式**：直接断言写出的**字节**是 `b'{...}\\n'` 且不含 `Content-Length`。
  2. **stdout 纯净性**：起**真子进程**跑整个会话，逐行 `json.loads`。
  3. **错误码**：-32700 / -32600 / -32601 / -32602 / -32603 各有独立用例，
     不用「返回了 error 就算过」这种模糊断言。
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import mcp_server, mcp_tools, runtime
from pwdvault.models import Record


def _frame(message: dict) -> bytes:
    """按规范应该写出的字节（测试里独立实现一遍，不复用被测代码）。"""
    return (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _session(fixture) -> mcp_tools.McpSession:
    """直接注入已解锁的 Vault：协议层测试不该依赖解锁链。"""
    return mcp_tools.McpSession(fixture.settings, vault=fixture.vault, unlocked_by="test")


class TransportFrameTest(unittest.TestCase):
    """① 帧格式：newline-delimited JSON，绝不是 LSP 的 Content-Length。"""

    def test_write_message_is_one_line_json(self) -> None:
        out = io.BytesIO()
        transport = mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=out)
        message = {"jsonrpc": "2.0", "id": 1, "result": {}}
        transport.write_message(message)

        data = out.getvalue()
        self.assertEqual(data, b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertNotIn(b"Content-Length", data)
        self.assertNotIn(b"\r", data)
        self.assertEqual(json.loads(data.decode("utf-8")), message)

    def test_write_message_keeps_chinese_as_utf8(self) -> None:
        out = io.BytesIO()
        transport = mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=out)
        transport.write_message({"jsonrpc": "2.0", "id": 7, "result": {"title": "淘宝"}})

        data = out.getvalue()
        self.assertIn("淘宝".encode("utf-8"), data)
        self.assertNotIn(b"\\u6dd8", data)  # 不是 \uXXXX 转义
        self.assertTrue(data.startswith(b'{"jsonrpc"'))  # 没有 BOM

    def test_full_session_never_emits_content_length(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        out = io.BytesIO()
        transport = mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=out)
        server = mcp_server.McpServer(fixture.settings, transport=transport, session=_session(fixture))

        for message in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        ):
            transport.write_message(server.handle_message(message))

        data = out.getvalue()
        self.assertNotIn(b"Content-Length", data)
        self.assertEqual(len([line for line in data.split(b"\n") if line]), 3)

    def test_read_message_eof_and_blank_lines(self) -> None:
        payload = b'\n\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        transport = mcp_server.StdioTransport(stdin=io.BytesIO(payload), stdout=io.BytesIO())
        self.assertEqual(transport.read_message(), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertIsNone(transport.read_message())  # EOF

    def test_read_message_empty_input_is_eof(self) -> None:
        transport = mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=io.BytesIO())
        self.assertIsNone(transport.read_message())

    def test_overlong_line_is_rejected_without_buffering(self) -> None:
        transport = mcp_server.StdioTransport(
            stdin=io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'),
            stdout=io.BytesIO(),
        )
        with mock.patch.object(mcp_server, "MAX_LINE_BYTES", 8):
            result = transport.read_message()
        # 超长行用返回值表达（不是抛异常），这样主循环可以继续服务下一条消息
        self.assertIsInstance(result, mcp_server.ParseFailure)
        self.assertEqual(result.reason, "too_long")

    def test_overlong_line_maps_to_invalid_request_in_loop(self) -> None:
        """serve_forever 里「超长行」→ -32600（区别于坏 JSON 的 -32700）。"""
        out = io.BytesIO()
        stdin = io.BytesIO(b"x" * 64 + b"\n")
        server = mcp_server.McpServer(
            support.make_vault(support.make_home(self)).settings,
            transport=mcp_server.StdioTransport(stdin=stdin, stdout=out),
        )
        with mock.patch.object(mcp_server, "MAX_LINE_BYTES", 16):
            self.assertEqual(server.serve_forever(), 0)
        reply = json.loads(out.getvalue().decode("utf-8").strip())
        self.assertEqual(reply["error"]["code"], mcp_server.INVALID_REQUEST)
        self.assertIsNone(reply["id"])


class HandshakeTest(unittest.TestCase):
    """② initialize 三版本回显 + 回退；③ ping；④ tools/list。"""

    def setUp(self) -> None:
        home = support.make_home(self)
        self.fixture = support.make_vault(home)
        self.server = mcp_server.McpServer(
            self.fixture.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=io.BytesIO()),
            session=_session(self.fixture),
        )

    def _initialize(self, version: str) -> dict:
        reply = self.server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {"roots": {"listChanged": True}},
                    "clientInfo": {"name": "WorkBuddy", "version": "2.3.0"},
                },
            }
        )
        self.assertIsNotNone(reply)
        return reply

    def test_echoes_each_supported_protocol_version(self) -> None:
        for version in mcp_server.PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                reply = self._initialize(version)
                self.assertEqual(reply["result"]["protocolVersion"], version)

    def test_falls_back_to_latest_for_unknown_version(self) -> None:
        reply = self._initialize("1999-01-01")
        self.assertEqual(reply["result"]["protocolVersion"], mcp_server.LATEST_PROTOCOL_VERSION)
        self.assertEqual(mcp_server.LATEST_PROTOCOL_VERSION, "2025-06-18")

    def test_capabilities_and_server_info(self) -> None:
        result = self._initialize("2025-06-18")["result"]
        self.assertEqual(result["capabilities"], {"tools": {}})
        self.assertEqual(result["serverInfo"]["name"], "pwdvault")
        self.assertEqual(result["serverInfo"]["version"], "1.1.0")
        self.assertIn("instructions", result)
        self.assertTrue(result["instructions"])

    def test_ping_returns_empty_result(self) -> None:
        reply = self.server.handle_message({"jsonrpc": "2.0", "id": 9, "method": "ping"})
        self.assertEqual(reply, {"jsonrpc": "2.0", "id": 9, "result": {}})

    def test_tools_list_is_well_formed(self) -> None:
        reply = self.server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = reply["result"]["tools"]
        self.assertIsInstance(tools, list)
        self.assertGreaterEqual(len(tools), 5)

        names = {tool["name"] for tool in tools}
        for expected in ("vault_status", "vault_search", "vault_get", "vault_copy", "vault_totp"):
            self.assertIn(expected, names)

        for tool in tools:
            with self.subTest(tool=tool["name"]):
                self.assertTrue(tool["name"].startswith("vault_"))
                self.assertTrue(tool["title"])
                self.assertGreater(len(tool["description"]), 10)
                schema = tool["inputSchema"]
                self.assertEqual(schema["type"], "object")
                self.assertIn("properties", schema)
                # 必须可 JSON 序列化（客户端会原样解析）
                json.loads(json.dumps(tool, ensure_ascii=False))

    def test_id_type_is_preserved(self) -> None:
        for request_id in (1, "abc-123", 0):
            with self.subTest(request_id=request_id):
                reply = self.server.handle_message(
                    {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
                )
                self.assertEqual(reply["id"], request_id)
                self.assertIs(type(reply["id"]), type(request_id))


class ErrorCodeTest(unittest.TestCase):
    """⑤ 错误码表：-32700 / -32600 / -32601（+ -32602 / -32603 的映射）。"""

    def setUp(self) -> None:
        home = support.make_home(self)
        self.fixture = support.make_vault(home)
        self.server = mcp_server.McpServer(
            self.fixture.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=io.BytesIO()),
            session=_session(self.fixture),
        )

    def test_parse_error_32700(self) -> None:
        out = io.BytesIO()
        server = mcp_server.McpServer(
            self.fixture.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(b'{"jsonrpc": oops\n'), stdout=out),
        )
        self.assertEqual(server.serve_forever(), 0)
        reply = json.loads(out.getvalue().decode("utf-8").strip())
        self.assertEqual(reply["jsonrpc"], "2.0")
        self.assertEqual(reply["error"]["code"], -32700)
        self.assertEqual(reply["error"]["message"], "Parse error")
        self.assertIsNone(reply["id"])

    def test_invalid_request_32600_for_missing_jsonrpc(self) -> None:
        reply = self.server.handle_message({"id": 1, "method": "ping"})
        self.assertEqual(reply["error"]["code"], -32600)
        self.assertEqual(reply["id"], 1)

    def test_invalid_request_32600_for_wrong_version(self) -> None:
        reply = self.server.handle_message({"jsonrpc": "1.0", "id": 2, "method": "ping"})
        self.assertEqual(reply["error"]["code"], -32600)

    def test_invalid_request_32600_for_missing_method(self) -> None:
        reply = self.server.handle_message({"jsonrpc": "2.0", "id": 3, "params": {}})
        self.assertEqual(reply["error"]["code"], -32600)
        self.assertEqual(reply["id"], 3)

    def test_invalid_request_32600_for_non_object_message(self) -> None:
        reply = self.server.handle_message([1, 2, 3])
        self.assertEqual(reply["error"]["code"], -32600)
        self.assertIsNone(reply["id"])

    def test_method_not_found_32601(self) -> None:
        reply = self.server.handle_message({"jsonrpc": "2.0", "id": 4, "method": "tools/subscribe"})
        self.assertEqual(reply["error"]["code"], -32601)
        self.assertIn("tools/subscribe", reply["error"]["message"])

    def test_unknown_tool_is_invalid_params_32602(self) -> None:
        reply = self.server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "vault_delete", "arguments": {}},
            }
        )
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertEqual(reply["error"]["message"], "Unknown tool: vault_delete")
        self.assertNotIn("result", reply)

    def test_invalid_arguments_is_invalid_params_32602(self) -> None:
        reply = self.server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "vault_copy", "arguments": {}},
            }
        )
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("vault_copy", reply["error"]["message"])

    def test_unexpected_exception_is_internal_error_32603(self) -> None:
        with mock.patch.object(mcp_server, "call_tool", side_effect=RuntimeError("boom")):
            reply = self.server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "vault_status", "arguments": {}},
                }
            )
        self.assertEqual(reply["error"]["code"], -32603)
        self.assertEqual(reply["error"]["message"], "internal error")
        self.assertNotIn("boom", json.dumps(reply, ensure_ascii=False))

    def test_business_error_is_result_not_jsonrpc_error(self) -> None:
        """业务错误（未解锁）必须是 `result.isError=true`，不是 JSON-RPC error。"""
        home = support.make_home(self)
        fixture = support.make_vault(home)
        locked = mcp_tools.McpSession(fixture.settings, env={})
        server = mcp_server.McpServer(
            fixture.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=io.BytesIO()),
            session=locked,
        )
        reply = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "vault_search", "arguments": {"query": "淘宝"}},
            }
        )
        self.assertNotIn("error", reply)
        result = reply["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["code"], "locked")
        self.assertEqual(result["content"][0]["type"], "text")
        self.assertEqual(json.loads(result["content"][0]["text"])["code"], "locked")


class NotificationTest(unittest.TestCase):
    """⑧ 通知不产生响应。"""

    def setUp(self) -> None:
        home = support.make_home(self)
        self.fixture = support.make_vault(home)
        self.server = mcp_server.McpServer(
            self.fixture.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=io.BytesIO()),
            session=_session(self.fixture),
        )

    def test_notifications_initialized_returns_none(self) -> None:
        self.assertIsNone(
            self.server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )

    def test_unknown_notification_returns_none(self) -> None:
        self.assertIsNone(
            self.server.handle_message(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
            )
        )

    def test_request_without_id_is_treated_as_notification(self) -> None:
        self.assertIsNone(self.server.handle_message({"jsonrpc": "2.0", "method": "tools/list"}))

    def test_session_produces_no_bytes_for_notifications(self) -> None:
        payload = (
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
            b'{"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n'
        )
        out = io.BytesIO()
        server = mcp_server.McpServer(
            self.fixture.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(payload), stdout=out),
        )
        self.assertEqual(server.serve_forever(), 0)
        self.assertEqual(out.getvalue(), b"")


class StdoutPurityTest(unittest.TestCase):
    """⑥ 最重要的一条：真进程跑整个会话，stdout 每一行都必须是合法 JSON。"""

    def _run_session(self) -> tuple[subprocess.CompletedProcess, bytes]:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        fixture.vault.records.append(
            Record(
                title="淘宝",
                username="zhangsan",
                password=support.SENTINEL_PW,
                url="https://taobao.com",
                notes=support.SENTINEL_NOTE,
            )
        )
        fixture.vault.save()
        support.write_config(home, fixture.settings.vault_path)

        lines = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "qa", "version": "0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": "three",
                "method": "tools/call",
                "params": {"name": "vault_search", "arguments": {"query": "淘宝"}},
            },
            {"jsonrpc": "2.0", "id": 4, "method": "no/such/method"},
            {"jsonrpc": "2.0", "id": 5, "method": "ping"},
        ]
        payload = b"".join(_frame(message) for message in lines)

        environ = os.environ.copy()
        environ["PV_HOME"] = str(home)
        environ["PV_MASTER_PASSWORD"] = support.PASSWORD
        environ.pop("PV_VAULT", None)
        environ.pop("PV_RECOVERY_CODE", None)

        proc = subprocess.run(
            [support.PYTHON, "-m", "pwdvault.mcp_server"],
            cwd=str(support.PROJECT_ROOT),
            env=environ,
            input=payload,
            capture_output=True,
            timeout=180,
        )
        return proc, payload

    def test_every_stdout_line_is_json(self) -> None:
        proc, _payload = self._run_session()
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", errors="replace"))

        raw = proc.stdout
        self.assertNotIn(b"Content-Length", raw)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "stdout 不能有 UTF-8 BOM")

        text = raw.decode("utf-8")  # 严格解码：任何非法字节都会在这里炸
        lines = [line for line in text.split("\n") if line.strip()]
        self.assertEqual(len(lines), 5, f"应当只有 5 条响应，实际 {len(lines)}: {lines}")

        replies = [json.loads(line) for line in lines]  # 每行都必须能解析
        self.assertEqual([reply["id"] for reply in replies], [1, 2, "three", 4, 5])
        for reply in replies:
            self.assertEqual(reply["jsonrpc"], "2.0")

        search = replies[2]["result"]
        self.assertFalse(search["isError"])
        self.assertEqual(search["structuredContent"]["count"], 1)
        self.assertEqual(search["content"][0]["type"], "text")

        self.assertEqual(replies[3]["error"]["code"], mcp_server.METHOD_NOT_FOUND)
        self.assertEqual(replies[4]["result"], {})

        # 日志只能出现在 stderr
        self.assertIn("event=start", proc.stderr.decode("utf-8", errors="replace"))
        self.assertNotIn(b"[pv", raw)

    def test_stdout_has_no_password(self) -> None:
        proc, _payload = self._run_session()
        self.assertNotIn(support.SENTINEL_PW.encode("utf-8"), proc.stdout)
        self.assertIn("淘宝".encode("utf-8"), proc.stdout)  # 反向对照：真返回了数据

    def test_install_stdout_guard_redirects_print(self) -> None:
        fake_out = io.BytesIO()
        real_stdout = sys.stdout
        real_stderr = sys.stderr
        captured = io.StringIO()
        try:
            sys.stderr = captured
            installed = mcp_server.install_stdout_guard(fake_out)
            self.assertIs(installed, fake_out)
            self.assertIs(sys.stdout, sys.stderr)
            print("这条 stray print 必须去 stderr")
        finally:
            sys.stdout = real_stdout
            sys.stderr = real_stderr

        self.assertEqual(fake_out.getvalue(), b"")
        self.assertIn("stray print", captured.getvalue())


class RuntimeFileTest(unittest.TestCase):
    """⑦ runtime.json 写/读/假 pid 判定。"""

    def test_write_and_read_roundtrip(self) -> None:
        home = support.make_home(self)
        path = runtime.write_runtime(home, port=8765, token="tok-abc", pid=os.getpid())
        self.assertTrue(path.is_file())

        info = runtime.read_runtime(home)
        self.assertIsNotNone(info)
        self.assertEqual(info["port"], 8765)
        self.assertEqual(info["token"], "tok-abc")
        self.assertEqual(info["pid"], os.getpid())
        self.assertEqual(info["host"], "127.0.0.1")
        self.assertEqual(info["version"], runtime.RUNTIME_VERSION)

    def test_runtime_file_is_not_world_readable(self) -> None:
        home = support.make_home(self)
        path = runtime.write_runtime(home, port=1, token="t", pid=os.getpid())
        mode = path.stat().st_mode & 0o777
        if os.name == "posix":
            self.assertEqual(mode, 0o600)
        else:
            # Windows：chmod 只能改只读位，这里只断言「尽力而为」没有炸
            self.assertIsInstance(mode, int)

    def test_read_missing_returns_none(self) -> None:
        self.assertIsNone(runtime.read_runtime(support.make_home(self)))

    def test_read_invalid_returns_none(self) -> None:
        home = support.make_home(self)
        path = runtime.runtime_path(home)
        for bad in ("not json", "[]", '{"port": 0, "token": "x", "pid": 1}', '{"port": 8765, "token": "", "pid": 1}'):
            with self.subTest(bad=bad):
                path.write_text(bad, encoding="utf-8")
                self.assertIsNone(runtime.read_runtime(home))

    def test_clear_runtime(self) -> None:
        home = support.make_home(self)
        runtime.write_runtime(home, port=1, token="t", pid=os.getpid())
        self.assertTrue(runtime.clear_runtime(home))
        self.assertIsNone(runtime.read_runtime(home))
        self.assertFalse(runtime.clear_runtime(home))

    def test_is_alive_fake_pid_is_false(self) -> None:
        self.assertFalse(runtime.is_alive(999_999_999))
        self.assertFalse(runtime.is_alive(0))
        self.assertFalse(runtime.is_alive(-1))
        self.assertFalse(runtime.is_alive(None))
        self.assertFalse(runtime.is_alive("not-a-pid"))
        self.assertTrue(runtime.is_alive(os.getpid()))

    def test_describe_reports_presence(self) -> None:
        home = support.make_home(self)
        self.assertEqual(runtime.describe(home)["present"], False)
        runtime.write_runtime(home, port=1234, token="t", pid=os.getpid())
        info = runtime.describe(home)
        self.assertTrue(info["present"])
        self.assertTrue(info["alive"])
        self.assertEqual(info["port"], 1234)

    def test_proxy_backend_is_stub(self) -> None:
        backend = runtime.ProxyBackend({"port": 8765})
        with self.assertRaises(NotImplementedError):
            backend.open(None)
        with self.assertRaises(NotImplementedError):
            backend.call("vault_status", {})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
