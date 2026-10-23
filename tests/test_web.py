"""Web 骨架（T08）测试：安全三件套、路径穿越、Content-Length、SSE、自锁、端口顺延、runtime.json。

覆盖 DESIGN §10.1 `test_web.py` 的 14 项，并额外钉住三件事：
  - 20 个并发 SSE 订阅**不串包**且断开后队列清空（订阅者数回到 0）；
  - 所有非 SSE 响应都带 `Content-Length`（用 raw socket 读原始字节，不信 `http.client`）；
  - `runtime.json` 由**真子进程**启动时创建、退出时删除。

时间控制：空闲自锁既有「注入时钟」的确定性用例，也有一个真线程的用例（0.4s 阈值，
总等待 <1s）。SSE 心跳用 0.15s 的小阈值，不真等 15 秒。
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault.errors import Refused
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record
from pwdvault.vault import Vault
from pwdvault.web.events import (
    CLOSE_EVENT,
    KEEPALIVE_BYTES,
    LAG_EVENT,
    EventBus,
    encode_chunk,
    encode_sse,
)
from pwdvault.web.server import COOKIE_NAME, TOKEN_HEADER, WebServer
from pwdvault.web.session import AppState

#: 探针：放在静态目录**外面**，任何泄漏都能被 `assertNotIn` 抓到
SECRET_PROBE = "ZZ-PvProbe-WebOutOfRoot-3f9c-DO-NOT-LEAK"

_DEFAULT = object()


# ---------------------------------------------------------------- 工具
def raw_exchange(port: int, request: bytes, *, timeout: float = 5.0) -> tuple[int, dict, bytes]:
    """用裸 socket 发一次请求，读回**原始字节**并拆头。

    `http.client` 会帮我们补齐 `Host`、也可能忽略畸形头，所以安全类断言必须走裸
    socket —— 否则「Content-Length 缺失」这种 bug 会被客户端库的宽容掩盖掉。
    """
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(request)
        sock.settimeout(timeout)
        chunks: list[bytes] = []
        while True:
            try:
                part = sock.recv(65536)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
    return parse_response(b"".join(chunks))


def parse_response(raw: bytes) -> tuple[int, dict, bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    return status, headers, body


def build_raw(
    port: int,
    method: str,
    path: str,
    *,
    host: str | None = None,
    cookie: str | None = None,
    extra: list[str] | None = None,
    close: bool = True,
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host or f'127.0.0.1:{port}'}"]
    if close:
        lines.append("Connection: close")
    if cookie is not None:
        lines.append(f"Cookie: {COOKIE_NAME}={cookie}")
    lines.extend(extra or [])
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


class ChunkReader:
    """读 chunked 响应体：`<hex长度> CRLF <数据> CRLF`。"""

    def __init__(self, sock: socket.socket, buffer: bytes = b"") -> None:
        self.sock = sock
        self.buf = buffer

    def _fill(self, size: int) -> None:
        while len(self.buf) < size:
            part = self.sock.recv(65536)
            if not part:
                raise EOFError("连接被关闭")
            self.buf += part

    def read_line(self) -> bytes:
        while b"\r\n" not in self.buf:
            part = self.sock.recv(65536)
            if not part:
                raise EOFError("连接被关闭")
            self.buf += part
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line

    def read_chunk(self) -> bytes:
        line = self.read_line()
        size = int((line.split(b";")[0].strip() or b"0"), 16)
        if size == 0:
            return b""
        self._fill(size + 2)
        body, tail, self.buf = self.buf[:size], self.buf[size : size + 2], self.buf[size + 2 :]
        if tail != b"\r\n":
            raise AssertionError(f"chunk 结尾不是 CRLF：{tail!r}")
        return body


class WebFixture:
    """起一个真的 `WebServer`（临时端口），默认已解锁。"""

    def __init__(
        self,
        case: unittest.TestCase,
        *,
        unlock: bool = True,
        auto_lock_seconds: float | None = None,
        heartbeat_seconds: float = 15.0,
        poll_seconds: float = 60.0,
        idle_check_seconds: float = 1.0,
        static_root: str | Path | None = None,
        state: AppState | None = None,
        token: str | None = None,
    ) -> None:
        self.home = support.make_home(case)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.password = fixture.password
        self.recovery = fixture.recovery
        self.server = WebServer(
            self.settings,
            port=0,
            open_browser=False,
            quiet=True,
            static_root=static_root,
            state=state,
            token=token,
            auto_lock_seconds=auto_lock_seconds,
            poll_seconds=poll_seconds,
            idle_check_seconds=idle_check_seconds,
            heartbeat_seconds=heartbeat_seconds,
        )
        self.server.start()
        self._serve_thread = self.server.start_in_thread()
        case.addCleanup(self._join_serve_thread)
        case.addCleanup(self.server.stop)
        if unlock and state is None:
            self.server.state.unlock(password=self.password)

    def _join_serve_thread(self) -> None:
        self._serve_thread.join(timeout=5.0)

    # ---- 便捷访问
    @property
    def port(self) -> int:
        return self.server.port

    @property
    def token(self) -> str:
        return self.server.token

    @property
    def state(self) -> AppState:
        return self.server.state

    def request(
        self,
        method: str,
        path: str,
        *,
        body: object = None,
        token: object = _DEFAULT,
        cookie: object = _DEFAULT,
        host: str | None = None,
        origin: str | None = None,
    ) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers: dict[str, str] = {}
        if token is not False:
            headers[TOKEN_HEADER] = self.token if token is _DEFAULT else str(token)
        if cookie is not False:
            value = self.token if cookie is _DEFAULT else str(cookie)
            headers["Cookie"] = f"{COOKIE_NAME}={value}"
        if host is not None:
            headers["Host"] = host
        if origin is not None:
            headers["Origin"] = origin
        payload = None
        if body is not None:
            payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            data = response.read()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            conn.close()

    def raw(self, method: str, path: str, **kwargs: object) -> tuple[int, dict, bytes]:
        return raw_exchange(self.port, build_raw(self.port, method, path, **kwargs))

    def open_sse(self, *, cookie: object = _DEFAULT) -> tuple[socket.socket, dict, "ChunkReader"]:
        """打开一条 SSE 连接，读完响应头，返回 (socket, headers, chunk reader)。"""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        value = self.token if cookie is _DEFAULT else str(cookie)
        sock.sendall(build_raw(self.port, "GET", "/api/events", cookie=value, close=False))
        raw_head = b""
        while b"\r\n\r\n" not in raw_head:
            part = sock.recv(4096)
            if not part:
                raise AssertionError("SSE 连接被立刻关闭")
            raw_head += part
        head, _, rest = raw_head.partition(b"\r\n\r\n")
        _, headers, _ = parse_response(head + b"\r\n\r\n")
        return sock, headers, ChunkReader(sock, rest)



# ---------------------------------------------------------------- 安全三件套
class SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = WebFixture(self)

    def test_host_whitelist_rejects_dns_rebinding(self) -> None:
        status, _, body = self.web.request("GET", "/api/session", host="evil.com")
        self.assertEqual(400, status)
        self.assertEqual("bad_host", json.loads(body)["code"])

        status, _, _ = self.web.request("GET", "/api/session", host=f"127.0.0.1:{self.web.port + 1}")
        self.assertEqual(400, status, "端口不一致的 Host 也必须拒绝")

        status, _, _ = self.web.request("GET", "/api/session", host=f"localhost:{self.web.port}")
        self.assertEqual(200, status, "localhost 与 127.0.0.1 都该放行")

    def test_missing_host_rejected(self) -> None:
        status, headers, body = raw_exchange(self.web.port, b"GET /api/session HTTP/1.0\r\n\r\n")
        self.assertEqual(400, status)
        self.assertEqual("bad_host", json.loads(body)["code"])
        self.assertIn("content-length", headers)

    def test_api_requires_session_token(self) -> None:
        status, _, body = self.web.request("GET", "/api/session", token=False, cookie=False)
        self.assertEqual(401, status)
        self.assertEqual("unauthorized", json.loads(body)["code"])

        status, _, _ = self.web.request("GET", "/api/session", token="wrong-token", cookie=False)
        self.assertEqual(401, status)

        status, _, _ = self.web.request("GET", "/api/session", token=False, cookie="nope")
        self.assertEqual(401, status)

        # 头或 Cookie 任一正确即放行（EventSource 只能靠 Cookie）
        status, _, _ = self.web.request("GET", "/api/session", cookie=False)
        self.assertEqual(200, status)
        status, _, _ = self.web.request("GET", "/api/session", token=False)
        self.assertEqual(200, status)

    def test_write_requests_check_origin(self) -> None:
        status, _, _ = self.web.request("POST", "/api/lock", body={}, origin="http://evil.com")
        self.assertEqual(403, status)

        status, _, _ = self.web.request(
            "POST", "/api/lock", body={}, origin=f"http://127.0.0.1:{self.web.port}"
        )
        self.assertEqual(200, status)

    def test_slow_body_rejection_does_not_reset_connection(self) -> None:
        """确定性复现「早退拒绝把连接 RST 掉、响应丢失」的那个缺陷。

        手法：只发请求头（声明 16 字节体），停 150ms 再发体。
        - 修复前：服务端在读到体之前就 403 并 close，未读体 → abortive close（RST）；
          客户端的体要么写进已被 RST 的连接，要么读不到那条 403。
        - 修复后：`_drain_body()` 在 1 秒窗口里等体到齐，再写 403 并正常 FIN。
        """
        sock = socket.create_connection(("127.0.0.1", self.web.port), timeout=10)
        body_bytes = b'{"pad":"1234567"}'
        try:
            head = (
                f"POST /api/lock HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.web.port}\r\n"
                f"Cookie: {COOKIE_NAME}={self.web.token}\r\n"
                f"Origin: http://evil.com\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin-1")
            sock.sendall(head)
            time.sleep(0.15)  # 让服务端先走完 Origin 校验（它必须在这里等我发体）
            sock.sendall(body_bytes)

            raw = b""
            sock.settimeout(5.0)
            while True:
                part = sock.recv(65536)
                if not part:
                    break
                raw += part
        finally:
            sock.close()

        status, headers, body = parse_response(raw)
        self.assertEqual(403, status, f"应当拿到干净的 403，实际响应：{raw[:200]!r}")
        self.assertEqual("bad_origin", json.loads(body)["code"])
        self.assertEqual(int(headers["content-length"]), len(body))

    def test_rejected_write_with_body_still_returns_clean_response(self) -> None:
        """早退拒绝（Origin / token / Host）发生在**读请求体之前**。

        此时若带着未读的请求体直接 close，Windows 会发 RST 而不是 FIN，飞行中的
        响应字节被丢弃 —— 客户端随机拿到 `ConnectionAbortedError`（浏览器表现为
        "Failed to fetch"）而不是干净的 403/401。这条用例用 256KB 体把窗口放大，
        钉住「先排干残留请求体，再关连接」这个修复。
        """
        payload = json.dumps({"pad": "x" * (256 * 1024)}).encode("utf-8")

        status, headers, body = self.web.request(
            "POST", "/api/lock", body=payload, origin="http://evil.com"
        )
        self.assertEqual(403, status)
        self.assertEqual("bad_origin", json.loads(body)["code"])
        self.assertEqual(int(headers["content-length"]), len(body))

        status, headers, body = self.web.request(
            "POST", "/api/lock", body=payload, token=False, cookie=False
        )
        self.assertEqual(401, status)
        self.assertEqual("unauthorized", json.loads(body)["code"])
        self.assertEqual(int(headers["content-length"]), len(body))

        status, _, body = self.web.request(
            "POST", "/api/lock", body=payload, host="evil.com"
        )
        self.assertEqual(400, status)
        self.assertEqual("bad_host", json.loads(body)["code"])

    def test_no_cors_headers_anywhere(self) -> None:
        responses = [
            self.web.request("GET", "/api/session"),
            self.web.request("POST", "/api/lock", body={}, origin="http://evil.com"),
            self.web.request("GET", "/api/nope"),
            self.web.request("GET", "/"),
            self.web.request("OPTIONS", "/api/session"),
        ]
        for status, headers, _ in responses:
            leaking = [key for key in headers if key.startswith("access-control-")]
            self.assertEqual([], leaking, f"响应里出现了 CORS 头（status={status}）")

    def test_path_traversal_is_blocked(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pvstatic-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "index.html").write_text("<html>ok</html>", encoding="utf-8")
        (root / "app.css").write_text("body{}", encoding="utf-8")

        outside = root.parent / f"pv-web-probe-{os.getpid()}.txt"
        outside.write_text(SECRET_PROBE, encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))

        web = WebFixture(self, static_root=root)
        probes = [
            f"/../{outside.name}",
            f"/..%2f{outside.name}",
            f"/%2e%2e/{outside.name}",
            f"/%252e%252e%252f{outside.name}",
            f"/static/../../{outside.name}",
            f"/..\\..\\{outside.name}",
            "/../../etc/passwd",
            "/..%2f..%2fetc%2fpasswd",
            "/static/../../pv.py",
        ]
        for path in probes:
            status, headers, body = web.request("GET", path)
            self.assertEqual(404, status, f"未拦住穿越：{path}")
            self.assertNotIn(SECRET_PROBE.encode(), body, f"泄漏了目录外文件：{path}")
            self.assertNotIn(b"class Vault", body, f"泄漏了源码：{path}")
            self.assertIn("content-length", headers)

    def test_static_files_and_cookie(self) -> None:
        status, headers, body = self.web.request("GET", "/", token=False, cookie=False)
        self.assertEqual(200, status)
        self.assertIn("text/html", headers["content-type"])
        self.assertEqual("no-store", headers["cache-control"])
        self.assertIn("<title>pwdvault</title>", body.decode("utf-8"))
        cookie = headers.get("set-cookie", "")
        self.assertIn(f"{COOKIE_NAME}={self.web.token}", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

        status, headers, _ = self.web.request("GET", "/app.css", token=False, cookie=False)
        self.assertEqual(200, status)
        self.assertIn("text/css", headers["content-type"])

        status, headers, _ = self.web.request("GET", "/app.js", token=False, cookie=False)
        self.assertEqual(200, status)
        self.assertIn("javascript", headers["content-type"])

        status, headers, body = self.web.request("GET", "/nope.css", token=False, cookie=False)
        self.assertEqual(404, status)
        self.assertIn("content-length", headers)


# ---------------------------------------------------------------- Content-Length
class ContentLengthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = WebFixture(self)

    def test_every_non_sse_response_has_content_length(self) -> None:
        cases = [
            ("GET", "/", None),
            ("GET", "/app.css", None),
            ("GET", "/api/session", self.web.token),
            ("GET", "/api/nope", self.web.token),
            ("GET", "/api/session", None),  # 401
            ("POST", "/api/lock", self.web.token),
        ]
        for method, path, cookie in cases:
            status, headers, body = self.web.raw(method, path, cookie=cookie)
            self.assertIn("content-length", headers, f"{method} {path} 缺 Content-Length")
            self.assertEqual(int(headers["content-length"]), len(body), f"{method} {path} 长度不符")
            self.assertNotIn("transfer-encoding", headers, f"{method} {path} 不该是 chunked")
            self.assertGreaterEqual(status, 200)

    def test_head_has_content_length_but_no_body(self) -> None:
        status, headers, body = self.web.raw("HEAD", "/")
        self.assertEqual(200, status)
        self.assertIn("content-length", headers)
        self.assertEqual("", body.decode("latin-1"))

        # HEAD /api/events：SSE 语义就是「一直写」，不能给 HEAD 用
        status, headers, _ = self.web.raw("HEAD", "/api/events", cookie=self.web.token)
        self.assertEqual(405, status)
        self.assertIn("allow", headers)


# ---------------------------------------------------------------- SSE
class SseTests(unittest.TestCase):
    def test_stream_format_is_chunked_sse(self) -> None:
        web = WebFixture(self)
        sock, headers, reader = web.open_sse()
        try:
            self.assertEqual("chunked", headers.get("transfer-encoding"))
            self.assertNotIn("content-length", headers)
            self.assertIn("text/event-stream", headers.get("content-type", ""))
            self.assertEqual([], [key for key in headers if key.startswith("access-control-")])

            first = reader.read_chunk()
            self.assertTrue(first.startswith(b"event: session\ndata: "), first)
            self.assertTrue(first.endswith(b"\n\n"), first)
            payload = json.loads(first.split(b"data: ", 1)[1].strip())
            self.assertTrue(payload["unlocked"])
            self.assertIn("revision", payload)
        finally:
            sock.close()

    def test_heartbeat_keeps_connection_alive(self) -> None:
        web = WebFixture(self, heartbeat_seconds=0.15)
        sock, _, reader = web.open_sse()
        try:
            reader.read_chunk()  # session
            deadline = time.monotonic() + 3.0
            seen = b""
            while time.monotonic() < deadline:
                seen = reader.read_chunk()
                if seen:
                    break
            self.assertEqual(b": ping\n\n", seen)
        finally:
            sock.close()

    def test_sse_requires_token(self) -> None:
        web = WebFixture(self)
        status, headers, body = web.raw("GET", "/api/events", cookie=None)
        self.assertEqual(401, status)
        self.assertEqual("unauthorized", json.loads(body)["code"])
        self.assertIn("content-length", headers)

    def test_20_concurrent_subscribers_no_crosstalk(self) -> None:
        web = WebFixture(self, heartbeat_seconds=0.1)
        sockets: list[socket.socket] = []
        readers: list[ChunkReader] = []
        try:
            for _ in range(20):
                sock, headers, reader = web.open_sse()
                self.assertEqual("chunked", headers.get("transfer-encoding"))
                sockets.append(sock)
                readers.append(reader)

            deadline = time.monotonic() + 5.0
            while web.state.bus.subscriber_count() < 20 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(20, web.state.bus.subscriber_count())

            for reader in readers:
                self.assertTrue(reader.read_chunk().startswith(b"event: session\n"))

            payload = {"revision": 99, "count": 318, "delta": 2, "source": "agent", "reloaded": True}
            web.state.bus.publish("revision", payload)
            expected = encode_sse("revision", payload)
            for index, reader in enumerate(readers):
                # 心跳是**合法**的协议帧（`: ping`），会插在任何两个事件之间。
                # 20 条连接是顺序建立的，读到这里时部分连接早已过了 0.1s 心跳周期，
                # 因此必须跳过注释帧再比对事件 —— 否则这就是个随机器负载飘的假失败。
                body = self._next_event_chunk(reader)
                self.assertEqual(expected, body, f"第 {index} 个订阅者收到的事件不一致")
        finally:
            for sock in sockets:
                sock.close()

        deadline = time.monotonic() + 5.0
        while web.state.bus.subscriber_count() != 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(0, web.state.bus.subscriber_count(), "客户端断开后队列没被清理")

    @staticmethod
    def _next_event_chunk(reader: ChunkReader, *, timeout: float = 5.0) -> bytes:
        """读到第一个**非注释帧**为止（心跳不算事件，但必须证明它格式合法）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            chunk = reader.read_chunk()
            if chunk == KEEPALIVE_BYTES:
                continue
            return chunk
        raise AssertionError("超时：没等到事件帧")


# ---------------------------------------------------------------- 会话与自锁
class SessionTests(unittest.TestCase):
    def test_unlock_lock_flow(self) -> None:
        web = WebFixture(self, unlock=False)

        status, _, body = web.request("GET", "/api/session")
        self.assertEqual(200, status)
        session = json.loads(body)
        self.assertFalse(session["unlocked"])
        self.assertTrue(session["vault_exists"])
        self.assertIn("password", session["methods"])
        self.assertIn("auto_lock_seconds", session)

        status, _, body = web.request("POST", "/api/unlock", body={"password": "错的主密码"})
        self.assertEqual(401, status)
        self.assertEqual("auth_failed", json.loads(body)["code"])

        status, _, body = web.request("POST", "/api/unlock", body={})
        self.assertEqual(400, status)
        self.assertEqual("missing_credential", json.loads(body)["code"])

        status, _, body = web.request("POST", "/api/unlock", body={"password": web.password})
        self.assertEqual(200, status)
        session = json.loads(body)
        self.assertTrue(session["unlocked"])
        self.assertEqual(0, session["count"])

        status, _, body = web.request("POST", "/api/lock", body={})
        self.assertEqual(200, status)
        self.assertFalse(json.loads(body)["unlocked"])

    def test_auto_lock_with_real_thread(self) -> None:
        web = WebFixture(
            self,
            auto_lock_seconds=0.4,
            idle_check_seconds=0.05,
            poll_seconds=60.0,
        )
        status, _, body = web.request("GET", "/api/session")
        self.assertEqual(200, status)
        self.assertTrue(json.loads(body)["unlocked"])

        time.sleep(0.9)  # 唯一允许的真等待：自锁需要真实时间推进

        status, _, body = web.request("GET", "/api/session")
        self.assertEqual(200, status)
        self.assertFalse(json.loads(body)["unlocked"], "空闲超过阈值后应当已自动上锁")

    def test_auto_lock_with_injected_clock(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home, snapshot_keep=0)
        now = [1000.0]
        state = AppState(
            fixture.settings,
            token="fixed-token",
            auto_lock_seconds=900,
            clock=lambda: now[0],
            start_inbox=False,
        )
        server = WebServer(
            fixture.settings,
            port=0,
            open_browser=False,
            quiet=True,
            token="fixed-token",
            state=state,
            poll_seconds=60.0,
        )
        server.start()
        serve_thread = server.start_in_thread()
        self.addCleanup(serve_thread.join, 5.0)
        self.addCleanup(server.stop)
        state.unlock(password=fixture.password)
        self.assertTrue(state.unlocked)

        now[0] += 60.0
        self.assertFalse(state.lock_if_idle(), "还没到阈值不该锁")
        now[0] += 900.0
        self.assertTrue(state.lock_if_idle(), "超过阈值应当自锁")
        self.assertFalse(state.unlocked)

        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        try:
            conn.request(
                "GET",
                "/api/session",
                headers={TOKEN_HEADER: "fixed-token"},
            )
            response = conn.getresponse()
            payload = json.loads(response.read())
        finally:
            conn.close()
        self.assertFalse(payload["unlocked"])
        self.assertEqual(0, payload["revision"])

    def test_revision_poll_reloads_external_write(self) -> None:
        web = WebFixture(self, poll_seconds=60.0)
        box = web.state.bus.subscribe()
        self.addCleanup(web.state.bus.unsubscribe, box)

        # 模拟另一个进程（MCP/CLI）写盘
        external = Vault.open(web.settings, password=web.password)
        store = VaultStore(web.settings, external)
        result = store.commit(
            [Operation.add(Record(title="外部新增", username="u", password="p"))]
        )
        self.assertEqual(1, result.added)

        new_revision = web.state.poll_once()
        self.assertEqual(result.revision, new_revision)
        self.assertEqual(1, web.state.count)

        event, data = box.get(timeout=5.0)
        self.assertEqual("revision", event)
        self.assertEqual(result.revision, data["revision"])
        self.assertEqual(1, data["count"])
        self.assertEqual("agent", data["source"])

        # 再调一次：盘上没变，不该重复推送
        self.assertEqual(0, web.state.poll_once())


# ---------------------------------------------------------------- 进程与端口
class ProcessTests(unittest.TestCase):
    def test_refuses_non_loopback_host_config(self) -> None:
        """配置里写 0.0.0.0 必须拒绝启动（只绑 127.0.0.1 是硬编码红线）。"""
        home = support.make_home(self)
        fixture = support.make_vault(home, snapshot_keep=0)
        settings = replace(fixture.settings, web_host="0.0.0.0")
        server = WebServer(settings, port=0, open_browser=False, quiet=True)
        with self.assertRaises(Refused):
            server.start()
        self.assertEqual(0, server.port, "拒绝启动时不该绑定任何端口")

    def test_port_fallback_when_busy(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home, snapshot_keep=0)

        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(5)
        self.addCleanup(blocker.close)
        busy = int(blocker.getsockname()[1])

        server = WebServer(fixture.settings, port=busy, open_browser=False, quiet=True)
        server.start()
        self.addCleanup(server.stop)
        self.assertGreaterEqual(server.port, busy + 1, "端口被占用时应顺延到下一个")
        self.assertTrue(server.url.endswith(f":{server.port}/"))
        self.assertEqual("127.0.0.1", server._httpd.server_address[0])

    def test_runtime_json_created_and_removed_by_real_process(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home, snapshot_keep=0)
        home.mkdir(parents=True, exist_ok=True)
        support.write_config(home, fixture.settings.vault_path)

        driver = home / "driver.py"
        driver.write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(support.PROJECT_ROOT)!r})\n"
            "from pwdvault.web.server import WebServer\n"
            "from pwdvault.config import load_settings\n"
            f"settings = load_settings(vault_override={str(fixture.settings.vault_path)!r})\n"
            "server = WebServer(settings, port=0, open_browser=False, quiet=True)\n"
            "server.start()\n"
            'print("READY %d %s" % (server.port, server.token), flush=True)\n'
            "sys.stdin.readline()\n"
            "server.stop()\n"
            'print("STOPPED", flush=True)\n',
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PV_HOME"] = str(home)
        proc = subprocess.Popen(
            [support.PYTHON, str(driver)],
            cwd=str(support.PROJECT_ROOT),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            line = proc.stdout.readline().strip()
            self.assertTrue(line.startswith("READY "), f"子进程没就绪：{line!r} {proc.stderr}")
            _, port_text, token = line.split(" ", 2)
            port = int(port_text)

            runtime_file = home / "runtime.json"
            self.assertTrue(runtime_file.is_file(), "启动后应当生成 runtime.json")
            info = json.loads(runtime_file.read_text(encoding="utf-8"))
            self.assertEqual(port, info["port"])
            self.assertEqual(token, info["token"])
            self.assertEqual("127.0.0.1", info["host"])
            self.assertEqual(proc.pid, info["pid"])

            self.assertIsNotNone(proc.stdin)
            proc.stdin.write("stop\n")
            proc.stdin.flush()
            self.assertIsNotNone(proc.stdout)
            self.assertEqual("STOPPED", proc.stdout.readline().strip())
            proc.wait(timeout=20)
            self.assertEqual(0, proc.returncode)
            self.assertFalse(runtime_file.exists(), "退出后应当删除 runtime.json")

            # 端口已释放：能立刻重新绑定
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("127.0.0.1", port))
            finally:
                probe.close()
        finally:
            if proc.poll() is None:
                proc.kill()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()


# ---------------------------------------------------------------- 事件总线（单元）
class EventBusTests(unittest.TestCase):
    def test_encode_helpers(self) -> None:
        self.assertEqual(
            b'event: revision\ndata: {"revision":43}\n\n',
            encode_sse("revision", {"revision": 43}),
        )
        self.assertEqual(b"4\r\nabcd\r\n", encode_chunk(b"abcd"))
        self.assertEqual(b"0\r\n\r\n", encode_chunk(b""))

    def test_slow_subscriber_degrades_to_lag(self) -> None:
        bus = EventBus(maxsize=2)
        box = bus.subscribe()
        try:
            for revision in range(5):
                bus.publish("revision", {"revision": revision})
            events = []
            while not box.empty():
                events.append(box.get_nowait())
            self.assertEqual(LAG_EVENT, events[-1][0], "队列满时最后一条必须是 lag")
            self.assertGreaterEqual(bus.dropped, 1)
        finally:
            bus.close()
            bus.unsubscribe(box)

    def test_unsubscribe_and_close_are_idempotent(self) -> None:
        bus = EventBus()
        box = bus.subscribe()
        self.assertEqual(1, bus.subscriber_count())
        bus.unsubscribe(box)
        bus.unsubscribe(box)
        self.assertEqual(0, bus.subscriber_count())

        second = bus.subscribe()
        bus.close()
        self.assertEqual(0, bus.subscriber_count())
        self.assertEqual(0, bus.publish("revision", {"revision": 1}))
        event, _ = second.get_nowait()
        self.assertEqual(CLOSE_EVENT, event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
