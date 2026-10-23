"""两种 MCP 启动形式都必须真的能起进程。

这是 `/api/mcp-config` 的**契约**，不是「顺手手工验一下」：接口给出的配置是
`[<pv.py 绝对路径>, "mcp"]`，而历史上用过 `["-m", "pwdvault.mcp_server"]`。
两种都有人抄、都写在文档里，所以两种都得被测试守住 —— 否则哪天 `pv.py` 的入口
被重构（或 `-m` 那条路径因为包结构变化而失效），我们只会在用户报「连接器里
一个工具都没有」时才发现。

两种形式的差别只在「`pwdvault` 包怎么被 import 到」：

* `[python, "-m", "pwdvault.mcp_server"]` —— 靠 `PYTHONPATH`（或恰好站在项目根）；
* `[python, "<项目根>/pv.py", "mcp"]` —— `pv.py` 自己把所在目录插进 `sys.path`，
  **不需要 `PYTHONPATH`**，也不受客户端工作目录影响。这是接口现在给出的形式。

两条用例都刻意把子进程的 `cwd` 设成系统临时目录：若某种形式其实依赖「站在项目
根」，这里会立刻红。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault.mcp_tools import TOOLS

PYTHON = sys.executable
ENTRY = support.PV_ENTRY
PROJECT_ROOT = support.PROJECT_ROOT

#: 这些环境变量必须清干净，否则「起得来」可能只是继承了我这台机器的运气。
SCRUBBED_ENV = (
    "PV_VAULT",
    "PYTHONPATH",
    "PV_MASTER_PASSWORD",
    "PV_RECOVERY_CODE",
    "PV_SNAPSHOT_KEEP",
)

CLIENT_INFO = {"name": "test_mcp_entry", "version": "0.0"}
PROTOCOL_VERSION = "2025-06-18"


class McpLaunchFormTests(unittest.TestCase):
    """两种启动方式的端到端握手（`initialize` + `tools/list` + EOF 退出）。"""

    def setUp(self) -> None:
        self.home = support.make_home(self)

    # ---- 基建
    def _env(self, extra: dict | None = None) -> dict:
        env = os.environ.copy()
        env["PV_HOME"] = str(self.home)
        for key in SCRUBBED_ENV:
            env.pop(key, None)
        if extra:
            env.update({str(k): str(v) for k, v in extra.items()})
        return env

    @staticmethod
    def _read_line(proc: subprocess.Popen, method: str, *, timeout: float = 25.0) -> bytes:
        """读一帧（读操作放线程里：进程卡死时超时失败，而不是把整个测试挂住）。"""
        box: dict = {}

        def reader() -> None:
            box["line"] = proc.stdout.readline()  # type: ignore[union-attr]

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            proc.kill()
            raise AssertionError(f"MCP 进程 {timeout} 秒内没有响应 {method}")
        raw = box.get("line") or b""
        if not raw:
            err = b""
            if proc.stderr is not None:
                try:
                    err = proc.stderr.read() or b""
                except Exception:  # noqa: BLE001 - 只为把 stderr 放进报错信息
                    err = b""
            proc.kill()
            raise AssertionError(
                f"MCP 进程对 {method} 一个字都没输出（多半是启动就崩了）："
                f"{err.decode('utf-8', 'replace')[:600]}"
            )
        return raw

    def _run_form(self, command: list[str], env: dict, label: str) -> list[str]:
        """起进程 → initialize → notifications/initialized → tools/list → 关 stdin → 断言 rc=0。"""
        proc = subprocess.Popen(
            command,
            cwd=tempfile.gettempdir(),  # 故意不在项目根：验证与 cwd 无关
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            hello = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": CLIENT_INFO,
                },
            }
            proc.stdin.write((json.dumps(hello) + "\n").encode("utf-8"))  # type: ignore[union-attr]
            proc.stdin.flush()  # type: ignore[union-attr]
            init_reply = json.loads(self._read_line(proc, "initialize").decode("utf-8"))
            self.assertEqual("2.0", init_reply.get("jsonrpc"), label)
            self.assertIn("result", init_reply, f"{label}: initialize 必须是成功响应：{init_reply}")
            self.assertEqual("pwdvault", init_reply["result"]["serverInfo"]["name"], label)
            self.assertEqual(PROTOCOL_VERSION, init_reply["result"]["protocolVersion"], label)

            # 规范要求客户端在 initialize 之后补一条通知；服务端不回帧。
            proc.stdin.write(  # type: ignore[union-attr]
                (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode(
                    "utf-8"
                )
            )
            proc.stdin.flush()  # type: ignore[union-attr]

            proc.stdin.write(  # type: ignore[union-attr]
                (json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n").encode(
                    "utf-8"
                )
            )
            proc.stdin.flush()  # type: ignore[union-attr]
            listing = json.loads(self._read_line(proc, "tools/list").decode("utf-8"))
            self.assertIn("result", listing, f"{label}: tools/list 必须是成功响应：{listing}")
            names = [str(tool["name"]) for tool in listing["result"]["tools"]]
        finally:
            # 关 stdin = 客户端断连，服务端应**干净退出**（rc=0），而不是抛异常或被 kill。
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except OSError:  # pragma: no cover - 进程已退出
                    pass
            try:
                proc.wait(timeout=25)
            except subprocess.TimeoutExpired:  # pragma: no cover - 兜底
                proc.kill()
                proc.wait(timeout=10)
                raise AssertionError(f"{label}: 关掉 stdin 之后 MCP 进程没有退出")
            # 管道也要关掉，否则 unittest 会打 ResourceWarning（不是失败，但噪音会淹没真问题）
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:  # pragma: no cover
                        pass

        self.assertEqual(0, proc.returncode, f"{label}: stdin EOF 之后应当退出码 0")
        return names

    def _assert_tool_table(self, names: list[str], label: str) -> None:
        expected = [spec.name for spec in TOOLS]
        self.assertEqual(expected, names, f"{label}: 工具表必须与 mcp_tools.TOOLS 一致")
        # 反向对照：证明不是「空列表也能过」
        self.assertEqual(10, len(names), f"{label}: 当前版本应当是 10 个工具")

    # ---- 形式一：python -m（靠 PYTHONPATH）
    def test_dash_m_form_with_pythonpath(self) -> None:
        env = self._env({"PYTHONPATH": str(PROJECT_ROOT)})
        self.assertEqual(str(PROJECT_ROOT), env["PYTHONPATH"])
        names = self._run_form(
            [PYTHON, "-m", "pwdvault.mcp_server"], env, "python -m + PYTHONPATH"
        )
        self._assert_tool_table(names, "python -m + PYTHONPATH")

    # ---- 形式二：pv.py 绝对路径 + mcp 子命令（接口现在给的形式，不需要 PYTHONPATH）
    def test_pv_py_script_form_without_pythonpath(self) -> None:
        env = self._env()
        self.assertNotIn("PYTHONPATH", env, "这条用例的前提：环境里不该有 PYTHONPATH")
        self.assertTrue(ENTRY.is_file(), f"pv.py 不存在：{ENTRY}")
        names = self._run_form([PYTHON, str(ENTRY), "mcp"], env, "pv.py + mcp")
        self._assert_tool_table(names, "pv.py + mcp")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
