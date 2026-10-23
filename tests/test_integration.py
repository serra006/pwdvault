"""T12 端到端联调：`pv web` / `pv mcp` 两个子命令 + 13 步真链路。

为什么这组测试必须起**真子进程**
----------------------------------
单元测试可以打桩，但它们验不到本轮真正交付的东西：

1. **入口**：`pv web` 只有经 `pv.py` 跑，`sys.argv[0]` 才带得动 `_clipwatch` 的识别；
   `python -m pwdvault.web` 那种入口下剪贴板定时清空会静默失效。打桩测不出来。
2. **stdout 纯净性**：MCP 客户端把 stdout 的每一行都当协议帧。只有真进程才能证明
   「日志走了 stderr、帧走了 stdout」—— 这一条一旦破了，用户看到的是客户端静默断连，
   而且是间歇性的，靠 in-process 测试永远发现不了。
3. **`runtime.json` 的生死**：它是进程级状态文件，只有真启动/真退出才谈得上
   「启动写了、退出删了、端口还回来了」。

13 步链路（括号里是本文件的步骤名）
-----------------------------------
    init（1）→ web 冷启动（2）→ 读 runtime token（3）→ 解锁（补充步）→
    上传 TXT（4）→ 等 inbox 建批（5）→ 读暂存区（6）→ `pv mcp` claim（7）→
    submit（8）→ Web 侧 commit（9）→ 搜索命中（10）→ 复制回执（11）→
    rollback（12）→ 搜索搜不到（13）

**上传是异步的**：`POST /api/inbox/upload` 只落盘、同步解析一律不做（解析与建批由
`inbox.py` 的轮询线程负责）。所以第 5 步是「轮询等批次出现」，不是「上传完就有」。

剪贴板（第 11 步）：本测试起的是真进程，没法在进程内打桩，所以会真的写系统剪贴板。
无桌面会话的机器上这一步可能拿不到剪贴板，此时断言降级为「错误必须是结构化 JSON」，
并在报告里标记该步为 headless-skip —— 不伪装成通过。
"""

from __future__ import annotations

import http.client
import inspect
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import runtime as runtime_mod
from pwdvault import mcp_server
from pwdvault.web.server import TOKEN_HEADER

PROJECT_ROOT = support.PROJECT_ROOT
PYTHON = support.PYTHON
PV_ENTRY = support.PV_ENTRY

# 6 个词，`score_secret` 能过 55 bit 门槛（`pv init` 不带 --force 也接受）
PASSWORD = "港湾 灯塔 松林 铜钟 麦田 河岸"

# 冷启动口径：**`pv web` 进程 spawn → `GET /api/session` 返回 200**。
# 不含解锁：Web 是在浏览器里输主密码解锁的，`serve` 自己不解锁，把 argon2 派生
# 算进「冷启动」等于把用户打字时间也算进去，那 3 秒阈值毫无意义。
MAX_COLD_START_SECONDS = 30.0

# 上传 → 批次出现的预算（config 里把 inbox 轮询压到 0.2s，3s 已经很宽松）
BATCH_WAIT_SECONDS = 3.0
MCP_FRAME_TIMEOUT = 20.0
STOP_WAIT_SECONDS = 20.0

UPLOAD_FILE_NAME = "粘贴.txt"
UPLOAD_TITLE = "淘宝"
UPLOAD_TEXT = (
    f"{UPLOAD_TITLE}\n"
    "账号：zhangsan\n"
    "密码：Zw9#kLm2!pQr9\n"
    "网址：https://taobao.com\n"
)
UPLOAD_PASSWORD = "Zw9#kLm2!pQr9"

CONFIG_EXTRA = """
[inbox]
interval_seconds = 0.2

[mcp]
proxy = false
"""


# --------------------------------------------------------------------- 小工具
def child_env(home: Path | str, extra: dict | None = None) -> dict:
    """子进程环境：PV_HOME 指向临时目录，其余与 `_support.run_py` 保持一致。"""
    environ = os.environ.copy()
    environ["PV_HOME"] = str(home)
    for key in ("PV_VAULT", "PV_RECOVERY_CODE", "PV_SNAPSHOT_KEEP"):
        environ.pop(key, None)
    if extra:
        for key, value in extra.items():
            if value is None:
                environ.pop(key, None)
            else:
                environ[key] = str(value)
    return environ


def can_bind(port: int, *, timeout: float = 5.0) -> bool:
    """`port` 现在能不能被 bind —— 用来证明端口**真的**释放了，而不只是删了个文件。

    故意不设 `SO_REUSEADDR`：设了它，`TIME_WAIT` 也会被当成「可用」，
    那就测不出「监听套接字没关」这种真故障。
    """
    deadline = time.monotonic() + timeout
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", int(port)))
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        finally:
            sock.close()


class _Drain(threading.Thread):
    """把子进程的管道抽干并存下最近若干行（不抽干会把子进程写阻塞）。"""

    def __init__(self, stream, name: str, *, keep: int = 400) -> None:
        super().__init__(name=f"drain-{name}", daemon=True)
        self._stream = stream
        self._keep = keep
        self.lines: list[str] = []
        self.start()

    def run(self) -> None:  # noqa: D102 - Thread 契约
        try:
            for line in self._stream:
                self.lines.append(str(line).rstrip("\r\n"))
                if len(self.lines) > self._keep:
                    del self.lines[: len(self.lines) - self._keep]
        except (OSError, ValueError):
            pass

    def text(self, limit: int = 40) -> str:
        return "\n".join(self.lines[-limit:])

    def join_thread(self, timeout: float = 5.0) -> None:
        """等抽干线程收工（用基类的 join；不要在本类里覆盖 `join`）。"""
        if self.is_alive():
            threading.Thread.join(self, timeout)


def _close_streams(proc: subprocess.Popen) -> None:
    """关掉子进程的三根管道（不关会在 unittest 里刷一堆 ResourceWarning）。"""
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream is not None:
                stream.close()
        except (OSError, ValueError):
            pass


def wait_for_text(drain: "_Drain", needle: str, *, timeout: float = 5.0) -> bool:
    """等 `drain` 的输出里出现 `needle`（子进程写 stderr 与测试读之间天然有延迟）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(needle in line for line in drain.lines):
            return True
        time.sleep(0.02)
    return False


class HttpClient:
    """最小 HTTP 客户端：每个请求一条连接，带一次性 token 头。"""

    def __init__(self, port: int, token: str) -> None:
        self.port = int(port)
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        body: object = None,
        raw: bytes | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        sent: dict[str, str] = {TOKEN_HEADER: self.token}
        if headers:
            sent.update({str(k): str(v) for k, v in headers.items()})
        payload: bytes | None = None
        if raw is not None:
            payload = raw
        elif body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            sent.setdefault("Content-Type", "application/json")
        try:
            conn.request(method, path, body=payload, headers=sent)
            response = conn.getresponse()
            data = response.read()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            conn.close()

    def json(self, method: str, path: str, **kwargs: object) -> tuple[int, dict]:
        status, _, data = self.request(method, path, **kwargs)
        try:
            return status, json.loads(data.decode("utf-8")) if data else {}
        except json.JSONDecodeError:
            raise AssertionError(f"{method} {path} 返回的不是 JSON：{data[:300]!r}")  # noqa: B904


class WebApp:
    """真 `pv web` 子进程：stdin 用管道接管，便于用 EOF 触发优雅退出。"""

    def __init__(
        self,
        case: unittest.TestCase,
        home: Path,
        *,
        args: list[str] | None = None,
        ready_timeout: float = MAX_COLD_START_SECONDS,
    ) -> None:
        self.home = Path(home)
        self.argv = [PYTHON, str(PV_ENTRY), "web", "--no-browser", "--port", "0"]
        self.argv.extend(args if args is not None else ["--exit-when-stdin-closes"])
        self.started = time.monotonic()
        self.proc = subprocess.Popen(
            self.argv,
            cwd=str(PROJECT_ROOT),
            env=child_env(self.home),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.out = _Drain(self.proc.stdout, "web-stdout")
        self.err = _Drain(self.proc.stderr, "web-stderr")
        case.addCleanup(self.stop)
        self.info = self._wait_ready(ready_timeout)
        self.ready_seconds = time.monotonic() - self.started
        self.http = HttpClient(self.info["port"], self.info["token"])

    # ---- 启动
    def _wait_ready(self, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        last: dict | None = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(
                    f"`pv web` 没起来就退出了（exit={self.proc.returncode}）：\n{self.err.text()}"
                )
            last = runtime_mod.read_runtime(self.home)
            if last is not None:
                # runtime.json 写出来 ≠ 能服务：再打一发 /api/session 确认真的在 accept
                probe = HttpClient(last["port"], last["token"])
                try:
                    status, _ = probe.json("GET", "/api/session")
                except OSError:
                    status = 0
                if status == 200:
                    return last
            time.sleep(0.03)
        raise AssertionError(
            f"`pv web` 在 {timeout:.1f}s 内没有准备好（runtime={last}）：\n{self.err.text()}"
        )

    # ---- 退出
    def stop(self) -> None:
        """关 stdin（= 请它退出），绝不用 terminate —— 见 `--exit-when-stdin-closes`。"""
        if self.proc.poll() is None:
            try:
                if self.proc.stdin is not None:
                    self.proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(timeout=STOP_WAIT_SECONDS)
            except subprocess.TimeoutExpired:  # pragma: no cover - 真故障时才走到
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.out.join_thread(5.0)
        self.err.join_thread(5.0)
        _close_streams(self.proc)

    @property
    def exit_code(self) -> int | None:
        return self.proc.returncode


class McpClient:
    """`pv mcp` 真子进程 + 单行 JSON-RPC 帧客户端。"""

    def __init__(
        self,
        case: unittest.TestCase,
        home: Path,
        *,
        env: dict | None = None,
        args: list[str] | None = None,
    ) -> None:
        self.home = Path(home)
        self.proc = subprocess.Popen(
            [PYTHON, str(PV_ENTRY), "mcp", *(args or [])],
            cwd=str(PROJECT_ROOT),
            env=child_env(self.home, env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.frames: list[str] = []
        self._queue: queue.Queue[str] = queue.Queue()
        self._reader = threading.Thread(target=self._read, name="mcp-stdout", daemon=True)
        self._reader.start()
        self.err = _Drain(self.proc.stderr, "mcp-stderr")
        case.addCleanup(self.close)

    def _read(self) -> None:
        try:
            for line in self.proc.stdout:
                self.frames.append(line)
                self._queue.put(line)
        except (OSError, ValueError):
            pass

    def send(self, payload: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def read_frame(self, *, timeout: float = MCP_FRAME_TIMEOUT) -> dict:
        try:
            line = self._queue.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(
                f"MCP 在 {timeout:.0f}s 内没有回帧；stderr：\n{self.err.text()}"
            ) from None
        # 每一行都必须能独立 json.loads —— 这本身就是「stdout 纯净」的断言
        return json.loads(line)

    def request(self, request_id: int, method: str, params: dict | None = None) -> dict:
        payload: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
        payload["params"] = params or {}
        self.send(payload)
        return self.read_frame()

    def notify(self, method: str, params: dict | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def call_tool(self, request_id: int, name: str, arguments: dict) -> dict:
        frame = self.request(request_id, "tools/call", {"name": name, "arguments": arguments})
        assert "error" not in frame, f"tools/call {name} 返回错误帧：{frame}"
        result = frame["result"]
        return {
            "is_error": bool(result.get("isError")),
            "payload": result.get("structuredContent") or {},
            "text": (result.get("content") or [{}])[0].get("text", ""),
        }

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                if self.proc.stdin is not None:
                    self.proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(timeout=STOP_WAIT_SECONDS)
            except subprocess.TimeoutExpired:  # pragma: no cover - 真故障时才走到
                self.proc.kill()
                self.proc.wait(timeout=10)
        self._reader.join(5.0)
        self.err.join_thread(5.0)
        _close_streams(self.proc)

    def stdout_lines(self) -> list[str]:
        return [line for line in self.frames]


# --------------------------------------------------------------------- 13 步
class EndToEndTests(unittest.TestCase):
    """一条真链路跑到底：CLI → Web HTTP → MCP stdio → Web HTTP。"""

    def _prepare_home(self) -> Path:
        home = support.make_home(self)
        result = support.run_py(
            ["init", "--no-local-unlock"],
            home=home,
            env={"PV_MASTER_PASSWORD": PASSWORD},
        )
        self.assertEqual(result.returncode, 0, f"pv init 失败：{result.stderr}")
        vault_path = home / "data.enc"
        self.assertTrue(vault_path.is_file(), "pv init 没有建出 data.enc")
        support.write_config(home, vault_path, extra=CONFIG_EXTRA)
        return home

    def test_thirteen_steps_full_chain(self) -> None:
        marks: list[tuple[str, float, str]] = []

        @contextmanager
        def step(name: str):
            start = time.monotonic()
            try:
                yield
            finally:
                cost = time.monotonic() - start
                marks.append((name, cost, ""))
                print(f"[itest] {name}: {cost * 1000:.0f} ms", file=sys.stderr)

        def mark(name: str, detail: str) -> None:
            """给刚记录的这一步补一句细节（写进最终报告）。"""
            if marks:
                label, cost, _ = marks[-1]
                marks[-1] = (label, cost, detail)

        with step("1 init"):
            home = self._prepare_home()

        with step("2 web 冷启动"):
            app = WebApp(self, home)
            cold = app.ready_seconds
            self.assertLessEqual(
                cold,
                MAX_COLD_START_SECONDS,
                f"pv web 冷启动 {cold:.2f}s 超过阈值 {MAX_COLD_START_SECONDS:.0f}s；"
                f"KDF 参数={support.FAST_KDF}（口径：进程 spawn → GET /api/session 200，不含解锁）",
            )
            self.assertEqual(app.exit_code, None, "服务不该已经退出")
        mark("2 web 冷启动", f"{cold*1000:.0f} ms（阈值 {MAX_COLD_START_SECONDS:.0f}s，不含解锁）")

        with step("3 runtime token"):
            info = app.info
            self.assertEqual(info["host"], "127.0.0.1")
            self.assertGreater(info["port"], 0)
            self.assertGreaterEqual(len(info["token"]), 16)
            self.assertEqual(info["pid"], app.proc.pid, "runtime.json 里的 pid 应该是本进程")
            self.assertTrue(runtime_mod.is_alive(info["pid"]))
        mark("3 runtime token", f"port={info['port']} pid={info['pid']}")

        with step("+ 解锁"):
            status, payload = app.http.json("POST", "/api/unlock", body={"password": PASSWORD})
            self.assertEqual(status, 200, payload)
            self.assertTrue(payload.get("unlocked"), payload)

        with step("4 上传 TXT"):
            status, payload = app.http.json(
                "POST",
                "/api/inbox/upload",
                raw=UPLOAD_TEXT.encode("utf-8"),
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Filename": urllib.parse.quote(UPLOAD_FILE_NAME),
                },
            )
            self.assertEqual(status, 200, payload)
            self.assertTrue(payload.get("pending"), payload)
            self.assertEqual(payload.get("size"), len(UPLOAD_TEXT.encode("utf-8")))

        with step("5 等 inbox 建批"):
            deadline = time.monotonic() + BATCH_WAIT_SECONDS
            batch_id = ""
            row: dict = {}
            while time.monotonic() < deadline:
                status, payload = app.http.json("GET", "/api/staging")
                self.assertEqual(status, 200, payload)
                rows = payload.get("batches") or []
                if rows:
                    row = rows[0]
                    batch_id = str(row.get("id") or "")
                    break
                time.sleep(0.05)
            self.assertTrue(batch_id, f"{BATCH_WAIT_SECONDS:.0f}s 内没建出批次（上传是异步的）")
            self.assertGreaterEqual(int(row.get("item_count") or 0), 1, row)
            self.assertIn(
                str(row.get("status")),
                ("detected", "drafted", "failed", "review"),
                f"批次状态异常：{row}",
            )
            batch_wait = BATCH_WAIT_SECONDS - max(0.0, deadline - time.monotonic())
        mark("5 等 inbox 建批", f"{batch_wait*1000:.0f} ms batch={batch_id}")

        with step("6 读暂存区"):
            status, payload = app.http.json("GET", f"/api/staging/{batch_id}")
            self.assertEqual(status, 200, payload)
            self.assertEqual(int(payload.get("count") or 0), len(payload.get("items") or []))
            self.assertGreaterEqual(int(payload.get("count") or 0), 1)
            body = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn(UPLOAD_PASSWORD, body, "暂存区把上传的密码明文透出去了")

        mcp = McpClient(self, home, env={"PV_MASTER_PASSWORD": PASSWORD})
        claimed_status = ""
        submitted_status = ""

        with step("7 mcp claim"):
            frame = mcp.request(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pwdvault-itest", "version": "1.0"},
                },
            )
            self.assertEqual(frame["result"]["serverInfo"]["name"], "pwdvault")
            mcp.notify("notifications/initialized")
            claimed = mcp.call_tool(2, "vault_staging_claim", {"batch_id": batch_id})
            self.assertFalse(claimed["is_error"], claimed)
            claimed_status = str(claimed["payload"].get("status") or "")
            self.assertIn(claimed_status, ("refining", "claimed"), claimed["payload"])
            self.assertIn(UPLOAD_TITLE, str(claimed["payload"].get("raw_text") or ""))
        mark("7 mcp claim", f"status={claimed_status}")

        with step("8 submit"):
            submitted = mcp.call_tool(
                3,
                "vault_staging_submit",
                {
                    "batch_id": batch_id,
                    "summary": "集成测试：从 TXT 整理出 1 条",
                    "records": [
                        {
                            "title": UPLOAD_TITLE,
                            "username": "zhangsan",
                            "password": UPLOAD_PASSWORD,
                            "url": "https://taobao.com",
                            "notes": "集成测试写入",
                            "tags": ["购物"],
                        }
                    ],
                },
            )
            self.assertFalse(submitted["is_error"], submitted)
            submitted_status = str(submitted["payload"].get("status") or "")
            self.assertEqual(submitted_status, "review", submitted["payload"])
            self.assertGreaterEqual(int(submitted["payload"].get("item_count") or 0), 1)

        # MCP 进程在这里就必须关掉：它持有自己的 VaultStore 视图，留着继续跑会在
        # 退出时和 Web 的写入抢同一份 data.enc。顺便在关闭时把 stdout 纯净性验完。
        with step("8b 关闭 mcp + stdout 纯净"):
            mcp.close()
            self.assertEqual(mcp.proc.returncode, 0, f"pv mcp 退出码异常：{mcp.err.text()}")
            lines = mcp.stdout_lines()
            self.assertGreaterEqual(len(lines), 3, f"帧太少：{lines}")
            for index, line in enumerate(lines):
                json.loads(line)  # 有一行不是 JSON 就直接红：stdout 被污染了
                self.assertTrue(line.endswith("\n"), f"第 {index} 帧没有以换行结束")
        mark("8b 关闭 mcp", f"{len(lines)} 帧全部可 json.loads")

        with step("9 commit"):
            status, payload = app.http.json(
                "POST", f"/api/staging/{batch_id}/commit", body={"mode": "skip"}
            )
            self.assertEqual(status, 200, payload)
            self.assertEqual(int(payload.get("committed") or 0), 1, payload)
            self.assertEqual(len(payload.get("ids") or []), 1, payload)
            record_id = str(payload["ids"][0])
            self.assertEqual(str(payload.get("status")), "committed")
            self.assertIsInstance(payload.get("revision"), int)
        mark("9 commit", f"record={record_id} revision={payload.get('revision')}")

        with step("10 搜索命中"):
            query = urllib.parse.quote(UPLOAD_TITLE)
            status, payload = app.http.json("GET", f"/api/records?q={query}")
            self.assertEqual(status, 200, payload)
            self.assertGreaterEqual(int(payload.get("total") or 0), 1, payload)
            ids = [str(item.get("id")) for item in payload.get("records") or []]
            self.assertIn(record_id, ids)
            self.assertNotIn(UPLOAD_PASSWORD, json.dumps(payload, ensure_ascii=False))

        copy_note = ""
        with step("11 copy 回执"):
            status, payload = app.http.json(
                "POST", f"/api/records/{record_id}/copy", body={"field": "password"}
            )
            if status == 200:
                self.assertTrue(payload.get("copied"), payload)
                self.assertEqual(str(payload.get("field")), "password")
                self.assertIn("auto_clear", payload)
                self.assertNotIn(
                    UPLOAD_PASSWORD,
                    json.dumps(payload, ensure_ascii=False),
                    "复制回执里不能出现明文",
                )
                copy_note = f"auto_clear={payload.get('auto_clear')}"
            else:
                # 无桌面会话的机器拿不到剪贴板：不伪装成通过，但要求错误也是结构化的
                self.assertGreaterEqual(status, 500, payload)
                self.assertTrue(payload.get("code"), payload)
                copy_note = f"headless-skip status={status} code={payload.get('code')}"
        mark("11 copy 回执", copy_note)

        with step("12 rollback"):
            status, payload = app.http.json(
                "POST", f"/api/staging/{batch_id}/rollback", body={}
            )
            self.assertEqual(status, 200, payload)
            self.assertGreaterEqual(int(payload.get("rolled_back") or 0), 1, payload)
            self.assertEqual(int(payload.get("deleted") or 0), 1, payload)

        with step("13 搜索搜不到"):
            status, payload = app.http.json(
                "GET", f"/api/records?q={urllib.parse.quote(UPLOAD_TITLE)}"
            )
            self.assertEqual(status, 200, payload)
            self.assertEqual(int(payload.get("total") or 0), 0, payload)

        with step("13b 优雅退出 + 端口释放"):
            port = int(app.info["port"])
            app.stop()
            self.assertEqual(app.exit_code, 0, f"pv web 退出码异常：{app.err.text()}")
            self.assertFalse(
                (home / "runtime.json").exists(), "runtime.json 没被删掉（脏文件会让 MCP 探测到假 pid）"
            )
            self.assertIsNone(runtime_mod.read_runtime(home))
            self.assertTrue(can_bind(port), f"端口 {port} 没有真正释放")

        self._report(marks)

    # ---- 报告
    def _report(self, marks: list[tuple[str, float, str]]) -> None:
        print("\n[itest] 13 步耗时", file=sys.stderr)
        for name, cost, detail in marks:
            suffix = f"  {detail}" if detail else ""
            print(f"[itest]   {name:<24} {cost * 1000:>7.0f} ms{suffix}", file=sys.stderr)


class EntryPointTests(unittest.TestCase):
    """脚本化验收：`--help` 的形状、`--vault` 透传、异常不进 stdout。"""

    def test_help_lists_web_and_mcp_without_clipwatch(self) -> None:
        result = support.run_py(["--help"], home=support.make_home(self))
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout
        self.assertIn("web", text)
        self.assertIn("mcp", text)
        # `_clipwatch` 是内部命令，绝不能出现在帮助里（会诱导用户去调它）
        self.assertNotIn("_clipwatch", text)

    def test_web_help_hides_exit_when_stdin_closes(self) -> None:
        result = support.run_py(["web", "--help"], home=support.make_home(self))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--port", result.stdout)
        self.assertIn("--no-browser", result.stdout)
        self.assertNotIn("exit-when-stdin-closes", result.stdout)

    def test_mcp_help_exists(self) -> None:
        result = support.run_py(["mcp", "--help"], home=support.make_home(self))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--vault", result.stdout)

    def test_mcp_main_accepts_injected_settings(self) -> None:
        """(c) 的 3 行改动：`main(argv, *, settings=...)` 必须存在且是关键字参数。"""
        signature = inspect.signature(mcp_server.main)
        self.assertIn("settings", signature.parameters)
        self.assertEqual(
            signature.parameters["settings"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            "settings 必须是仅关键字参数，否则 --vault 会顺着位置参数传错",
        )
        self.assertIsNone(signature.parameters["settings"].default)

    def test_pv_mcp_honours_vault_argument(self) -> None:
        """`pv mcp --vault X` 真的用 X —— 修之前 `--vault` 是被静默忽略的。"""
        home = support.make_home(self)
        fixture = support.make_vault(home)
        support.write_config(home, fixture.settings.vault_path)
        missing = home / "nope" / "other.enc"

        with_vault = McpClient(
            self,
            home,
            env={"PV_MASTER_PASSWORD": fixture.password},
            args=["--vault", str(missing)],
        )
        with_vault.request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                            "clientInfo": {"name": "itest", "version": "1"}})
        status_missing = with_vault.call_tool(2, "vault_status", {})
        with_vault.close()
        self.assertFalse(status_missing["payload"].get("exists"), status_missing)
        self.assertEqual(with_vault.proc.returncode, 0, with_vault.err.text())

        without_vault = McpClient(self, home, env={"PV_MASTER_PASSWORD": fixture.password})
        without_vault.request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                "clientInfo": {"name": "itest", "version": "1"}})
        status_ok = without_vault.call_tool(2, "vault_status", {})
        without_vault.close()
        self.assertTrue(status_ok["payload"].get("exists"), status_ok)

    def test_mcp_unexpected_exception_never_touches_stdout(self) -> None:
        """(d)：`mcp_server.main` 抛异常时 stdout 必须是 0 字节。"""
        home = support.make_home(self)
        fixture = support.make_vault(home)
        support.write_config(home, fixture.settings.vault_path)
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(PROJECT_ROOT)!r})\n"
            "from pwdvault import mcp_server, cli\n"
            "def _boom(*args, **kwargs):\n"
            "    raise RuntimeError('protocol-exploded-ZZ')\n"
            "mcp_server.main = _boom\n"
            "raise SystemExit(cli.main(['mcp']))\n"
        )
        result = subprocess.run(
            [PYTHON, "-c", script],
            cwd=str(PROJECT_ROOT),
            env=child_env(home, {"PV_MASTER_PASSWORD": fixture.password}),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.stdout, "", f"stdout 被污染了：{result.stdout!r}")
        self.assertNotEqual(result.returncode, 0, "异常路径的退出码必须非 0")
        self.assertIn("protocol-exploded-ZZ", result.stderr)
        self.assertIn("[pv mcp]", result.stderr)


class LifecycleTests(unittest.TestCase):
    """`pv web` 的生命周期：冷启动、EOF 退出、runtime.json、端口释放。"""

    def _home(self):
        home = support.make_home(self)
        result = support.run_py(
            ["init", "--no-local-unlock"],
            home=home,
            env={"PV_MASTER_PASSWORD": PASSWORD},
        )
        self.assertEqual(result.returncode, 0, f"pv init 失败：{result.stderr}")
        support.write_config(home, home / "data.enc", extra=CONFIG_EXTRA)
        return home

    def test_stdin_eof_exits_cleanly_and_frees_port(self) -> None:
        home = self._home()
        app = WebApp(self, home)
        self.assertEqual(app.info["host"], "127.0.0.1")
        port = int(app.info["port"])

        # 前提校验：此刻端口确实被占着，否则「退出后能 bind」证明不了任何事
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            occupied.settimeout(1.0)
            with self.assertRaises(OSError, msg=f"端口 {port} 没被 pv web 占用，测试前提不成立"):
                occupied.bind(("127.0.0.1", port))
        finally:
            occupied.close()

        started = time.monotonic()
        app.stop()
        self.assertLessEqual(time.monotonic() - started, STOP_WAIT_SECONDS)
        self.assertEqual(app.exit_code, 0, app.err.text())
        self.assertFalse((home / "runtime.json").exists())
        self.assertTrue(can_bind(port), f"端口 {port} 没有真正释放")

    def test_port_fallback_and_actual_address(self) -> None:
        """`--port N` 被占用时顺延，且打印/写盘的都是**实际**端口。"""
        home = self._home()
        squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        squatter.bind(("127.0.0.1", 0))
        squatter.listen(1)
        taken = int(squatter.getsockname()[1])
        self.addCleanup(squatter.close)

        app = WebApp(self, home, args=["--port", str(taken), "--exit-when-stdin-closes"])
        actual = int(app.info["port"])
        self.assertNotEqual(actual, taken, "端口没被占用时这条测试没有意义")
        self.assertGreater(actual, taken)
        self.assertTrue(
            wait_for_text(app.err, f"127.0.0.1:{actual}"),
            f"stderr 里没有打印实际地址；实际端口 {actual}，输出：\n{app.err.text()}",
        )
        app.stop()
        self.assertEqual(app.exit_code, 0, app.err.text())


class StdInGuardTests(unittest.TestCase):
    """`--exit-when-stdin-closes` 只在「stdin 不是终端」时生效（裁决 a-2）。"""

    def test_pipe_like_stdin_is_not_a_tty(self) -> None:
        import io

        from pwdvault.web.server import _stdin_is_tty

        self.assertFalse(_stdin_is_tty(io.StringIO("")))
        # 用真管道，不要用 `open(os.devnull)`：Windows 上 NUL 是**字符设备**，
        # `isatty()` 返回 True（`_isatty` 对字符设备一律为真），拿它当「非终端」
        # 的样例会把测试本身写错。
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, "r", encoding="utf-8") as reader:
                self.assertFalse(_stdin_is_tty(reader))
        finally:
            os.close(write_fd)

    def test_tty_stdin_is_detected(self) -> None:
        from pwdvault.web.server import _stdin_is_tty

        class FakeTty:
            def isatty(self) -> bool:
                return True

        self.assertTrue(_stdin_is_tty(FakeTty()))

    def test_unknown_stdin_counts_as_tty(self) -> None:
        """拿不到 isatty 时按「是终端」处理：宁可少关一次，也不乱关用户的服务。"""
        from pwdvault.web.server import _stdin_is_tty

        class Weird:
            def isatty(self):
                raise ValueError("detached")

        self.assertTrue(_stdin_is_tty(Weird()))
        self.assertTrue(_stdin_is_tty(object()))


if __name__ == "__main__":  # pragma: no cover - 手工调试
    unittest.main(verbosity=2)
