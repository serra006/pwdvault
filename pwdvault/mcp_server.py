"""MCP（Model Context Protocol）stdio 传输层 + JSON-RPC 分发。

本文件是 L5：**只**懂「帧怎么读写」与「方法怎么分发」。业务一律委托给
`mcp_tools.py`（L4）。它不认识 `Record`、不认识 `Vault`、不碰任何字段值。

帧格式（已核实官方规范 2025-06-18 · basic/transports#stdio）
------------------------------------------------------------
    一帧 = 一行 UTF-8 JSON + "\\n"，无 `Content-Length` 头，消息内不得含换行。

这是 LSP 之外的另一套约定。**不要**照抄 LSP 的 `Content-Length: N\\r\\n\\r\\n`：
按那个格式写出去，所有主流 MCP 客户端都会在收到第一帧后静默断连，
而且不会有任何错误提示 —— 这是本项目最难排查的一类故障，所以帧格式只允许
`StdioTransport` 一个类知道，将来若规范变动，改动面就是这里的 20 行。

stdout 纯净性（做错整个功能就废）
---------------------------------
MCP 客户端的读线程把 stdout 的每一行都当 JSON 解析。只要有一行是日志
（`[pv] ... event=...`），客户端就解析失败并**静默停止工作**，用户看到的是
「工具列表是空的 / 调一下就断」。所以：

  * `main()` 第一件事就是把 `sys.stdout` 换成 `sys.stderr` 的别名，
    原始 stdout 存进 `_PROTO_OUT` 只交给 transport —— 之后任何 stray `print()`
    都会去 stderr，绝不会污染协议。
  * 写帧走 `_PROTO_OUT.buffer.write(bytes)` 并按**字节** flush：
    Windows 下文本层会做 CRLF 转换与 BOM/编码回退，字节层不会。
  * `tests/test_mcp_protocol.py::test_stdout_purity_subprocess` 起**真进程**
    跑一整个会话，逐行 `json.loads` 断言——只要有半行杂音就红。
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from .config import Settings, load_settings, log_event
from .mcp_tools import (
    McpSession,
    ToolError,
    call_tool,
    list_tools,
    unlock_chain,
)

# --------------------------------------------------------------------- 常量
PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION = PROTOCOL_VERSIONS[0]

SERVER_NAME = "pwdvault"
SERVER_VERSION = "1.1.0"
SERVER_TITLE = "pwdvault 本地密码库"

SERVER_INFO: dict = {
    "name": SERVER_NAME,
    "title": SERVER_TITLE,
    "version": SERVER_VERSION,
}

INSTRUCTIONS = (
    "本机密码库。规则："
    "1) 用户要『用』密码时用 vault_copy，它不返回明文（回执里没有 auto_clear_in 就说明"
    "自动清空没装上，要提醒用户用完手动覆盖剪贴板）；"
    "2) 用户要『看』账号/网址时用 vault_search 或 vault_get，密码永远只显示掩码；"
    "3) 匹配到多条时不要猜，把 candidates 回问用户；"
    "4) 批量整理走 vault_staging_list → vault_staging_claim → vault_staging_submit，"
    "**你没有落库权限**：vault_staging_commit / vault_delete / vault_import_batch / "
    "vault_export / vault_change_master_password 这些工具不存在，不要尝试，也不要假装成功；"
    "5) 单条新增用 vault_add，默认 dry_run=true，先把草案给用户看过再改成 false；"
    "6) 修改记录用 vault_update 并带上 expected_updated，收到 record_conflict 就重新读一遍再问用户；"
    "7) 任何情况下都不要把字段值念进对话。"
)

# JSON-RPC 2.0 标准错误码
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# 单行上限：正常请求都 < 100KB。超长行直接丢弃并回 -32600，
# 而不是把它读进内存 —— 否则一个写错管道的客户端能把 MCP 进程撑死。
MAX_LINE_BYTES = 8 * 1024 * 1024

_MISSING = object()

# 原始 stdout 的唯一持有者。`main()` 把它从 sys 上摘下来交给 transport。
_PROTO_OUT: Any = None


def log(event: str, **fields: Any) -> None:
    """单行 stderr 日志：`[pv mcp] <ts> INFO event=... `。

    允许出现的字段只有 event / code / id / field_name / count / revision / ms
    （DESIGN §9.2）—— 这些都不可能是字段值，所以日志里永远不会漏明文。
    """
    log_event(event, scope="pv mcp", level="INFO", **fields)


def install_stdout_guard(stream: Any = None) -> Any:
    """把 stdout 从 `sys` 上摘下来，返回原始流；此后 stray `print()` 去 stderr。

    为什么用「换 sys.stdout」而不是「给 print 打补丁」：任何第三方库、
    任何 `logging.StreamHandler()` 默认 handler、任何 `sys.stdout.write`
    都走 `sys.stdout`。换掉这一个引用，覆盖面是 100%；打补丁只能覆盖自己写的代码。
    """
    global _PROTO_OUT
    _PROTO_OUT = stream if stream is not None else sys.stdout
    sys.stdout = sys.stderr
    return _PROTO_OUT


def protocol_stream() -> Any:
    """给测试用的只读访问器（返回原始 stdout）。"""
    return _PROTO_OUT


# --------------------------------------------------------------------- 帧
class ParseFailure:
    """`read_message()` 的失败标记。用对象而不是 `Exception`：

    解析失败要回 `-32700`，超长行要回 `-32600`，两者处理不同且都不该打断循环，
    用返回值表达比异常更直观。
    """

    __slots__ = ("reason", "detail")

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail

    def __repr__(self) -> str:  # pragma: no cover - 仅调试用
        return f"ParseFailure({self.reason!r})"


class StdioTransport:
    """唯一知道「帧长什么样」的类。读一行 / 写一行，别的什么都不做。"""

    def __init__(self, stdin: Any = None, stdout: Any = None) -> None:
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout

    # ------------------------------------------------------------ 内部
    def _source(self) -> Any:
        """优先拿**字节层**：文本层会做换行转换与编码回退，两者都会破坏帧。"""
        return getattr(self.stdin, "buffer", self.stdin)

    def read_message(self) -> dict | ParseFailure | None:
        """读一帧。

        返回：
            dict          —— 解析成功的 JSON 对象
            ParseFailure  —— 坏 JSON / 超长行
            None          —— EOF
        空行被忽略（宽容：某些客户端会在握手前多发一个换行）。
        """
        source = self._source()
        while True:
            try:
                raw = source.readline()
            except (OSError, ValueError):  # pragma: no cover - 管道被关闭
                return None
            if raw is None:
                return None
            if raw == b"" or raw == "":
                return None
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if len(raw) > MAX_LINE_BYTES:
                return ParseFailure("too_long", f"{len(raw)} bytes")
            chunk = raw.strip()
            if not chunk:
                continue
            try:
                return json.loads(chunk.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                return ParseFailure("parse_error", f"{exc.msg} at {exc.pos}")
            except (UnicodeDecodeError, RecursionError) as exc:  # pragma: no cover - 畸形输入
                return ParseFailure("parse_error", type(exc).__name__)

    def write_message(self, message: dict) -> None:
        """写一帧：`json.dumps(..., separators=(",",":"), ensure_ascii=False)` + "\\n"。

        `ensure_ascii=False` 是必须的：中文标题要以 UTF-8 原样出现（客户端按 UTF-8 解）；
        转成 `\\u6dd8\\u5b9d` 虽然合法，但会让人工核对报文变成苦差事。
        """
        line = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        data = (line + "\n").encode("utf-8")
        buffer = getattr(self.stdout, "buffer", None)
        if buffer is not None:
            buffer.write(data)
            buffer.flush()
            return
        try:
            self.stdout.write(data)
            self.stdout.flush()
        except TypeError:
            self.stdout.write(data.decode("utf-8"))
            self.stdout.flush()


# --------------------------------------------------------------------- 响应构造
def ok_response(request_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": int(code), "message": str(message)}}


# --------------------------------------------------------------------- 服务端
class McpServer:
    """JSON-RPC 分发器。`handle_message()` 是纯函数（便于单测），不做 IO。"""

    def __init__(
        self,
        settings: Settings,
        *,
        stdin: Any = None,
        stdout: Any = None,
        session: McpSession | None = None,
        transport: StdioTransport | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport if transport is not None else StdioTransport(stdin, stdout)
        self.session = session if session is not None else McpSession(settings)
        self.initialized = False
        self.client_info: dict = {}

    # ------------------------------------------------------------ 主循环
    def serve_forever(self) -> int:
        """读—分发—写，直到 EOF 或 Ctrl+C。返回进程退出码。"""
        log("start", count=len(list_tools()))
        try:
            while True:
                message = self.transport.read_message()
                if message is None:
                    break
                if isinstance(message, ParseFailure):
                    code = INVALID_REQUEST if message.reason == "too_long" else PARSE_ERROR
                    text = "Invalid Request: message too large" if code == INVALID_REQUEST else "Parse error"
                    log("frame_rejected", code=code)
                    self.transport.write_message(error_response(None, code, text))
                    continue
                reply = self.handle_message(message)
                if reply is not None:
                    self.transport.write_message(reply)
        except KeyboardInterrupt:  # pragma: no cover - 交互式中断
            log("interrupted")
        except BrokenPipeError:  # pragma: no cover - 客户端先退出
            log("broken_pipe")
        finally:
            self.session.drop()
            log("stop")
        return 0

    # ------------------------------------------------------------ 分发
    def handle_message(self, message: Any) -> dict | None:
        """处理一条已解析的消息。返回 None 表示**不回应**（通知）。"""
        if not isinstance(message, dict):
            log("invalid_request", code=INVALID_REQUEST)
            return error_response(None, INVALID_REQUEST, "Invalid Request: message must be a JSON object")

        has_id = "id" in message
        request_id = message.get("id", None)

        if message.get("jsonrpc") != "2.0":
            log("invalid_request", code=INVALID_REQUEST)
            return error_response(
                request_id if has_id else None,
                INVALID_REQUEST,
                'Invalid Request: jsonrpc must be "2.0"',
            )

        method = message.get("method")
        if not isinstance(method, str) or not method:
            return error_response(
                request_id if has_id else None,
                INVALID_REQUEST,
                "Invalid Request: missing method",
            )

        params = message.get("params", _MISSING)
        if params is _MISSING or params is None:
            params = {}
        if not isinstance(params, dict):
            if not has_id:
                return None
            return error_response(request_id, INVALID_PARAMS, f"Invalid params for {method}: must be an object")

        # 通知一律无响应。`notifications/initialized` 是最常见的一条：
        # 客户端声明「我准备好了」，规范要求服务端不回。
        if method.startswith("notifications/"):
            log("notification", code=method.split("/", 1)[-1])
            return None

        # 没有 id 的「请求」按通知处理（JSON-RPC 2.0：无 id = 通知）
        if not has_id:
            log("notification", code=method)
            return None

        try:
            if method == "initialize":
                return ok_response(request_id, self._initialize(params))
            if method == "ping":
                return ok_response(request_id, {})
            if method == "tools/list":
                self.initialized = True
                return ok_response(request_id, {"tools": list_tools()})
            if method == "tools/call":
                self.initialized = True
                return self._tools_call(request_id, params)
        except ToolError as exc:
            # 未知工具 / 参数不合法：协议错误（规范明确 Unknown tools 属 -32602）
            log("invalid_params", code=INVALID_PARAMS, id=str(request_id)[:32])
            return error_response(request_id, INVALID_PARAMS, str(exc))
        except Exception:  # noqa: BLE001 - 兜底：细节只进 stderr
            traceback.print_exc(file=sys.stderr)
            log("internal_error", code=INTERNAL_ERROR, id=str(request_id)[:32])
            return error_response(request_id, INTERNAL_ERROR, "internal error")

        log("unknown_method", code=METHOD_NOT_FOUND)
        return error_response(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    # ------------------------------------------------------------ 方法
    def _initialize(self, params: dict) -> dict:
        """握手。

        `protocolVersion` 的规则：客户端请求的版本在我们支持列表里就**原样回显**
        （这样新旧客户端都能走同一段代码），否则回我们自己支持的最新版，
        由客户端决定是否继续 —— 规范就是这么约定的。
        """
        requested = params.get("protocolVersion")
        version = requested if isinstance(requested, str) and requested in PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION

        client_info = params.get("clientInfo")
        self.client_info = dict(client_info) if isinstance(client_info, dict) else {}
        self.initialized = True

        log("initialize", code=version)
        return {
            "protocolVersion": version,
            # 工具表是静态的，不发 notifications/tools/list_changed，所以不声明 listChanged
            "capabilities": {"tools": {}},
            "serverInfo": dict(SERVER_INFO),
            "instructions": INSTRUCTIONS,
        }

    def _tools_call(self, request_id: Any, params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ToolError("Invalid arguments for tools/call: missing tool name")
        name = name.strip()

        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ToolError(f"Invalid arguments for {name}: arguments must be a JSON object")

        outcome = call_tool(self.session, name, arguments)
        payload = outcome.payload
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        log(
            "tools_call",
            code=name,
            count=1,
            id=str(payload.get("id") or "")[:32] if isinstance(payload, dict) else "",
        )
        return ok_response(
            request_id,
            {
                "content": [{"type": "text", "text": text}],
                "structuredContent": payload,
                "isError": bool(outcome.is_error),
            },
        )


# --------------------------------------------------------------------- 入口
def main(argv: list[str] | None = None, *, settings: Settings | None = None) -> int:
    """`python -m pwdvault.mcp_server`（`pv mcp` 在 T12 接到这里）。"""
    del argv
    stream = install_stdout_guard()
    settings = settings or load_settings()
    transport = StdioTransport(sys.stdin, stream)
    session = McpSession(settings)
    server = McpServer(settings, transport=transport, session=session)
    return server.serve_forever()


__all__ = [
    "INSTRUCTIONS",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "LATEST_PROTOCOL_VERSION",
    "MAX_LINE_BYTES",
    "METHOD_NOT_FOUND",
    "McpServer",
    "PARSE_ERROR",
    "PROTOCOL_VERSIONS",
    "ParseFailure",
    "SERVER_INFO",
    "SERVER_NAME",
    "SERVER_VERSION",
    "StdioTransport",
    "error_response",
    "install_stdout_guard",
    "log",
    "main",
    "ok_response",
    "protocol_stream",
    "unlock_chain",
]

if __name__ == "__main__":  # pragma: no cover - 入口
    raise SystemExit(main())
