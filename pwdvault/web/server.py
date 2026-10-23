"""HTTP 传输层（L5）：`ThreadingHTTPServer` + 安全三件套 + 静态托管 + chunked SSE。

本文件只负责「HTTP 报文怎么收发、路由怎么分派」。业务接口在 `web/api.py`（T09），
本迭代只提供会话级 4 个接口与 SSE：`/api/session`、`/api/unlock`、`/api/lock`、
`/api/events`。扩展方式是 `WebServer.router.add(method, "/api/xxx", handler)`，
handler 签名为 `Callable[[Request], Response]`，抛 `HttpError` 或 `VaultError`。

安全三件套（P0，缺一不可，DESIGN §9.4.4）
-----------------------------------------
1. **只绑 `127.0.0.1`**（硬编码，不从配置读；配置里写了别的值直接拒绝启动）。
2. **`Host` 头白名单**：必须是 `127.0.0.1:<port>` 或 `localhost:<port>`，否则 400。
   这是防 DNS rebinding 的唯一手段：攻击者把自己的域名解析到 127.0.0.1 之后，
   浏览器发出的请求 `Host` 仍然是攻击者的域名，于是被这里挡掉。
3. **一次性 session token**：启动时 `secrets.token_urlsafe(32)`，写进
   `runtime.json`（供 MCP/P1 代理用）+ 以 `HttpOnly; SameSite=Strict` Cookie 下发。
   所有 `/api/*` 都校验（SSE 也不例外），失败 401。
4. **不发任何 `Access-Control-*` 头**。没有 CORS 许可，浏览器的跨源 JS 读不到
   任何响应体；再加上 `SameSite=Strict`，跨站请求连 Cookie 都不会带上。

两个必须写对的 HTTP 细节（DESIGN R7）
------------------------------------
- `protocol_version = "HTTP/1.1"` 时，**所有非 SSE 响应都必须带 `Content-Length`**，
  否则浏览器会一直等连接结束，表现为「页面转圈」。
- SSE 必须手写 chunked：`ThreadingHTTPServer` 的响应以「连接关闭」为结束标志，
  `EventSource` 看到关闭就重连，于是每 2 秒断一次。手写 chunked 之后连接可长期
  存活，事件按块推送（见 `web/events.py` 的模块 docstring）。
"""

from __future__ import annotations

import atexit
import hmac
import json
import os
import queue
import re
import secrets
import signal
import socket
import sys
import threading
import traceback
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from .. import runtime
from ..config import Settings, load_settings, log_event
from ..errors import Refused, VaultError
from ..redact import public_error
from .events import CLOSE_EVENT, KEEPALIVE_BYTES, encode_chunk, encode_sse
from .session import AppState

# ---------------------------------------------------------------- 常量
#: 静态资源根目录。测试可以注入别的目录（`WebServer(static_root=...)`）。
PACKAGE_STATIC_DIR = Path(__file__).resolve().parent / "static"

#: 绑定地址：**硬编码**，不接受配置覆盖（见模块 docstring）。
BIND_HOST = "127.0.0.1"

DEFAULT_PORT = 8765
#: 端口占用时最多顺延多少个（8765 → 8784）。
PORT_ATTEMPTS = 20

COOKIE_NAME = "pv_session"
TOKEN_HEADER = "X-PV-Token"

#: 请求体上限（当前接口只收 JSON 小体；上传走 multipart 的 T09 另行放宽）。
MAX_BODY_BYTES = 8 * 1024 * 1024

ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})

CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
    ".map": "application/json; charset=utf-8",
}

#: 每个响应都带的安全头（不含任何 Access-Control-*）。
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    # 无构建链的本地单页：只允许同源脚本/样式，内联白名单是给「首屏主题脚本」用的
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}

#: `VaultError.code` → HTTP 状态码。
STATUS_BY_CODE: dict[str, int] = {
    "auth_failed": 401,
    "no_unlock_method": 400,
    "vault_not_found": 404,
    "vault_corrupt": 500,
    "vault_replaced": 409,
    "dpapi_unavailable": 400,
    "locked": 409,
    "lock_timeout": 503,
    "record_conflict": 409,
    "record_not_found": 404,
    "ambiguous_record": 409,
    "staging_busy": 409,
    "staging_not_found": 404,
    "invalid_record": 400,
    "import_failed": 400,
    "weak_password": 400,
    "refused": 400,
    "stale_write": 409,
}


# ---------------------------------------------------------------- 异常与响应
class HttpError(Exception):
    """传输层错误：由 dispatcher 统一翻译成 JSON 响应（一定带 Content-Length）。"""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        hint: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = int(status)
        self.code = str(code)
        self.message = str(message)
        self.hint = hint
        self.headers = dict(headers or {})


@dataclass
class Response:
    """一个待发送的 HTTP 响应。`body` 已经是最终字节，长度由 `_send` 写进 Content-Length。"""

    status: int = 200
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    cache_control: str = "no-store"
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie: str = ""

    @classmethod
    def json(
        cls,
        payload: Any,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        set_cookie: str = "",
    ) -> "Response":
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return cls(
            status=status,
            body=body,
            content_type="application/json; charset=utf-8",
            headers=dict(headers or {}),
            set_cookie=set_cookie,
        )

    @classmethod
    def text(
        cls,
        text: str,
        *,
        status: int = 200,
        content_type: str = "text/plain; charset=utf-8",
        headers: Mapping[str, str] | None = None,
    ) -> "Response":
        return cls(
            status=status,
            body=str(text).encode("utf-8"),
            content_type=content_type,
            headers=dict(headers or {}),
        )

    @classmethod
    def error(
        cls,
        status: int,
        code: str,
        message: str,
        *,
        hint: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> "Response":
        payload: dict[str, Any] = {"code": code, "message": message}
        if hint:
            payload["hint"] = hint
        return cls.json(payload, status=status, headers=headers)


@dataclass
class Request:
    """已经校验过 Host/Origin/token 的请求上下文，交给业务 handler。

    `headers` 是**小写键**的扁平字典：业务层要用 `X-PV-Editor-Id`（暂存区编辑者）
    与 `X-Filename`（inbox 上传的原始文件名），所以传输层把请求头原样传下去，
    而不是让 `web/api.py` 反向依赖 `BaseHTTPRequestHandler`。
    """

    method: str
    path: str
    query: dict[str, str]
    body: bytes
    state: AppState
    server: "WebServer"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def json_body(self) -> dict:
        """把请求体解析成 JSON 对象；空体视为 `{}`。"""
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HttpError(400, "invalid_json", "请求体不是合法的 JSON。") from exc
        if not isinstance(data, dict):
            raise HttpError(400, "invalid_json", "请求体必须是一个 JSON 对象。")
        return data

    def param(self, key: str, default: str = "") -> str:
        return str(self.params.get(key, default))

    def query_str(self, key: str, default: str = "") -> str:
        return str(self.query.get(key, default))

    def query_int(self, key: str, default: int) -> int:
        try:
            return int(self.query.get(key, default))
        except (TypeError, ValueError):
            return default


# ---------------------------------------------------------------- 路由
@dataclass(frozen=True)
class Route:
    """一条路由。`{name}` 占位符会被编译成命名分组。"""

    pattern: re.Pattern
    methods: frozenset[str]
    handler: Callable[..., Any]
    sse: bool = False


class Router:
    """极小的正则路由表。够 18 个接口用，不引入框架。"""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add(
        self,
        method: str,
        path: str,
        handler: Callable[..., Any],
        *,
        sse: bool = False,
    ) -> None:
        pattern = self.compile(path)
        existing = [route for route in self._routes if route.pattern.pattern == pattern.pattern]
        if existing:
            route = existing[0]
            self._routes[self._routes.index(route)] = Route(
                pattern=pattern,
                methods=route.methods | {method.upper()},
                handler=handler,
                sse=sse or route.sse,
            )
            return
        self._routes.append(
            Route(pattern=pattern, methods=frozenset({method.upper()}), handler=handler, sse=sse)
        )

    @staticmethod
    def compile(path: str) -> re.Pattern:
        """`/api/records/{id}` → `^/api/records/(?P<id>[^/]+)$`（严格锚定，不做前缀匹配）。"""
        out = ["^"]
        index = 0
        for match in re.finditer(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", path):
            out.append(re.escape(path[index : match.start()]))
            out.append(f"(?P<{match.group(1)}>[^/]+)")
            index = match.end()
        out.append(re.escape(path[index:]))
        out.append("$")
        return re.compile("".join(out))

    def resolve(self, method: str, path: str) -> tuple[Route, dict[str, str]] | None:
        """返回 `(route, params)`；路径存在但方法不匹配 → 405；全不匹配 → None。"""
        allowed: set[str] = set()
        for route in self._routes:
            matched = route.pattern.match(path)
            if matched is None:
                continue
            if method not in route.methods:
                allowed |= set(route.methods)
                continue
            return route, dict(matched.groupdict())
        if allowed:
            raise HttpError(
                405,
                "method_not_allowed",
                "这个路径不支持该请求方法。",
                headers={"Allow": ", ".join(sorted(allowed | {"GET", "HEAD"}))},
            )
        return None

    def routes(self) -> list[Route]:
        return list(self._routes)


# ---------------------------------------------------------------- 工具函数
def _const_eq(left: str, right: str) -> bool:
    """定时安全比较。非 ASCII 输入不会把 `compare_digest` 弄崩。"""
    try:
        return hmac.compare_digest(str(left).encode("utf-8"), str(right).encode("utf-8"))
    except Exception:  # noqa: BLE001 - 比较失败一律按不匹配处理
        return False


def cookie_value(header: str, name: str) -> str:
    """从 `Cookie` 头里取一个值。手写 10 行，不引 `http.cookies` 的边界行为。"""
    for chunk in str(header or "").split(";"):
        key, _, value = chunk.strip().partition("=")
        if key.strip() == name:
            return value.strip().strip('"')
    return ""


def _squash(text: str, *, limit: int = 160) -> str:
    """把任意文本压成单行（日志纪律：一行一条）。"""
    flat = " ".join(str(text).split())
    return flat[:limit]


# ---------------------------------------------------------------- 会话级 handler
def handle_index(req: Request) -> Response:
    """`GET /` → 首页（顺带下发 session Cookie）。"""
    return req.server.static_response("/index.html")


def handle_session(req: Request) -> Response:
    """`GET /api/session` → 会话状态（是否解锁、修订号、条数、自锁倒计时）。"""
    return Response.json(
        req.state.session_payload(),
        set_cookie=req.server.cookie_header(),
    )


def handle_unlock(req: Request) -> Response:
    """`POST /api/unlock` → 解锁。三选一：password / recovery_code / use_dpapi。"""
    data = req.json_body()
    password = data.get("password")
    recovery = data.get("recovery_code") or data.get("recovery")
    use_dpapi = bool(data.get("use_dpapi"))
    if password is not None and not isinstance(password, str):
        raise HttpError(400, "invalid_credential", "password 必须是字符串。")
    if recovery is not None and not isinstance(recovery, str):
        raise HttpError(400, "invalid_credential", "recovery_code 必须是字符串。")
    if not password and not recovery and not use_dpapi:
        raise HttpError(
            400,
            "missing_credential",
            "请提供主密码、恢复码，或选择用这台电脑直接进入。",
        )
    req.state.unlock(
        password=password or None,
        recovery_code=recovery or None,
        use_dpapi=use_dpapi,
    )
    return Response.json(req.state.session_payload(), set_cookie=req.server.cookie_header())


def handle_lock(req: Request) -> Response:
    """`POST /api/lock` → 立即上锁（丢内存 DEK）。"""
    req.state.lock()
    return Response.json(req.state.session_payload())


# ---------------------------------------------------------------- HTTP 服务器
class _ThreadingHTTPServer(ThreadingHTTPServer):
    """每个连接一个线程；daemon 保证 Ctrl+C 不被长驻 SSE 卡住。

    `allow_reuse_address` 在 Windows 上必须关掉：Windows 的 `SO_REUSEADDR` 语义与
    POSIX 不同，它允许**绑定到已被别人监听的端口**，于是「端口被占用 → 顺延」这条
    逻辑会失效（两个进程都"成功"绑上，第二个静默收不到流量）。关掉之后 bind 会
    正常抛 `WSAEADDRINUSE`，顺延逻辑才能生效。
    """

    daemon_threads = True
    allow_reuse_address = sys.platform != "win32"
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], handler_cls: type, web: "WebServer") -> None:
        self.web = web
        super().__init__(address, handler_cls)

    def handle_error(self, request: Any, client_address: Any) -> None:
        """连接被客户端掐断是**正常路径**（关标签页、SSE 断开），不打印 traceback。

        `socketserver` 默认把每个异常都打成多行 traceback，SSE 一断就连刷十几行，
        既污染日志也违反「单行 stderr」的纪律。真正的内部错误仍然打出来。
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        log_event(
            "server_error",
            scope="pv web",
            level="ERROR",
            code=type(exc).__name__ if exc is not None else "unknown",
        )
        traceback.print_exc(file=sys.stderr)


class _Handler(BaseHTTPRequestHandler):
    """请求处理器。所有方法都汇到 `_dispatch`，保证「一条路径只有一套安全校验」。"""

    protocol_version = "HTTP/1.1"
    server_version = "pwdvault"
    sys_version = ""
    # 空闲 keep-alive 连接的回收时间（秒）。SSE 期间只在写阻塞时生效，块很小不会触发。
    timeout = 60

    def version_string(self) -> str:
        """只报产品名，不报 Python/系统版本（少暴露一点指纹）。"""
        return self.server_version

    # ---- 日志：访问日志不刷屏；错误由 dispatcher 显式记录（单行、无字段值）
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102 - 覆盖基类
        return

    def log_error(self, fmt: str, *args: Any) -> None:  # noqa: D102 - 覆盖基类
        log_event("http_error", scope="pv web", level="WARN", detail=_squash(fmt % args))

    # ---- 方法入口
    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")

    # ---- 分发
    def _dispatch(self, method: str) -> None:
        web = self.server.web  # type: ignore[attr-defined]
        self._body_consumed = False
        head = method == "HEAD"
        try:
            web.guard_host(self)  # ① DNS rebinding
            path, query = self._parse_target()
            if method in ("POST", "PATCH", "PUT", "DELETE"):
                web.guard_origin(self)  # ② CSRF（Origin 存在时必须同源）
            is_api = path == "/api" or path.startswith("/api/")
            if is_api:
                web.guard_token(self)  # ③ 一次性 token
                web.state.touch()
            body = self._read_body()

            req = Request(
                method=method,
                path=path,
                query=query,
                body=body,
                state=web.state,
                server=web,
                headers={str(key).lower(): str(value) for key, value in self.headers.items()},
            )
            route_match = web.router.resolve("GET" if head else method, path)
            if route_match is None:
                if is_api:
                    raise HttpError(404, "not_found", "接口不存在。")
                if method not in ("GET", "HEAD"):
                    raise HttpError(405, "method_not_allowed", "这个路径只支持 GET。")
                self._send(web.static_response(path), head=head)
                return

            route, params = route_match
            req.params = params
            if route.sse:
                if head:
                    # HEAD 不能带响应体，而 SSE 的语义就是「一直往下写」
                    raise HttpError(
                        405, "method_not_allowed", "SSE 只支持 GET。", headers={"Allow": "GET"}
                    )
                web.stream_events(self)  # 自己写 chunked，不产生 Response
                return
            self._send(route.handler(req), head=head)
        except HttpError as exc:
            self._send(
                Response.error(
                    exc.status, exc.code, exc.message, hint=exc.hint, headers=exc.headers
                ),
                head=head,
            )
        except VaultError as exc:
            status = STATUS_BY_CODE.get(exc.code, 400)
            self._send(Response.json(public_error(exc), status=status), head=head)
            log_event("api_error", scope="pv web", level="WARN", code=exc.code, method=method)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except socket.timeout:  # pragma: no cover - 客户端半途不发数据
            self.close_connection = True
        except Exception:  # noqa: BLE001 - 兜底：绝不把 traceback 发给客户端
            print(
                "[pv web] ERROR event=unhandled_exception\n" + traceback.format_exc(),
                file=sys.stderr,
                flush=True,
            )
            self._send(
                Response.error(500, "internal_error", "服务内部出错了，请查看终端日志。"),
                head=head,
            )

    # ---- 目标与请求体
    def _parse_target(self) -> tuple[str, dict[str, str]]:
        raw = self.path or "/"
        if not raw.startswith("/"):
            # 绝对形式的 request-target（`GET http://x/ HTTP/1.1`）一律拒绝：
            # 它会让 Host 校验失去意义
            raise HttpError(400, "bad_target", "只接受以 / 开头的请求目标。")
        path, _, query_string = raw.partition("?")
        path = urllib.parse.unquote(path)
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        return path, {key: values[-1] for key, values in parsed.items() if values}

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise HttpError(411, "chunked_body_unsupported", "请在请求里带 Content-Length。")
        raw = self.headers.get("Content-Length")
        if not raw:
            self._body_consumed = True
            return b""
        try:
            length = int(str(raw).split(",")[0].strip())
        except ValueError as exc:
            raise HttpError(400, "bad_content_length", "Content-Length 不是整数。") from exc
        if length < 0:
            raise HttpError(400, "bad_content_length", "Content-Length 不能是负数。")
        if length > MAX_BODY_BYTES:
            raise HttpError(413, "body_too_large", "请求体太大了。")
        data = self.rfile.read(length) if length else b""
        self._body_consumed = True
        if len(data) != length:
            raise HttpError(400, "short_body", "请求体比 Content-Length 短。")
        return data

    def _drain_body(self, *, seconds: float = 1.0) -> None:
        """把**没读完**的请求体吃掉，再让连接关闭。

        为什么必须做：`guard_host` / `guard_origin` / `guard_token` 都在读体之前
        就拒绝请求。此时若直接 `close_connection = True`，Windows 上「带着未读数据
        close」是**abortive close**，内核会发 RST 而不是 FIN，飞行中的响应字节被
        丢弃 —— 客户端随机拿到 `ConnectionAbortedError` / 浏览器报 "Failed to
        fetch"，而不是干净的 403/401/400。这是本地实测复现过的（8 次全量跑挂 1 次），
        属于协议层缺陷，不是测试抖动。

        界面上限 1 秒 + `MAX_BODY_BYTES`：本服务的请求体都很小（JSON），真有人发
        8MB 慢速体也只是让这一个线程多等 1 秒，然后照常拒绝。
        """
        if getattr(self, "_body_consumed", True):
            return
        raw = self.headers.get("Content-Length")
        if not raw or self.headers.get("Transfer-Encoding"):
            # 没有体，或者是 chunked（我们不解），无法按长度排干 → 只能关连接
            self._body_consumed = True
            self.close_connection = True
            return
        try:
            length = int(str(raw).split(",")[0].strip())
        except ValueError:
            self.close_connection = True
            return
        if length <= 0:
            self._body_consumed = True
            return

        remaining = min(length, MAX_BODY_BYTES)
        previous = None
        try:
            previous = self.connection.gettimeout()
            self.connection.settimeout(max(0.05, float(seconds)))
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._body_consumed = remaining == 0
        except OSError:
            self.close_connection = True
        finally:
            try:
                if previous is not None:
                    self.connection.settimeout(previous)
            except OSError:
                pass
        if not self._body_consumed:
            self.close_connection = True

    # ---- 发送
    def _send(self, response: Response, *, head: bool = False) -> None:
        body = bytes(response.body or b"")
        # 先把残留请求体排干：否则关闭时发 RST，客户端读不到这条响应（见 _drain_body）
        self._drain_body()
        try:
            self.send_response(int(response.status))
            self.send_header("Content-Type", response.content_type)
            # HTTP/1.1 下缺 Content-Length 浏览器会一直等：这里**每条**非 SSE 响应都写
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", response.cache_control)
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            if response.set_cookie:
                self.send_header("Set-Cookie", response.set_cookie)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            if not head and body:
                self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True
            return
        finally:
            # 请求体没读完就不能复用这条连接（否则下一个请求会读到上一个的残余）
            if not getattr(self, "_body_consumed", True):
                self.close_connection = True


class WebServer:
    """把 settings + AppState + 路由 + 监听套接字装配成一个可启动/可停止的对象。

    典型用法（`serve()` 就是这么写的）::

        server = WebServer(settings)
        server.start()          # 绑端口、写 runtime.json、起后台线程
        server.serve_forever()  # 阻塞
        server.stop()           # 幂等收尾
    """

    def __init__(
        self,
        settings: Settings,
        *,
        port: int | None = None,
        open_browser: bool = True,
        token: str | None = None,
        static_root: str | Path | None = None,
        state: AppState | None = None,
        auto_lock_seconds: float | None = None,
        poll_seconds: float | None = None,
        idle_check_seconds: float | None = None,
        heartbeat_seconds: float | None = None,
        quiet: bool = False,
    ) -> None:
        self.settings = settings
        self.requested_port = DEFAULT_PORT if port is None else int(port)
        self.open_browser = bool(open_browser)
        self.token = str(token or secrets.token_urlsafe(32))
        self.static_root = Path(static_root) if static_root is not None else PACKAGE_STATIC_DIR
        self.quiet = bool(quiet)

        state_kwargs: dict[str, Any] = {"token": self.token}
        if auto_lock_seconds is not None:
            state_kwargs["auto_lock_seconds"] = auto_lock_seconds
        if poll_seconds is not None:
            state_kwargs["poll_seconds"] = poll_seconds
        if idle_check_seconds is not None:
            state_kwargs["idle_check_seconds"] = idle_check_seconds
        if heartbeat_seconds is not None:
            state_kwargs["heartbeat_seconds"] = heartbeat_seconds
        self.state = state or AppState(settings, **state_kwargs)

        self.router = Router()
        self.register_core_routes()

        self._httpd: _ThreadingHTTPServer | None = None
        self._serving = False
        self._closed = False
        self._stop_guard = threading.Lock()
        self._cleanup_done = threading.Event()
        self.port = 0
        self.url = ""

    # ------------------------------------------------------------- 路由装配
    def register_core_routes(self) -> None:
        """注册本迭代的会话级接口。T09 在这里之后追加 `/api/records` 等。

        **T09 契约备忘（来自 T07 的接口变更，不要按 DESIGN 旧版写）**

        1. `POST /api/records/{id}/copy` 必须
           `service.copy_field(record, field, seconds=..., spawn=False)`。
           本进程是长驻服务，且可能由 `python -m pwdvault.web` 启动；那种情况下
           `sys.argv[0]` 是 `web/__main__.py`，`clipboard.spawn_clear_watcher()`
           拉起的子进程会因不认识 `_clipwatch` 立即退出 —— 回执说「30 秒后清空」，
           实际永远不清，等于对用户撒谎。`spawn=False` 走进程内 daemon Timer，
           到点仍按**摘要**比对，用户中途复制了别的东西就不清空。
        2. `copy_field` 的回执**原样透传**（可加字段，绝不删减）：
           装上定时器 → `{copied, title, field, auto_clear: true, auto_clear_in,
           auto_clear_mode, host?}`；装不上 → `{..., auto_clear: false,
           auto_clear_in: 0, auto_clear_mode, hint}`。
        3. 前端只能以 `auto_clear === true` 为依据承诺倒计时；`false` 时必须展示
           `hint` 让用户自己覆盖剪贴板。无条件显示倒计时 = 骗用户。
        """
        self.router.add("GET", "/", handle_index)
        self.router.add("GET", "/api/session", handle_session)
        self.router.add("POST", "/api/unlock", handle_unlock)
        self.router.add("POST", "/api/lock", handle_lock)
        self.router.add("GET", "/api/events", self.stream_events, sse=True)

        # 业务接口（T09）在 `web/api.py` 里集中注册。`api` 必须在这里再 import：
        # `api.py` 需要 `Request` / `Response` / `HttpError`，顶层互相 import 会成环；
        # 延迟到路由装配时（两个模块都已加载完）再取最安全。
        from .api import register_api_routes  # noqa: PLC0415 - 见上

        register_api_routes(self)

    # ------------------------------------------------------------- 安全校验
    def guard_host(self, handler: BaseHTTPRequestHandler) -> None:
        """Host 白名单（防 DNS rebinding）。端口必须与本服务一致。"""
        raw = str(handler.headers.get("Host") or "").strip()
        if not raw:
            raise HttpError(400, "bad_host", "缺少 Host 头。")
        host, separator, port = raw.rpartition(":")
        if not separator:
            host, port = raw, ""
        host = host.strip().strip("[]").lower()
        port = port.strip()
        if host not in ALLOWED_HOSTS:
            raise HttpError(400, "bad_host", "Host 头不被接受。")
        if port != str(self.port):
            raise HttpError(400, "bad_host", "Host 头里的端口与本服务不一致。")

    def guard_origin(self, handler: BaseHTTPRequestHandler) -> None:
        """写请求带 Origin 时必须同源；不带 Origin 的（curl / 命令行）放行。"""
        origin = handler.headers.get("Origin")
        if origin is None:
            return
        allowed = {
            f"http://127.0.0.1:{self.port}",
            f"http://localhost:{self.port}",
        }
        if str(origin).strip().rstrip("/") not in allowed:
            raise HttpError(403, "bad_origin", "跨站请求被拒绝。")

    def guard_token(self, handler: BaseHTTPRequestHandler) -> None:
        """一次性 session token：先看头，再看 Cookie。失败 401。"""
        supplied = str(handler.headers.get(TOKEN_HEADER) or "")
        if not supplied:
            supplied = cookie_value(str(handler.headers.get("Cookie") or ""), COOKIE_NAME)
        if not supplied or not _const_eq(supplied, self.token):
            raise HttpError(401, "unauthorized", "缺少或错误的会话 token，请重新打开页面。")

    def cookie_header(self) -> str:
        return f"{COOKIE_NAME}={self.token}; Path=/; HttpOnly; SameSite=Strict"

    # ------------------------------------------------------------- 静态资源
    def static_response(self, path: str) -> Response:
        """把 URL 路径映射成包内静态文件。越界一律 404（不泄露文件是否存在）。"""
        target = self.resolve_static(path)
        if target is None:
            return Response.text("404 页面不存在。\n", status=404)
        try:
            data = target.read_bytes()
        except OSError:
            return Response.text("404 页面不存在。\n", status=404)
        suffix = target.suffix.lower()
        response = Response(
            status=200,
            body=data,
            content_type=CONTENT_TYPES.get(suffix, "application/octet-stream"),
            cache_control="no-store",
        )
        if suffix in (".html", ".htm"):
            # 首屏就下发 Cookie：SSE 与 /api/* 都靠它（EventSource 不能自定义头）
            response.set_cookie = self.cookie_header()
        return response

    def resolve_static(self, path: str) -> Path | None:
        """路径穿越防护的核心。

        三道关：
          1. 逐层 URL 解码（最多 3 次），挡住 `..%2f`、`%252e%252e` 这类二次编码；
          2. 按 `/` 切段，任一段等于 `..` 直接拒绝（不依赖操作系统的规范化行为）；
          3. `os.path.realpath` 之后再比对 `commonpath`，挡住符号链接/短名跳出目录。
        Windows 上还要把 `\\` 当成 `/`，否则 `..\\` 会绕过第 2 关。
        """
        root_real = os.path.realpath(str(self.static_root))
        decoded = str(path or "/")
        for _ in range(3):
            expanded = urllib.parse.unquote(decoded)
            if expanded == decoded:
                break
            decoded = expanded
        decoded = decoded.replace("\\", "/")
        if "\x00" in decoded:
            return None
        relative = decoded.lstrip("/") or "index.html"
        if relative.endswith("/"):
            relative += "index.html"
        parts = [part for part in relative.split("/") if part not in ("", ".")]
        if not parts or any(part == ".." for part in parts):
            return None
        candidate = os.path.join(root_real, *parts)
        resolved = os.path.realpath(candidate)
        try:
            if os.path.normcase(os.path.commonpath([resolved, root_real])) != os.path.normcase(root_real):
                return None
        except ValueError:  # 不同盘符
            return None
        if not os.path.isfile(resolved):
            return None
        return Path(resolved)

    # ------------------------------------------------------------- SSE
    def stream_events(self, handler: BaseHTTPRequestHandler) -> None:
        """一条长连接：首帧发 `session`，之后按事件推送，空闲每 `heartbeat` 秒一条注释行。

        连接必须用 chunked（见模块 docstring），且**不能**写 Content-Length。
        """
        state = self.state
        box = state.bus.subscribe()
        try:
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Connection", "keep-alive")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.send_header("X-Accel-Buffering", "no")
            handler.end_headers()
            handler.close_connection = False
            self._write_chunk(handler, encode_sse("session", state.session_payload()))
            while not state.stop_event.is_set():
                try:
                    event, data = box.get(timeout=state.heartbeat_seconds)
                except queue.Empty:
                    self._write_chunk(handler, KEEPALIVE_BYTES)
                    continue
                if event == CLOSE_EVENT:
                    break
                self._write_chunk(handler, encode_sse(event, data))
        except (BrokenPipeError, ConnectionResetError, OSError):
            # 客户端关掉页面 / 切走：正常路径，不记 ERROR，只清队列
            pass
        finally:
            state.bus.unsubscribe(box)
            try:
                self._write_chunk(handler, b"")  # 终止块："0\r\n\r\n"
            except OSError:
                pass

    @staticmethod
    def _write_chunk(handler: BaseHTTPRequestHandler, payload: bytes) -> None:
        handler.wfile.write(encode_chunk(payload))  # type: ignore[attr-defined]
        handler.wfile.flush()  # type: ignore[attr-defined]

    # ------------------------------------------------------------- 生命周期
    def start(self) -> str:
        """绑定端口（占用则顺延）、写 `runtime.json`、起后台线程、打印实际地址。"""
        if self._httpd is not None:
            return self.url
        configured_host = str(getattr(self.settings, "web_host", BIND_HOST))
        if configured_host not in ALLOWED_HOSTS:
            raise Refused(
                f"Web 服务只允许绑定 127.0.0.1，配置里的 host={configured_host} 不被接受。"
            )

        self._httpd = self._bind()
        self.port = int(self._httpd.server_address[1])
        self.state.port = self.port
        self.url = f"http://127.0.0.1:{self.port}/"

        runtime.write_runtime(
            self.settings.home,
            port=self.port,
            token=self.token,
            host=BIND_HOST,
        )
        self.state.start_background(port=self.port)
        log_event("start", scope="pv web", port=self.port, pid=os.getpid())
        if not self.quiet:
            print(f"[pv web] 已启动：{self.url}", file=sys.stderr, flush=True)
            print(
                f"[pv web] 状态文件：{runtime.runtime_path(self.settings.home)}",
                file=sys.stderr,
                flush=True,
            )
        if self.open_browser:
            threading.Thread(target=self._open_browser, name="pv-web-browser", daemon=True).start()
        return self.url

    def _bind(self) -> _ThreadingHTTPServer:
        """端口顺延：`requested_port` 起最多试 `PORT_ATTEMPTS` 个。`port=0` 直接要临时端口。"""
        candidates = (
            [0]
            if self.requested_port == 0
            else [self.requested_port + offset for offset in range(PORT_ATTEMPTS)]
        )
        last_error: OSError | None = None
        for candidate in candidates:
            try:
                return _ThreadingHTTPServer((BIND_HOST, candidate), _Handler, self)
            except OSError as exc:
                last_error = exc
                log_event(
                    "port_busy",
                    scope="pv web",
                    level="WARN",
                    port=candidate,
                    code=getattr(exc, "errno", 0) or 0,
                )
        raise Refused(
            f"端口 {self.requested_port} ~ {self.requested_port + PORT_ATTEMPTS - 1} 都被占用，无法启动。",
        ) from last_error

    def serve_forever(self) -> None:
        """阻塞在 accept 循环里。`stop()`（另一个线程）会让它返回。"""
        httpd = self._httpd
        if httpd is None:
            # `stop()` 已经在 `serve_forever()` 之前跑完（stdin 立刻 EOF、或收到
            # 信号早于进入 accept 循环）：套接字与 runtime.json 都收好了，直接返回。
            # 不这么写的话，`--exit-when-stdin-closes` 在「启动瞬间 stdin 就是
            # EOF」时会抛 Refused，退出码变成 1，看起来像启动失败。
            if self._closed:
                return
            raise Refused("先调用 start() 再 serve_forever()。")
        self._serving = True
        try:
            httpd.serve_forever(poll_interval=0.2)
        finally:
            self._serving = False

    def start_in_thread(self) -> threading.Thread:
        """`start()` 之后在后台线程跑 `serve_forever()`，返回该线程。

        测试与嵌入（比如将来做 `pv web --daemon`）需要「不阻塞当前线程」的启动方式。
        先把 `_serving` 置上再起线程，避免 `stop()` 与线程启动之间的竞态导致漏掉
        `shutdown()`。
        """
        if self._httpd is None:
            raise Refused("先调用 start() 再 start_in_thread()。")
        self._serving = True
        thread = threading.Thread(target=self.serve_forever, name="pv-web-serve", daemon=True)
        thread.start()
        return thread

    def stop(self, *, timeout: float = 5.0) -> None:
        """幂等收尾：停后台线程 → 关监听套接字 → 删 `runtime.json` → 释放端口。

        并发调用必须**等第一个收完再返回**，不能看到「已经有人开始了」就直接返回：
        `--exit-when-stdin-closes` 下 stdin 监视线程先调 `stop()`，主线程的
        `serve()` 紧接着在 `finally` 里也调一次，然后 `pv.py` 就 `SystemExit` 了。
        如果后者直接返回，解释器会立刻退出并**杀掉还在收尾的 daemon 线程** ——
        症状是进程退出码 0、日志里没有 `event=stop`、而 `runtime.json` 留在盘上
        （脏文件会让 MCP 代理探测到假 pid）。这不是理论问题，是本轮实测踩到的。
        """
        with self._stop_guard:
            waiter = self._cleanup_done if self._closed else None
            if waiter is None:
                self._closed = True
        if waiter is not None:
            waiter.wait(timeout)
            return

        try:
            self._close_impl(timeout=timeout)
        finally:
            self._cleanup_done.set()

    def _close_impl(self, *, timeout: float) -> None:
        """真正的收尾动作。只由 `stop()` 里抢到「执行权」的那个线程调用。"""
        try:
            self.state.close()
        except Exception:  # noqa: BLE001 - 收尾不能抛
            log_event("state_close_failed", scope="pv web", level="WARN")

        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            if self._serving:
                # shutdown() 必须从别的线程调，否则会和自己等死
                reaper = threading.Thread(
                    target=httpd.shutdown, name="pv-web-shutdown", daemon=True
                )
                reaper.start()
                reaper.join(timeout)
            try:
                httpd.server_close()
            except OSError:
                pass

        removed = runtime.clear_runtime(self.settings.home)
        log_event(
            "stop",
            scope="pv web",
            port=self.port,
            runtime_removed=int(bool(removed)),
        )

    def _open_browser(self) -> None:
        try:
            webbrowser.open(self.url)
        except Exception:  # noqa: BLE001 - 打不开浏览器不是错误
            log_event("open_browser_failed", scope="pv web", level="WARN")


# ---------------------------------------------------------------- 入口
def _raise_keyboard_interrupt(signum: int, frame: Any) -> None:  # noqa: ARG001
    """SIGINT/SIGTERM/SIGBREAK 统一转成 KeyboardInterrupt，让 finally 里的收尾跑到。"""
    raise KeyboardInterrupt


def _stdin_is_tty(stream: Any = None) -> bool:
    """stdin 是不是终端。判断失败按「是终端」处理（保守：不乱关别人的服务）。"""
    source = sys.stdin if stream is None else stream
    try:
        return bool(source.isatty())
    except (AttributeError, ValueError, OSError):
        return True


def _watch_stdin_eof(server: WebServer, stream: Any = None) -> None:
    """读到 stdin EOF 就请求关闭（`--exit-when-stdin-closes` 用）。

    为什么需要：Windows 上 `Popen.terminate()` 是 `TerminateProcess`，不发任何信号，
    `finally` / `atexit` 都不会跑，于是 `runtime.json` 会留在盘上。脏文件比「进程没了」
    更危险：后续 MCP 代理探测会读到假 pid，可能把调用转发到一个已经死掉的端口。
    于是留一个「stdin 关闭 = 请退出」的通道，让测试（与 `pv web < 管道`）能真正
    走到优雅收尾。

    收尾只调 `server.stop()` —— 与 Ctrl+C 路径是**同一个函数**，不另写一份清理逻辑
    （两份清理逻辑迟早会不同步，而这里的后果是端口泄漏或 runtime.json 残留）。
    `stop()` 内部从别的线程调 `httpd.shutdown()`，于是主线程的 `serve_forever()`
    会正常返回，`serve()` 的 `finally` 再跑一次幂等的 `stop()`。
    """
    source = sys.stdin if stream is None else stream
    try:
        while True:
            chunk = source.readline()
            if not chunk:
                break
    except (OSError, ValueError):  # 管道被对端异常关闭 / 流已 detach
        pass
    if not server.quiet:
        print("[pv web] 标准输入已关闭，正在关闭服务…", file=sys.stderr, flush=True)
    server.stop()


def serve(
    settings: Settings,
    *,
    port: int | None = None,
    open_browser: bool = True,
    static_root: str | Path | None = None,
    quiet: bool = False,
    exit_when_stdin_closes: bool = False,
    **kwargs: Any,
) -> int:
    """启动 Web 服务并阻塞，直到 Ctrl+C 或收到终止信号。返回进程退出码。

    收尾顺序（不能被 `KeyboardInterrupt` 打断成半截）：停后台线程 → 关监听 →
    删 `runtime.json` → 释放端口。`atexit` 再兜一层，防止异常路径漏掉。

    `exit_when_stdin_closes`：stdin 读到 EOF 时走与 Ctrl+C 相同的收尾路径。
    **只在 stdin 不是终端时生效** —— 用户在终端里按 Ctrl+D 不应该把服务关掉，
    只有「被父进程用管道接管」时才把它当成退出信号。
    """
    server = WebServer(
        settings,
        port=port,
        open_browser=open_browser,
        static_root=static_root,
        quiet=quiet,
        **kwargs,
    )
    atexit.register(server.stop)

    previous: dict[Any, Any] = {}
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, _raise_keyboard_interrupt)
        except (ValueError, OSError, RuntimeError):  # 非主线程 / 平台不支持
            continue

    try:
        server.start()
        if exit_when_stdin_closes and not _stdin_is_tty():
            threading.Thread(
                target=_watch_stdin_eof,
                args=(server,),
                name="pv-web-stdin",
                daemon=True,
            ).start()
        server.serve_forever()
    except KeyboardInterrupt:
        if not quiet:
            print("[pv web] 收到退出信号，正在关闭…", file=sys.stderr, flush=True)
    finally:
        server.stop()
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError, RuntimeError, TypeError):
                continue
    return 0


def main(argv: list[str] | None = None) -> int:
    """`python -m pwdvault.web` 的入口：只做参数解析，然后交给 `serve()`。"""
    args = list(sys.argv[1:] if argv is None else argv)
    port: int | None = None
    open_browser = True
    vault: str | None = None
    index = 0
    while index < len(args):
        item = args[index]
        if item in ("--no-browser", "-n"):
            open_browser = False
        elif item in ("--port", "-p") and index + 1 < len(args):
            index += 1
            try:
                port = int(args[index])
            except ValueError:
                print("[pv web] --port 需要一个整数", file=sys.stderr, flush=True)
                return 2
        elif item.startswith("--port="):
            try:
                port = int(item.split("=", 1)[1])
            except ValueError:
                print("[pv web] --port 需要一个整数", file=sys.stderr, flush=True)
                return 2
        elif item in ("--vault", "-V") and index + 1 < len(args):
            index += 1
            vault = args[index]
        elif item.startswith("--vault="):
            vault = item.split("=", 1)[1]
        elif item in ("--help", "-h"):
            print(
                "用法: python -m pwdvault.web [--port N] [--no-browser] [--vault PATH]",
                file=sys.stderr,
                flush=True,
            )
            return 0
        else:
            print(f"[pv web] 未知参数：{item}", file=sys.stderr, flush=True)
            return 2
        index += 1

    return serve(load_settings(vault_override=vault), port=port, open_browser=open_browser)


__all__ = [
    "BIND_HOST",
    "COOKIE_NAME",
    "DEFAULT_PORT",
    "HttpError",
    "PORT_ATTEMPTS",
    "Request",
    "Response",
    "Route",
    "Router",
    "TOKEN_HEADER",
    "WebServer",
    "cookie_value",
    "main",
    "serve",
]


if __name__ == "__main__":  # pragma: no cover - 手工调试用
    raise SystemExit(main())
