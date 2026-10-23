"""SSE 事件总线：每个订阅者一个 `queue.Queue`，`publish()` 广播。属于 L4。

为什么必须手写 chunked 编码
---------------------------
`http.server` 的语义是「响应体写完就结束这个响应」，`ThreadingHTTPServer` 默认
`close_connection = True`。浏览器 `EventSource` 看到连接被关掉会按规范在 3 秒后
重连，于是 UI 上表现为「每 2~3 秒断一次、状态条反复闪」。解决办法只有一个：
用 HTTP/1.1 的 `Transfer-Encoding: chunked`（十六进制长度前缀 + 块体），让一条
连接可以长期存活、按块推送、永不主动结束。chunked 由本模块的
`encode_chunk()` 生成，服务端只负责 `wfile.write()` + `flush()`。

设计要点
--------
1. **订阅者之间完全隔离**。每个客户端一个独立队列，发布时逐个 `put_nowait`，
   任何一个客户端断开或卡住都不影响其他人（这是「20 个订阅不串包」的实现基础）。
2. **落后比丢事件安全**。队列满（默认 64 条）时清空该队列并只投一条
   `("lag", {})`，语义是「你落后了，请全量刷新」，前端收到 `lag` 就重新拉一次
   列表。静默丢事件会让 UI 停留在错误的旧状态，那比多一次全量请求糟得多。
3. **关闭要能叫醒阻塞者**。SSE 线程阻塞在 `queue.get(timeout=heartbeat)` 上，
   进程退出时不能让每个连接各等 15 秒，所以 `close()` 会往每个队列塞一个
   `CLOSE_EVENT` 哨兵。
"""

from __future__ import annotations

import json
import queue
import threading
from typing import Any

#: 心跳：SSE 注释行。没有 data，浏览器会忽略，但足以让代理/浏览器知道连接还活着。
KEEPALIVE_BYTES = b": ping\n\n"

#: 队列满时的降级信号（前端收到后全量刷新）。
LAG_EVENT = "lag"

#: 服务端主动关闭连接用的哨兵事件名（不是业务事件，前端永远收不到）。
CLOSE_EVENT = "__close__"

DEFAULT_MAXSIZE = 64


def encode_sse(event: str, data: dict | None = None) -> bytes:
    """把一条业务事件编码成 SSE 帧：`event: <名>\\ndata: <单行 JSON>\\n\\n`。

    `json.dumps` 会把字符串里的换行转义成 `\\n`，所以 data 永远只占一行，
    不需要（也不能）写成多行 `data:` —— 多行形式在解析上更容易出错。
    """
    payload = json.dumps(dict(data or {}), ensure_ascii=False, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")


def encode_chunk(payload: bytes) -> bytes:
    """给一块数据加上 chunked 长度前缀与结尾 CRLF。

    格式（RFC 9112 §7.1）：``<十六进制长度> CRLF <数据> CRLF``。
    长度为 0 的块是终止块（本模块不生成，由 server 在收尾时写）。
    """
    body = bytes(payload)
    return b"%X\r\n" % len(body) + body + b"\r\n"


class EventBus:
    """进程内广播总线。线程安全，无第三方依赖。"""

    def __init__(self, *, maxsize: int = DEFAULT_MAXSIZE) -> None:
        self._maxsize = max(1, int(maxsize))
        self._guard = threading.Lock()
        self._subs: list[queue.Queue] = []
        self._closed = False
        self._published = 0
        self._dropped = 0

    # ------------------------------------------------------------- 订阅
    def subscribe(self) -> "queue.Queue[tuple[str, dict]]":
        """新建一个订阅队列。调用方必须在结束后 `unsubscribe()`（server 用 finally 保证）。"""
        box: queue.Queue[tuple[str, dict]] = queue.Queue(maxsize=self._maxsize)
        with self._guard:
            self._subs.append(box)
        return box

    def unsubscribe(self, box: "queue.Queue[tuple[str, dict]]") -> None:
        """幂等移除。重复调用不抛异常（断开与收尾都会调一次）。"""
        with self._guard:
            try:
                self._subs.remove(box)
            except ValueError:
                pass

    def subscriber_count(self) -> int:
        """当前订阅者数量。测试用它断言「客户端断开后队列被清理干净」。"""
        with self._guard:
            return len(self._subs)

    @property
    def published(self) -> int:
        """累计发布次数（诊断用）。"""
        return self._published

    @property
    def dropped(self) -> int:
        """累计因队列满而降级的次数（诊断用）。"""
        return self._dropped

    def is_closed(self) -> bool:
        with self._guard:
            return self._closed

    # ------------------------------------------------------------- 发布
    def publish(self, event: str, data: Any = None) -> int:
        """广播一条事件，返回实际投递到的订阅者数量。

        - 队列满 → 清空该队列 + 投 `lag`（见模块 docstring 第 2 点）。
        - 总线已关闭 → 直接返回 0，不抛异常（关闭竞态下调用方不必加锁）。
        """
        payload = (str(event), dict(data) if isinstance(data, dict) else {})
        with self._guard:
            if self._closed:
                return 0
            subs = list(self._subs)
            self._published += 1

        delivered = 0
        for box in subs:
            try:
                box.put_nowait(payload)
                delivered += 1
                continue
            except queue.Full:
                pass
            self._drop_log(box)
            try:
                box.put_nowait((LAG_EVENT, {"dropped": True}))
                delivered += 1
            except queue.Full:  # pragma: no cover - 被 drain 后几乎不可能再满
                pass
        return delivered

    def _drop_log(self, box: "queue.Queue[tuple[str, dict]]") -> None:
        self._dropped += 1
        while True:
            try:
                box.get_nowait()
            except queue.Empty:
                return

    # ------------------------------------------------------------- 关闭
    def close(self) -> None:
        """停止广播，并叫醒所有阻塞在 `get()` 上的 SSE 线程。幂等。"""
        with self._guard:
            if self._closed:
                return
            self._closed = True
            subs = list(self._subs)
            self._subs.clear()
        for box in subs:
            try:
                box.put_nowait((CLOSE_EVENT, {}))
            except queue.Full:  # pragma: no cover - 满队列直接清空再塞
                try:
                    self._drop_log(box)
                    box.put_nowait((CLOSE_EVENT, {}))
                except queue.Full:
                    pass


__all__ = [
    "CLOSE_EVENT",
    "DEFAULT_MAXSIZE",
    "EventBus",
    "KEEPALIVE_BYTES",
    "LAG_EVENT",
    "encode_chunk",
    "encode_sse",
]
