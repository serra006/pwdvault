"""Web 层包入口（L4 会话/事件 + L5 传输）。

对外只暴露一件真正重要的事：`serve(settings, *, port=None, open_browser=True,
exit_when_stdin_closes=False)`。`cli.py::cmd_web` 与 `python -m pwdvault.web`
都只调它（前者是唯一受支持的入口，见 `cmd_web` 的 docstring）。
"""

from __future__ import annotations

from .events import EventBus, encode_chunk, encode_sse
from .server import WebServer, serve
from .session import AppState

__all__ = [
    "AppState",
    "EventBus",
    "WebServer",
    "encode_chunk",
    "encode_sse",
    "serve",
]
