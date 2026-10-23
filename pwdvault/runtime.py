"""运行期状态文件 `runtime.json` —— 长驻进程（`pv web`）的「我在哪」公告板。

为什么需要它
------------
P1 的代理模式要让 MCP 进程把工具调用转给已经在跑的 Web 进程（全局一个写者、
一份 DEK）。前提是 MCP 得先知道「Web 在不在、端口多少、用哪个 token」。

为什么放在文件里而不是 IPC
--------------------------
设计文档 §6.3 的裁决：自建 named pipe / socket 等于自己实现一个分布式系统，
连接、重连、对端消失都要各自处理。一个 0600 的小 JSON 文件已经够用，而且
进程被强杀时留下的脏文件可以用 pid 存活探测识别出来（见 `is_alive`）。

安全边界（必须诚实）
--------------------
- 文件里带一次性 token，所以**只允许当前用户读**：写入后 `os.chmod(0o600)`。
  Windows 的 chmod 只能改只读位，ACL 由目录继承决定，因此这一步是「尽力而为」，
  失败不抛 —— 但它绝不是安全保证，真正兜底的是「只监听 127.0.0.1」。
- token 每次 `pv web` 启动都重新生成，退出时文件被删（见 `clear_runtime`）。
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

RUNTIME_FILE_NAME = "runtime.json"
RUNTIME_VERSION = 1

# OpenProcess 的最小权限：只要查询信息，不要写入/终止
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259

DEFAULT_HOST = "127.0.0.1"


def runtime_path(home: str | Path) -> Path:
    """`runtime.json` 的固定位置：vault 同级的 home 目录。"""
    return Path(home) / RUNTIME_FILE_NAME


def write_runtime(
    home: str | Path,
    *,
    port: int,
    token: str,
    pid: int | None = None,
    host: str = DEFAULT_HOST,
    started: str | None = None,
) -> Path:
    """写入运行期状态，返回文件路径。

    采用 tmp + `os.replace` 的原子写：读端要么看到旧文件、要么看到新文件，
    绝不会读到半截 JSON（半截 JSON 会让 MCP 侧把「Web 在跑」误判成「不在」，
    症状是偶发地退回本地解锁，很难复现）。
    """
    from .models import now_iso  # 局部导入，避免 runtime → models 的顶层耦合面扩大

    target = runtime_path(home)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "version": RUNTIME_VERSION,
        "host": str(host or DEFAULT_HOST),
        "port": int(port),
        "token": str(token or ""),
        "pid": int(pid if pid is not None else os.getpid()),
        "started": str(started or now_iso()),
    }
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, target)

    # 0600：Windows 上 chmod 只影响只读位，失败也无所谓（见模块 docstring）
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def read_runtime(home: str | Path) -> dict | None:
    """读取并校验运行期状态；不存在或不可信一律返回 None。

    校验比「能 json.loads 就算数」严格：端口必须像端口、token 必须非空、
    pid 必须是正数。半可信的信息会让我们把一个随机端口当成 Web 端口去
    POST，那比直接放弃更糟。
    """
    target = runtime_path(home)
    try:
        raw = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    try:
        port = int(data.get("port"))
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None

    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        return None

    try:
        pid = int(data.get("pid"))
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None

    host = data.get("host")
    return {
        "version": int(data.get("version") or RUNTIME_VERSION),
        "host": host if isinstance(host, str) and host else DEFAULT_HOST,
        "port": port,
        "token": token,
        "pid": pid,
        "started": str(data.get("started") or ""),
    }


def clear_runtime(home: str | Path) -> bool:
    """删除运行期状态（`pv web` 正常退出时调用）。文件不存在返回 False。"""
    target = runtime_path(home)
    try:
        target.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def is_alive(pid: int | str | None) -> bool:
    """pid 对应的进程是否还活着。

    探测失败一律按「不存活」处理：脏 `runtime.json` 的代价是**多一次本地解锁**，
    而误判「存活」的代价是每次工具调用都去连一个不存在的端口、再超时失败，
    用户看到的是「工具时好时坏」。两害相权，宁可保守。
    """
    try:
        value = int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    if value == os.getpid():
        return True

    if sys.platform == "win32":
        return _is_alive_windows(value)

    try:
        os.kill(value, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # 进程存在但属于别人 —— 对我们来说仍然是「有人在跑」
        return True
    except OSError:
        return False


def _is_alive_windows(pid: int) -> bool:
    """Windows 版本：OpenProcess + GetExitCodeProcess。

    不用 `psutil`：本项目零新增依赖，而这两个 API 只要 ctypes 就够。
    """
    try:
        import ctypes.wintypes as wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            code = wintypes.DWORD(0)
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return int(code.value) == STILL_ACTIVE
            # 拿不到退出码但句柄有效：按存活处理（同上，保守方向相反但更少误伤）
            return True
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - 探测手段本身不可用 → 不存活
        return False


def machine_host() -> str:
    """本机主机名。`vault_copy` 用它告诉用户「值进了哪台机器的剪贴板」。"""
    try:
        return socket.gethostname()
    except OSError:  # pragma: no cover - 极少数无网络栈环境
        return "unknown-host"


def describe(home: str | Path) -> dict:
    """给 `pv doctor` / 状态工具用的只读摘要（不解密、不碰 vault）。"""
    info = read_runtime(home)
    if info is None:
        return {"present": False, "alive": False}
    return {
        "present": True,
        "alive": is_alive(info["pid"]),
        "host": info["host"],
        "port": info["port"],
        "pid": info["pid"],
        "started": info["started"],
    }


class ProxyBackend:
    """P1：把工具调用转发给运行中的 `pv web` 进程（单写者、单份 DEK）。

    本迭代（v1.1 P0）**只留桩**，不实现。调用点已经固定：

        mcp_server.unlock_chain() / mcp_tools.unlock_chain() 第一行探测
        `runtime.read_runtime(settings.home)` + `runtime.is_alive(info)`，
        命中且 `settings.mcp_proxy` 为真时尝试 `ProxyBackend().open(settings)`。

    将来怎么接（P1 唯一需要改的地方就是下面两个方法体）：

        POST http://{host}:{port}/api/mcp/{tool}
        Header: X-PV-Token: {token}         ← 来自 runtime.json
        Body:   {"arguments": {...}}
        返回:   与本地 handler 同构的 {ok: bool, payload: dict}

    `open()` 返回一个「远程 Vault 视图」，只需要支持 `records` / `find_by_id` /
    `revision` 三个被只读工具用到的成员；写工具（P1 之后）应改为在 Web 进程内
    执行，MCP 进程永远不持有 DEK。转发失败（连接被拒 / token 过期 / 5xx）时
    必须抛 `NotImplementedError` 之外的可识别异常，让 unlock_chain 落回本地解锁，
    绝不能静默把「远程不可达」当成「库是空的」。
    """

    def __init__(self, info: dict | None = None) -> None:
        self.info = dict(info or {})

    def open(self, settings: Any) -> Any:
        """接管解锁：向 Web 进程取一份只读视图。P1 实现。"""
        raise NotImplementedError("P1")

    def call(self, tool: str, arguments: dict) -> dict:
        """把一次工具调用转发给 Web 进程。P1 实现。"""
        raise NotImplementedError("P1")


__all__ = [
    "DEFAULT_HOST",
    "ProxyBackend",
    "RUNTIME_FILE_NAME",
    "RUNTIME_VERSION",
    "STILL_ACTIVE",
    "clear_runtime",
    "describe",
    "is_alive",
    "machine_host",
    "read_runtime",
    "runtime_path",
    "write_runtime",
]
