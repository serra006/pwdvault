"""剪贴板读写（仅 Windows，直接用 user32，不引入额外依赖）。

复制密码后定时清空是必要的：剪贴板内容对同用户的所有进程可见，
清空只能缩短暴露窗口，不能根治 —— 所以默认 30 秒，并且只在
「当前内容仍是刚才那份」时才清，避免误删用户后来复制的东西。

关键实现细节：CLI 主进程复制完就退出了，daemon 线程活不到超时。
所以清空动作交给一个**分离的子进程**去做，并且只把密码的 SHA-256
摘要传给它，避免明文出现在进程命令行里（命令行对同用户进程可见）。

两种清空方式（`copy_with_autoclear(..., spawn=)` 选一种）
--------------------------------------------------------
* `spawn=True`（CLI 用）：起分离子进程，适合「复制完就退出」的短命进程。
  它依赖 `sys.argv[0]` 认 `_clipwatch` 子命令，所以只有经 `pv` 入口启动才有效。
* `spawn=False`（MCP 用）：进程内 `threading.Timer`（daemon），适合长驻进程。
  v1.0 的缺陷是：MCP 下用子进程方式时 `python -m pwdvault.mcp_server` 的 argv[0]
  不认 `_clipwatch`，看门狗立刻退出，而回执仍写 `auto_clear_in=30` —— 也就是
  **回执说谎**。现在 MCP 一律走进程内定时器，且回执只报「真的装上了」的秒数。
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import sys
import threading
from typing import Callable

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


def _api():
    if sys.platform != "win32":
        raise RuntimeError("剪贴板功能目前只支持 Windows")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_bool
    user32.EmptyClipboard.restype = ctypes.c_bool
    user32.CloseClipboard.restype = ctypes.c_bool
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p

    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    return user32, kernel32


def copy_text(text: str) -> None:
    user32, kernel32 = _api()
    data = text.encode("utf-16-le") + b"\x00\x00"

    if not user32.OpenClipboard(None):
        raise RuntimeError("打开剪贴板失败，可能被其他程序占用")
    try:
        user32.EmptyClipboard()
        handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not handle:
            raise RuntimeError("剪贴板内存分配失败")
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            kernel32.GlobalFree(handle)
            raise RuntimeError("剪贴板内存锁定失败")
        try:
            ctypes.memmove(pointer, data, len(data))
        finally:
            kernel32.GlobalUnlock(handle)
        user32.SetClipboardData(CF_UNICODETEXT, handle)
    finally:
        user32.CloseClipboard()


def read_text() -> str:
    user32, kernel32 = _api()
    if not user32.OpenClipboard(None):
        return ""
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return ""
        try:
            return ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clear_if_matches(digest: str) -> bool:
    try:
        current = read_text()
    except Exception:  # noqa: BLE001
        return False
    if current and digest_of(current) == digest:
        try:
            copy_text("")
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


def spawn_clear_watcher(digest: str, seconds: int) -> bool:
    """起一个分离进程，超时后按摘要比对并清空剪贴板。"""
    if sys.platform != "win32":
        return False
    entry = os.path.abspath(sys.argv[0])
    if not entry.lower().endswith(".py"):
        return False
    flags = 0x00000008 | 0x08000000  # DETACHED_PROCESS | CREATE_NO_WINDOW
    try:
        subprocess.Popen(
            [sys.executable, entry, "_clipwatch", digest, str(seconds)],
            creationflags=flags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            cwd=os.path.dirname(entry) or None,
        )
        return True
    except OSError:
        return False


def process_clear_watcher(
    digest: str,
    seconds: float,
    *,
    on_fired: Callable[[], None] | None = None,
) -> bool:
    """进程内定时清空（`threading.Timer`，daemon）。

    给长驻进程（MCP）用：进程活着，线程就活着，不依赖 argv[0]、不起子进程。
    到点后仍然只按**摘要**比对 —— 用户在 30 秒内又复制了别的东西，就绝不清空，
    否则等于把用户刚复制的内容删掉。

    `on_fired` 只是给测试用的回调（`threading.Event().set`），生产路径不需要。
    返回是否真的装上了定时器（装不上就如实返回 False，绝不假报成功）。
    """
    delay = float(seconds)

    def _tick() -> None:
        try:
            clear_if_matches(digest)
        except Exception:  # noqa: BLE001 - 定时器里绝不能抛，抛了会污染 stderr 之外也无处可去
            pass
        finally:
            if on_fired is not None:
                try:
                    on_fired()
                except Exception:  # noqa: BLE001 - 测试回调出错不影响主流程
                    pass

    try:
        timer = threading.Timer(delay, _tick)
        timer.daemon = True  # 不阻塞解释器退出
        timer.start()
    except (RuntimeError, ValueError):
        # 线程资源耗尽 / 非法延时：不装定时器，由调用方如实告诉用户
        return False
    return True


def copy_with_autoclear(
    text: str,
    seconds: float,
    *,
    spawn: bool = True,
    on_fired: Callable[[], None] | None = None,
) -> dict:
    """复制 `text` 并安排自动清空，返回**如实的**执行结果。

    Args:
        text: 要写进剪贴板的明文。
        seconds: 多少秒后清空（测试可以给 0.05）。
        spawn: True 用分离子进程（CLI），False 用进程内 daemon 定时器（MCP）。
        on_fired: 仅供测试观察「定时器真的跑完了」。

    Returns:
        ``{"auto_clear": bool, "seconds": float, "mode": "subprocess"|"process"|"none",
        "spawn": bool}``。`auto_clear` 为 False 表示**定时器没装上**，调用方必须
        如实转达，不许再写一个假的 30 秒。

    明文只在本函数里作为一个局部变量存在：取完摘要立刻 `del`，不进入返回结构，
    也不进入定时器的闭包（闭包里只有摘要）。
    """
    value = text if isinstance(text, str) else str(text)
    digest = digest_of(value)
    copy_text(value)
    del value

    delay = max(0.0, float(seconds))
    if spawn:
        installed = spawn_clear_watcher(digest, int(delay))
        mode = "subprocess"
    else:
        installed = process_clear_watcher(digest, delay, on_fired=on_fired)
        mode = "process"

    return {
        "auto_clear": bool(installed),
        "seconds": delay if installed else 0.0,
        "mode": mode if installed else "none",
        "spawn": bool(spawn),
    }

