"""Windows DPAPI 绑定 —— 实现「本机免密」。

原理：把 DEK 交给 Windows 的 CryptProtectData，由操作系统用「当前用户 + 当前机器」
的凭据加密。之后同一个用户在这台机器上跑程序，可以不经主密码直接取回 DEK。

必须清楚的代价
--------------
DPAPI 绑定的是「用户身份」，不是「你本人」。因此在这台机器上、以你的账户运行的
任何程序（包括恶意软件）都能解密这份包裹。它防的是「文件被拷到别的机器/被别人
拿走」，防不住「本机已中招」。

所以主密码包裹永远保留，DPAPI 只是便利层，不是替代品。
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes

from .errors import DpapiUnavailable

ENTROPY = b"pwdvault/v1/dek"
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def is_supported() -> bool:
    return sys.platform == "win32"


def _require() -> tuple:
    if not is_supported():
        raise DpapiUnavailable("仅 Windows 支持 DPAPI")
    try:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError as exc:  # pragma: no cover - 仅异常环境
        raise DpapiUnavailable(str(exc)) from exc

    blob_ptr = ctypes.POINTER(_DataBlob)
    crypt32.CryptProtectData.argtypes = [
        blob_ptr,
        wintypes.LPCWSTR,
        blob_ptr,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        blob_ptr,
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        blob_ptr,
        ctypes.POINTER(wintypes.LPWSTR),
        blob_ptr,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        blob_ptr,
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _as_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _take(blob: _DataBlob, kernel32) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    crypt32, kernel32 = _require()
    in_blob, _keep1 = _as_blob(data)
    ent_blob, _keep2 = _as_blob(ENTROPY)
    out_blob = _DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "pwdvault",
        ctypes.byref(ent_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise DpapiUnavailable(f"CryptProtectData 失败（错误码 {ctypes.get_last_error()}）")
    return _take(out_blob, kernel32)


def unprotect(blob: bytes) -> bytes:
    crypt32, kernel32 = _require()
    in_blob, _keep1 = _as_blob(blob)
    ent_blob, _keep2 = _as_blob(ENTROPY)
    out_blob = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise DpapiUnavailable(
            "本机免密凭据无效（可能换了机器、重装了系统或改了用户）"
        )
    return _take(out_blob, kernel32)


def machine_fingerprint() -> str:
    """仅用于 doctor 展示，帮助用户理解本机绑定的范围。"""
    parts = [os.environ.get("COMPUTERNAME", "?"), os.environ.get("USERNAME", "?")]
    return " / ".join(parts)
