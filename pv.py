#!/usr/bin/env python
"""pwdvault 命令入口。

用法：
    python pv.py init
    python pv.py add -t 淘宝 -u zhangsan -p xxx
    python pv.py find 淘宝
    python pv.py doctor
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _fix_console() -> None:
    """Windows 控制台切到 UTF-8，否则中文与符号会因 GBK 编码报错。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:  # noqa: BLE001
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    _fix_console()
    from pwdvault.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
