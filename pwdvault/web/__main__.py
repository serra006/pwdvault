"""`python -m pwdvault.web` —— 不依赖 cli.py 的直启入口（T12 的 `pv web` 与之等价）。"""

from __future__ import annotations

from .server import main

if __name__ == "__main__":  # pragma: no cover - 只在 `python -m` 时执行
    raise SystemExit(main())
