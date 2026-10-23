"""被 `test_locks.py` 以**子进程**启动的锁竞争者。

用法：`python _locker.py <lockfile> <tag> <hold_ms> <logfile>`

拿着锁时向日志追加 `start <tag>`，释放前追加 `end <tag>`。
父进程据此断言「没有任何 start 落在别人未闭合的 start 之内」——
这条断言在删掉 `msvcrt.locking` / `fcntl.flock` 之后必定失败，
所以它是一个真测试，而不是「同进程 RLock 自己跟自己玩」的假绿。
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault.locks import LockManager  # noqa: E402


def append(path: str, line: str) -> None:
    """单次 os.write 追加，保证多进程下的行不交错。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: _locker.py <lockfile> <tag> <hold_ms> <logfile>", file=sys.stderr)
        return 2
    lock_path = Path(argv[0])
    tag = argv[1]
    hold_ms = int(argv[2])
    log_path = argv[3]

    manager = LockManager(lock_path, default_timeout=30.0, poll_seconds=0.005)
    with manager.hold(purpose="locker"):
        append(log_path, f"start {tag}")
        time.sleep(hold_ms / 1000.0)
        append(log_path, f"end {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
