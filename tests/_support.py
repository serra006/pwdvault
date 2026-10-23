"""测试夹具：临时库、子进程执行器、哨兵常量。

**故意不叫 `test_*.py`**，所以 `unittest discover` 不会把它当测试收集。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PV_ENTRY = PROJECT_ROOT / "pv.py"
PYTHON = sys.executable

# 测试里一律用极快的 KDF 参数：加密强度由 test_crypto/test_vault 单独守，
# 这里要的是「一次 save 别花 200ms」，否则并发用例会慢到没法跑。
FAST_KDF = {"algo": "argon2id", "time_cost": 1, "memory_cost": 8192, "parallelism": 1}
PASSWORD = "测试 专用 的 主 密码 词组"

# 哨兵：正常数据里绝不会出现，命中即代表明文漏进了对外结构
SENTINEL_PW = "ZZ-PvProbe-Pw-9f2c1d-DO-NOT-LEAK"
SENTINEL_CUSTOM = "ZZ-PvProbe-Custom-4a7e-DO-NOT-LEAK"
SENTINEL_NOTE = "ZZ-PvProbe-Note-1b3f-VISIBLE-OK"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pwdvault.config import Settings  # noqa: E402
from pwdvault.vault import Vault  # noqa: E402


class Fixture(NamedTuple):
    settings: Settings
    vault: Vault
    password: str
    recovery: str


def make_home(testcase) -> Path:
    """建一个临时 home 目录，并在用例结束时清理。"""
    home = Path(tempfile.mkdtemp(prefix="pvtest-"))
    testcase.addCleanup(shutil.rmtree, home, ignore_errors=True)
    return home


def write_config(home: Path, vault_path: Path, *, extra: str = "") -> Path:
    """写一份 config.toml，让子进程 `pv` 用同一个库与同一套快速 KDF。"""
    home.mkdir(parents=True, exist_ok=True)
    text = (
        "[vault]\n"
        f'path = "{Path(vault_path).as_posix()}"\n'
        "snapshots = 3\n"
        "\n"
        "[kdf]\n"
        'algo = "argon2id"\n'
        "time_cost = 1\n"
        "memory_cost = 8192\n"
        "parallelism = 1\n"
        "\n"
        "[lock]\n"
        # 50 个进程同时抢锁时，3 秒是给「人手操作」准备的，不是给压力测试的。
        # 真实 MCP 侧也是 10 秒（DESIGN §4.3）。
        "timeout_seconds = 20\n"
        "poll_seconds = 0.01\n"
    )
    if extra:
        text = text + "\n" + extra.strip() + "\n"
    path = home / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def make_vault(
    home: Path | str | None = None,
    *,
    password: str = PASSWORD,
    snapshot_keep: int = 0,
    kdf: dict | None = None,
    label: str = "",
) -> Fixture:
    """建一个全新的临时 vault，返回 (settings, vault, password, recovery)。"""
    base = Path(home) if home is not None else Path(tempfile.mkdtemp(prefix="pvtest-"))
    settings = Settings(
        vault_path=base / "data.enc",
        snapshot_keep=snapshot_keep,
        kdf=dict(kdf or FAST_KDF),
    )
    vault, recovery = Vault.create(settings, password, label=label)
    return Fixture(settings, vault, password, recovery)


def run_py(
    args: list[str],
    *,
    home: Path | str,
    env: dict | None = None,
    timeout: float = 180.0,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    """用**当前解释器**跑一次 `pv.py`，环境隔离（PV_HOME 指向临时目录）。"""
    environ = os.environ.copy()
    environ["PV_HOME"] = str(home)
    environ.pop("PV_VAULT", None)
    environ.pop("PV_RECOVERY_CODE", None)
    environ.pop("PV_SNAPSHOT_KEEP", None)
    if env:
        for key, value in env.items():
            if value is None:
                environ.pop(key, None)
            else:
                environ[key] = str(value)
    return subprocess.run(
        [PYTHON, str(PV_ENTRY), *args],
        cwd=str(PROJECT_ROOT),
        env=environ,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def popen_py(args: list[str], *, home: Path | str, env: dict | None = None) -> subprocess.Popen:
    """起一个不等待的 `pv.py` 子进程（并发测试用）。"""
    environ = os.environ.copy()
    environ["PV_HOME"] = str(home)
    environ.pop("PV_VAULT", None)
    environ.pop("PV_RECOVERY_CODE", None)
    if env:
        for key, value in env.items():
            if value is None:
                environ.pop(key, None)
            else:
                environ[key] = str(value)
    return subprocess.Popen(
        [PYTHON, str(PV_ENTRY), *args],
        cwd=str(PROJECT_ROOT),
        env=environ,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def load_json(text: str) -> dict:
    return json.loads(text)


__all__ = [
    "FAST_KDF",
    "Fixture",
    "PASSWORD",
    "PROJECT_ROOT",
    "PV_ENTRY",
    "PYTHON",
    "SENTINEL_CUSTOM",
    "SENTINEL_NOTE",
    "SENTINEL_PW",
    "load_json",
    "make_home",
    "make_vault",
    "popen_py",
    "run_py",
    "write_config",
]
