"""集中配置。

原则：所有可调参数集中在这个文件，来自「命令行 > 环境变量 > config.toml > 内置默认」
四级覆盖，绝不在业务代码里散落魔法数字。密钥永远不在这里出现。

v1.1 新增 web / inbox / staging / mcp / lock 五组参数，**一律用扁平属性暴露**
（`settings.web_port` 而不是 `settings.web.port`），避免两层访问在各处散开。
旧字段（vault_path / snapshot_keep / clipboard_seconds / auto_lock_seconds / kdf）
一个都没删，默认值也没变。
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

APP_NAME = "pwdvault"
FORMAT_NAME = "pwdvault"
FORMAT_VERSION = 1

# Argon2id 参数：64 MiB / 3 轮 / 4 并行，单次派生约 100~250ms。
# 这是给「文件会被放进网盘、攻击者可离线爆破」这个前提准备的。
DEFAULT_KDF = {
    "algo": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,  # KiB
    "parallelism": 4,
    "hash_len": 32,
    "salt_len": 16,
}

DEFAULT_SNAPSHOT_KEEP = 30
DEFAULT_CLIPBOARD_SECONDS = 30
DEFAULT_AUTO_LOCK_SECONDS = 300

# ---------------------------------------------------------------- v1.1 默认值
DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8765
DEFAULT_WEB_OPEN_BROWSER = True
DEFAULT_WEB_SESSION_MAX_AGE_HOURS = 24

DEFAULT_INBOX_ENABLED = True
DEFAULT_INBOX_INTERVAL_SECONDS = 2.0
DEFAULT_INBOX_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_INBOX_ARCHIVE_PROCESSED = True

DEFAULT_STAGING_LEASE_SECONDS = 180
DEFAULT_STAGING_LEASE_MAX_SECONDS = 600
DEFAULT_STAGING_TTL_DAYS = 30
DEFAULT_STAGING_MAX_ITEMS = 500
DEFAULT_STAGING_MAX_RAW_BYTES = 204800

DEFAULT_MCP_AUTO_LOCK_SECONDS = 900
DEFAULT_MCP_PROXY = True
DEFAULT_MCP_LOCK_TIMEOUT_SECONDS = 10.0

DEFAULT_LOCK_TIMEOUT_SECONDS = 3.0
DEFAULT_LOCK_POLL_SECONDS = 0.025


def default_home() -> Path:
    env = os.environ.get("PV_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / APP_NAME


@dataclass(frozen=True)
class Settings:
    vault_path: Path
    snapshot_keep: int = DEFAULT_SNAPSHOT_KEEP
    clipboard_seconds: int = DEFAULT_CLIPBOARD_SECONDS
    auto_lock_seconds: int = DEFAULT_AUTO_LOCK_SECONDS
    kdf: dict = field(default_factory=lambda: dict(DEFAULT_KDF))
    config_file: Path | None = None

    # --- [web]
    web_host: str = DEFAULT_WEB_HOST
    web_port: int = DEFAULT_WEB_PORT
    web_open_browser: bool = DEFAULT_WEB_OPEN_BROWSER
    web_session_max_age_hours: int = DEFAULT_WEB_SESSION_MAX_AGE_HOURS

    # --- [inbox]
    inbox_dir: str = ""
    inbox_enabled: bool = DEFAULT_INBOX_ENABLED
    inbox_interval_seconds: float = DEFAULT_INBOX_INTERVAL_SECONDS
    inbox_max_file_bytes: int = DEFAULT_INBOX_MAX_FILE_BYTES
    inbox_archive_processed: bool = DEFAULT_INBOX_ARCHIVE_PROCESSED

    # --- [staging]
    staging_lease_seconds: int = DEFAULT_STAGING_LEASE_SECONDS
    staging_lease_max_seconds: int = DEFAULT_STAGING_LEASE_MAX_SECONDS
    staging_ttl_days: int = DEFAULT_STAGING_TTL_DAYS
    staging_max_items: int = DEFAULT_STAGING_MAX_ITEMS
    staging_max_raw_bytes: int = DEFAULT_STAGING_MAX_RAW_BYTES
    # 下面两个是 O-4：`None` 表示「配置里没写」，此时用 `staging.py` 的模块常量
    # （EDITOR_LOCK_SECONDS = 120 / STAGING_LOCK_TIMEOUT = 5.0，也就是产品默认值）。
    # 为什么用 None 而不是直接写 120 / 5.0：`None` 才能区分「用户没配」与「配了」，
    # 从而保留「运行时改模块常量」这条路（QA 用它把编辑锁压缩到 1~2 秒验真实时间路径），
    # 同时让 config.toml 里的 `editor_lock_seconds` 真正生效。
    staging_editor_lock_seconds: float | None = None
    staging_lock_timeout_seconds: float | None = None

    # --- [mcp]
    mcp_auto_lock_seconds: int = DEFAULT_MCP_AUTO_LOCK_SECONDS
    mcp_proxy: bool = DEFAULT_MCP_PROXY
    mcp_lock_timeout_seconds: float = DEFAULT_MCP_LOCK_TIMEOUT_SECONDS

    # --- [lock]
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS
    lock_poll_seconds: float = DEFAULT_LOCK_POLL_SECONDS

    # ------------------------------------------------------------ 派生路径
    @property
    def home(self) -> Path:
        return self.vault_path.parent

    @property
    def snapshot_dir(self) -> Path:
        return self.home / "snapshots"

    @property
    def inbox_path(self) -> Path:
        """inbox 目录：配置为空时落在 vault 同级的 inbox/。"""
        if self.inbox_dir:
            return Path(self.inbox_dir).expanduser().resolve()
        return self.home / "inbox"

    @property
    def processed_dir(self) -> Path:
        return self.inbox_path / "processed"

    @property
    def staging_dir(self) -> Path:
        return self.home / "staging"

    @property
    def tombstones_path(self) -> Path:
        return self.staging_dir / "tombstones.json"

    @property
    def staging_lock_path(self) -> Path:
        return self.staging_dir / ".staging.lock"

    @property
    def lock_path(self) -> Path:
        """vault 文件的写锁：与 data.enc 同名加 .lock 后缀。"""
        return self.vault_path.with_name(self.vault_path.name + ".lock")

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def runtime_path(self) -> Path:
        return self.home / "runtime.json"

    def with_vault(self, path: str | Path) -> "Settings":
        return replace(self, vault_path=Path(path).expanduser().resolve())


def _read_toml(path: Path) -> dict:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"config.toml 语法错误：{exc}") from exc


def _as_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "y")
    if value is None:
        return default
    return bool(value)


def _as_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_optional_float(value, *, minimum: float) -> float | None:
    """可缺省的数值配置：缺键 / 空串 / 解析不了 → None（代表「用代码里的默认值」）。"""
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return max(minimum, parsed)


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _pick(cfg: dict, key: str, fallback):
    """从 TOML 段里取值，缺键就返回 fallback。"""
    return cfg[key] if key in cfg else fallback


def load_settings(vault_override: str | None = None) -> Settings:
    """按优先级装载配置。命令行 > 环境变量 > config.toml > 内置默认。"""
    home = default_home()
    cfg_candidates = [home / "config.toml", Path.cwd() / "config.toml"]
    cfg_path = next((p for p in cfg_candidates if p.is_file()), None)
    cfg = _read_toml(cfg_path) if cfg_path else {}

    vault_cfg = cfg.get("vault", {})
    kdf_cfg = cfg.get("kdf", {})
    clip_cfg = cfg.get("clipboard", {})
    web_cfg = cfg.get("web", {})
    inbox_cfg = cfg.get("inbox", {})
    staging_cfg = cfg.get("staging", {})
    mcp_cfg = cfg.get("mcp", {})
    lock_cfg = cfg.get("lock", {})

    raw_vault = (
        vault_override
        or os.environ.get("PV_VAULT")
        or vault_cfg.get("path")
        or str(home / "data.enc")
    )

    kdf = dict(DEFAULT_KDF)
    for key in ("algo", "time_cost", "memory_cost", "parallelism"):
        if key in kdf_cfg:
            kdf[key] = kdf_cfg[key]

    keep = int(os.environ.get("PV_SNAPSHOT_KEEP", vault_cfg.get("snapshots", DEFAULT_SNAPSHOT_KEEP)))
    clip = int(clip_cfg.get("clear_after", DEFAULT_CLIPBOARD_SECONDS))

    return Settings(
        vault_path=Path(raw_vault).expanduser().resolve(),
        snapshot_keep=max(1, keep),
        clipboard_seconds=max(1, clip),
        kdf=kdf,
        config_file=cfg_path,
        web_host=str(_pick(web_cfg, "host", DEFAULT_WEB_HOST)),
        web_port=_as_int(_pick(web_cfg, "port", DEFAULT_WEB_PORT), DEFAULT_WEB_PORT),
        web_open_browser=_as_bool(_pick(web_cfg, "open_browser", DEFAULT_WEB_OPEN_BROWSER), True),
        web_session_max_age_hours=_as_int(
            _pick(web_cfg, "session_max_age_hours", DEFAULT_WEB_SESSION_MAX_AGE_HOURS),
            DEFAULT_WEB_SESSION_MAX_AGE_HOURS,
        ),
        inbox_dir=str(_pick(inbox_cfg, "dir", "") or ""),
        inbox_enabled=_as_bool(_pick(inbox_cfg, "enabled", DEFAULT_INBOX_ENABLED), True),
        inbox_interval_seconds=max(
            0.05,
            _as_float(_pick(inbox_cfg, "interval_seconds", DEFAULT_INBOX_INTERVAL_SECONDS), 2.0),
        ),
        inbox_max_file_bytes=max(
            1,
            _as_int(_pick(inbox_cfg, "max_file_bytes", DEFAULT_INBOX_MAX_FILE_BYTES), DEFAULT_INBOX_MAX_FILE_BYTES),
        ),
        inbox_archive_processed=_as_bool(
            _pick(inbox_cfg, "archive_processed", DEFAULT_INBOX_ARCHIVE_PROCESSED), True
        ),
        staging_lease_seconds=max(
            1,
            _as_int(_pick(staging_cfg, "lease_seconds", DEFAULT_STAGING_LEASE_SECONDS), DEFAULT_STAGING_LEASE_SECONDS),
        ),
        staging_lease_max_seconds=max(
            1,
            _as_int(
                _pick(staging_cfg, "lease_max_seconds", DEFAULT_STAGING_LEASE_MAX_SECONDS),
                DEFAULT_STAGING_LEASE_MAX_SECONDS,
            ),
        ),
        staging_ttl_days=max(1, _as_int(_pick(staging_cfg, "ttl_days", DEFAULT_STAGING_TTL_DAYS), 30)),
        staging_max_items=max(1, _as_int(_pick(staging_cfg, "max_items", DEFAULT_STAGING_MAX_ITEMS), 500)),
        staging_max_raw_bytes=max(
            1,
            _as_int(_pick(staging_cfg, "max_raw_bytes", DEFAULT_STAGING_MAX_RAW_BYTES), DEFAULT_STAGING_MAX_RAW_BYTES),
        ),
        staging_editor_lock_seconds=_as_optional_float(
            _pick(staging_cfg, "editor_lock_seconds", None), minimum=0.2
        ),
        staging_lock_timeout_seconds=_as_optional_float(
            _pick(staging_cfg, "lock_timeout_seconds", None), minimum=0.1
        ),
        mcp_auto_lock_seconds=max(
            1,
            _as_int(_pick(mcp_cfg, "auto_lock_seconds", DEFAULT_MCP_AUTO_LOCK_SECONDS), DEFAULT_MCP_AUTO_LOCK_SECONDS),
        ),
        mcp_proxy=_as_bool(_pick(mcp_cfg, "proxy", DEFAULT_MCP_PROXY), True),
        mcp_lock_timeout_seconds=max(
            0.1,
            _as_float(
                _pick(mcp_cfg, "lock_timeout_seconds", DEFAULT_MCP_LOCK_TIMEOUT_SECONDS),
                DEFAULT_MCP_LOCK_TIMEOUT_SECONDS,
            ),
        ),
        lock_timeout_seconds=max(
            0.1,
            _as_float(
                _pick(lock_cfg, "timeout_seconds", DEFAULT_LOCK_TIMEOUT_SECONDS), DEFAULT_LOCK_TIMEOUT_SECONDS
            ),
        ),
        lock_poll_seconds=max(
            0.001,
            _as_float(_pick(lock_cfg, "poll_seconds", DEFAULT_LOCK_POLL_SECONDS), DEFAULT_LOCK_POLL_SECONDS),
        ),
    )


# ------------------------------------------------------------------ 日志约定
def log_event(event: str, *, scope: str = "pv", level: str = "INFO", **fields) -> None:
    """单行 stderr 日志。

    格式（DESIGN §9.2）：``[pv] 2026-01-05T04:31:12Z INFO event=commit rev=41->42 added=2 ms=34``
    允许的字段只有 event / code / id / field / count / revision / ms / purpose / state，
    **绝不允许出现任何字段值**。
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [f"[{scope}]", stamp, level, f"event={event}"]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    try:
        print(" ".join(parts), file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 - 日志失败绝不影响主流程
        pass
