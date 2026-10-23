"""暂存区：批次 / 条目模型、8 状态机、加密持久化、条目校验、commit / rollback。

三个设计要点：

1. **草稿必须加密落盘**。TXT 里的密码是明文，草稿如果明文写 `staging/xxx.json`，
   等于在库旁边放一份明文。这里复用**已被 KEK 解包的 DEK**（不新造密钥、不派生），
   AAD 绑定 `vault_id + "staging/<batch_id>"`，所以：
     - 把 staging 密文挪到 `data.enc` 的 payload 位置打不开（AAD 是 `payload`）；
     - 把 sb_A 的 sealed 挪到 sb_B 打不开（AAD 里含 batch_id）；
     - 跨 vault 搬运打不开（AAD 里含 vault_id）。
   外层 JSON 只放**标识 / 状态 / 计数 / 时间**，没有任何字段值。

2. **每次读-改-写都在 `staging/.staging.lock` 内，且锁内必须重读文件**，
   绝不相信内存缓存（否则两个人同时点提交就会互相覆盖）。

3. **条目校验是确定性规则，不交给模型判断**（PRD §6.3 的 8 类）。警告标记来自
   `importers` 的旁路采集与 `service.validate_records`，**绝不写进 record.fields**。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Literal, MutableMapping, Sequence

from . import crypto, service
from .config import Settings, log_event
from .errors import CorruptVault, Locked, StagingBusy, StagingNotFound, VaultError
from .locks import LockManager, Operation, VaultStore
from .models import Record, Warning, is_sensitive_key, new_id
from .redact import redact_record
from .vault import atomic_write, read_header

STAGING_FORMAT = "pwdvault-staging"
STAGING_VERSION = 1
TOMBSTONE_FORMAT = "pwdvault-tombstones"
STAGING_SUFFIX = ".enc"
BATCH_PREFIX = "sb_"
ITEM_PREFIX = "it_"

EDITOR_LOCK_SECONDS = 120
MAX_NOTES_CHARS = 200
MAX_TOMBSTONES = 5000
STAGING_LOCK_TIMEOUT = 5.0

# `EDITOR_LOCK_SECONDS` / `STAGING_LOCK_TIMEOUT` 是**兜底默认值**：配置里给了
# `[staging] editor_lock_seconds` / `lock_timeout_seconds` 就以配置为准，
# 没给（`Settings` 里是 None）才用常量。保留常量的原因：它同时是「运行时改常量」
# 这个测试/运维手段的入口（QA 用它把编辑锁压缩到 1~2 秒验真实时间路径）。
NOTES_REDACTED_TEXT = "（已隐去，疑似含敏感内容）"

# Agent 的一句话总结（`outer["notes"]`）是**明文**落盘的，所以落盘前必须扫一遍（O-2）。
# 两道检查缺一不可：Agent 最常泄漏的不是随机串，而是它刚从源文件里读到的**那一条
# 密码 / 密钥** —— 形状检查抓不到（那个值可能就是个普通单词），只有拿本次批次的
# 字段值当探针才抓得到；反过来，用户直接粘进来的 `otpauth://` 又不在草稿字段里，
# 只能靠形状。命中任意一条就**整条**替换，不做部分遮掩（部分遮掩会留下语义暗示）。
MIN_SCRUB_PROBE_CHARS = 4
_SECRET_SHAPES = (
    re.compile(r"otpauth://", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[A-Z2-7]{16,}={0,6}\b"),
    re.compile(
        r"(?:密码|口令|passw(?:or)?d|pwd|secret|token|api[_-]?key)\s*(?:是|为|:|：|=)\s*\S{2,}",
        re.IGNORECASE,
    ),
)

BatchStatus = Literal[
    "detected",
    "drafted",
    "failed",
    "refining",
    "review",
    "reviewing",
    "committed",
    "rolled_back",
    "discarded",
]

Origin = Literal["local", "agent"]
Resolution = Literal["skip", "overwrite", "append"]

# UI 文案（PRD §6.1）。状态机报错只引用这里的文案，不含任何记录内容。
STATUS_LABEL: dict[str, str] = {
    "detected": "已发现",
    "drafted": "待确认 · 本地解析",
    "failed": "无法识别",
    "refining": "整理中 · Agent",
    "review": "待确认 · Agent 整理",
    "reviewing": "确认中",
    "committed": "已入库",
    "rolled_back": "已撤销",
    "discarded": "已丢弃",
}

FINISHED_STATUSES = frozenset({"committed", "rolled_back", "discarded"})

#: 判重时「**不算**已存在」的状态。目前只有 `discarded`。
#:
#: 为什么只有它：`ALLOWED_TRANSITIONS` 里 `discarded` **没有任何出边** —— 它是唯一
#: 不可复活的终态。用户丢掉一批之后，同一份内容若不能重新开一批，就等于这个文件
#: 对这个库永久隐身（改内容会换 sha256 从而绕过，但「我就是想再处理一遍这份」走不通）。
#:
#: 为什么 `committed` / `rolled_back` 不在里面：那两种批次本身还留在待整理列表里，
#: 用户可以就地再提交一次（重建才是灾难 —— 同一份内容会在列表里出现两份）。
#: 重启之后的去重也依赖它们继续算「已存在」。
#:
#: 为什么 `failed` 不在里面：failed 批次是给用户的出口（「手动新建」），判重命中它
#: 是有意的行为；放进来会让用户失去那个出口，还会丢掉 failed 可以 → refin/t/review
#: 的复活路径。
DEDUP_EXEMPT_STATUSES = frozenset({"discarded"})

# 唯一状态变更依据。非法转换一律 `StagingBusy`。
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "detected": {"drafted", "failed", "refining", "discarded"},
    "drafted": {"refining", "review", "discarded"},
    "failed": {"refining", "review", "discarded"},
    "refining": {"review", "drafted", "failed", "discarded"},
    "review": {"reviewing", "committed", "discarded"},
    "reviewing": {"review", "committed", "discarded"},
    "committed": {"rolled_back"},
    "rolled_back": {"discarded"},
    "discarded": set(),
}


def can_transition(current: str, target: str) -> bool:
    """状态机查询（纯函数，方便表驱动测试）。"""
    return target in ALLOWED_TRANSITIONS.get(current, set())


def label_of(status: str) -> str:
    return STATUS_LABEL.get(status, status)


def _iso(moment: datetime) -> str:
    """UTC ISO 时间戳，**毫秒精度**。

    为什么不是整秒（Q-04）：`since`/`expires` 都靠字符串回读后与 `now()` 相减。
    截到整秒时 `now - since` 最多被放大约 1 秒 —— 120s 编辑锁、180s 租约无所谓，
    但「3 秒租约」「1 秒编辑锁」会变成 0~3 秒随机失效，任何想在测试里用短超时的
    场景都得打补丁。毫秒精度下误差 < 1ms，短周期也可靠。
    老的整秒字符串 `datetime.fromisoformat` 照样能解析，不需要迁移数据。
    """
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _parse_iso(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(str(text))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


# ---------------------------------------------------------------- 数据模型
@dataclass
class StagingItem:
    """一条待确认草稿。`draft` 含明文，只存在于加密区与内存。"""

    item_id: str
    draft: Record
    origin: Origin = "local"
    accepted: bool = True
    edited: bool = False
    warnings: list[Warning] = field(default_factory=list)
    conflict: dict | None = None
    before: dict | None = None

    @property
    def has_error(self) -> bool:
        return any(warning.level == "error" for warning in self.warnings)

    def to_public(self, *, reveal: frozenset[str] = frozenset()) -> dict:
        """对外形态：记录走 `redact_record`，密码默认掩码。"""
        return {
            "item_id": self.item_id,
            "origin": self.origin,
            "accepted": self.accepted,
            "edited": self.edited,
            "has_error": self.has_error,
            "warnings": [warning.to_dict() for warning in self.warnings],
            "conflict": dict(self.conflict) if self.conflict else None,
            "has_before": self.before is not None,
            "record": redact_record(self.draft, profile="web", reveal_fields=reveal),
        }


@dataclass
class StagingBatch:
    batch_id: str
    status: str = "detected"
    source: dict = field(default_factory=dict)
    items: list[StagingItem] = field(default_factory=list)
    origin: Origin = "local"
    created: str = ""
    updated: str = ""
    lease: dict | None = None
    editor: dict | None = None
    commit: dict | None = None
    notes: str = ""
    item_count: int = 0
    # 本次调用是否「命中同 sha256 的既有批次」（Q-05 的幂等返回）。
    # 只用于调用方区分「新建了」与「本来就有」，不落盘、不进 to_public。
    deduped: bool = False

    @property
    def sha256(self) -> str:
        return str(self.source.get("sha256") or "")

    @property
    def file_name(self) -> str:
        return str(self.source.get("file_name") or "")

    def accepted_items(self) -> list[StagingItem]:
        return [item for item in self.items if item.accepted and not item.has_error]

    def to_public(
        self,
        *,
        include_items: bool = True,
        reveal: frozenset[str] = frozenset(),
    ) -> dict:
        created = _parse_iso(self.created)
        age = 0
        if created is not None:
            age = max(0, int((datetime.now(timezone.utc) - created).total_seconds()))
        payload: dict = {
            "batch_id": self.batch_id,
            "status": self.status,
            "status_label": label_of(self.status),
            "origin": self.origin,
            "created": self.created,
            "updated": self.updated,
            "item_count": self.item_count or len(self.items),
            "notes": self.notes,
            "age_seconds": age,
            "source": dict(self.source),
            "lease": dict(self.lease) if self.lease else None,
            "editor": dict(self.editor) if self.editor else None,
            "commit": dict(self.commit) if self.commit else None,
        }
        if include_items:
            payload["items"] = [item.to_public(reveal=reveal) for item in self.items]
        return payload


# ---------------------------------------------------------------- 序列化助手
def _draft_from_dict(raw: dict) -> Record:
    """`Record.to_dict()` 的严格逆运算（不抛异常，草稿可能标题为空）。"""
    return Record(
        title=str(raw.get("title") or ""),
        username=str(raw.get("username") or ""),
        password=str(raw.get("password") or ""),
        url=str(raw.get("url") or ""),
        notes=str(raw.get("notes") or ""),
        totp=str(raw.get("totp") or ""),
        tags=list(raw.get("tags") or []),
        fields={str(k): str(v) for k, v in (raw.get("fields") or {}).items()},
        id=str(raw.get("id") or ""),
        created=str(raw.get("created") or ""),
        updated=str(raw.get("updated") or ""),
        pw_changed=str(raw.get("pw_changed") or ""),
    )


def _item_to_dict(item: StagingItem) -> dict:
    return {
        "item_id": item.item_id,
        "origin": item.origin,
        "accepted": item.accepted,
        "edited": item.edited,
        "draft": item.draft.to_dict(),
        "warnings": [warning.to_dict() for warning in item.warnings],
        "conflict": item.conflict,
        "before": item.before,
    }


def _item_from_dict(raw: dict) -> StagingItem:
    warnings = [
        Warning(
            code=str(entry.get("code") or ""),
            level=str(entry.get("level") or "warn"),  # type: ignore[arg-type]
            message=str(entry.get("message") or ""),
            field=entry.get("field"),
        )
        for entry in (raw.get("warnings") or [])
        if isinstance(entry, dict)
    ]
    return StagingItem(
        item_id=str(raw.get("item_id") or (ITEM_PREFIX + secrets.token_hex(4))),
        draft=_draft_from_dict(raw.get("draft") or {}),
        origin=str(raw.get("origin") or "local"),  # type: ignore[arg-type]
        accepted=bool(raw.get("accepted", True)),
        edited=bool(raw.get("edited", False)),
        warnings=warnings,
        conflict=raw.get("conflict"),
        before=raw.get("before"),
    )


def _full_changes(record: Record) -> dict:
    """把一条记录表达成「整条覆盖」的 changes（`apply_changes` 能吃）。"""
    return {
        "title": record.title,
        "username": record.username,
        "password": record.password,
        "url": record.url,
        "notes": record.notes,
        "totp": record.totp,
        "tags": ",".join(record.tags),
        "fields": dict(record.fields),
    }


def _changes_from_snapshot(raw: dict) -> dict:
    return {
        "title": str(raw.get("title") or ""),
        "username": str(raw.get("username") or ""),
        "password": str(raw.get("password") or ""),
        "url": str(raw.get("url") or ""),
        "notes": str(raw.get("notes") or ""),
        "totp": str(raw.get("totp") or ""),
        "tags": ",".join(raw.get("tags") or []),
        "fields": dict(raw.get("fields") or {}),
    }


class StagingStore:
    """进程内单例（按 vault home 缓存）+ 跨进程 `.staging.lock` 串行化。"""

    _REGISTRY: dict[str, "StagingStore"] = {}
    _REGISTRY_GUARD = threading.Lock()

    @classmethod
    def shared(
        cls,
        settings: Settings,
        dek_provider: Callable[[], bytes | None],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> "StagingStore":
        """按 vault 目录缓存的进程内单例（web / mcp 各进程各一份）。"""
        key = str(settings.staging_dir.resolve())
        with cls._REGISTRY_GUARD:
            existing = cls._REGISTRY.get(key)
            if existing is None:
                existing = cls(settings, dek_provider, clock=clock)
                cls._REGISTRY[key] = existing
            return existing

    def __init__(
        self,
        settings: Settings,
        dek_provider: Callable[[], bytes | None],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._dek_provider = dek_provider
        self._clock = clock
        self._dir = settings.staging_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = LockManager(
            settings.staging_lock_path,
            default_timeout=self._lock_timeout(),
            poll_seconds=getattr(settings, "lock_poll_seconds", 0.025),
        )
        self._cached_vault_id: str = ""
        # 文件名 → (源文件 sha256, batch_id) 的增量索引（Q-05 的锁内二次确认要用）。
        # `batches_by_hash()` 每次都要把**所有** `sb_*.enc` 外层 JSON 读一遍解析一遍，
        # 在「一次扫进 500 个文件」的场景里就是 500×500 次读盘（实测多花 10 秒）。
        # 批次文件一旦建成就不会再改 `source.sha256`，所以按文件名缓存是安全的：
        # 只需为「缓存里没有的新文件」补一次读，其余都是零成本的 dict 查表。
        self._outer_index: dict[str, tuple[str, str]] = {}
        self._cleanup_tombstones()

    # ------------------------------------------------------------- 基础设施
    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def lock(self) -> LockManager:
        return self._lock

    def now(self) -> datetime:
        if self._clock is not None:
            return self._clock()
        return datetime.now(timezone.utc)

    def _lock_timeout(self) -> float:
        """`.staging.lock` 的等待上限：配置优先，没配就用模块常量（O-4）。"""
        configured = getattr(self._settings, "staging_lock_timeout_seconds", None)
        if configured:
            try:
                return float(configured)
            except (TypeError, ValueError):
                return float(STAGING_LOCK_TIMEOUT)
        return float(STAGING_LOCK_TIMEOUT)

    def _editor_lock_seconds(self) -> float:
        """编辑锁有效期：配置优先，没配就用模块常量（O-4）。"""
        configured = getattr(self._settings, "staging_editor_lock_seconds", None)
        if configured:
            try:
                return float(configured)
            except (TypeError, ValueError):
                return float(EDITOR_LOCK_SECONDS)
        return float(EDITOR_LOCK_SECONDS)

    def has_dek(self) -> bool:
        """未解锁时只能读墓碑/扫目录，不能建批次、不能解草稿。"""
        try:
            return self._dek_provider() is not None
        except Exception:  # noqa: BLE001 - provider 出问题按「没有 DEK」处理
            return False

    def _require_dek(self) -> bytes:
        dek = None
        if self._dek_provider is not None:
            try:
                dek = self._dek_provider()
            except Exception:  # noqa: BLE001
                dek = None
        if not dek:
            raise Locked(
                "密码库现在是锁着的，待整理的草稿打不开。",
                hint="先打开界面解锁，或开启本机免密。",
            )
        return dek

    def _vault_id(self) -> str:
        if self._cached_vault_id:
            return self._cached_vault_id
        try:
            header = read_header(self._settings.vault_path)
            vault_id = str(header.get("vault_id") or "")
        except VaultError:
            vault_id = ""
        if not vault_id:
            raise Locked(
                "密码库现在是锁着的，暂时读不了待整理草稿。",
                hint="先打开界面解锁，或开启本机免密。",
            )
        self._cached_vault_id = vault_id
        return vault_id

    def _aad(self, batch_id: str, vault_id: str) -> bytes:
        return crypto.make_aad(vault_id, f"staging/{batch_id}")

    def _batch_path(self, batch_id: str) -> Path:
        safe = "".join(ch for ch in str(batch_id) if ch.isalnum() or ch in "_-")
        return self._dir / f"{safe}{STAGING_SUFFIX}"

    def _raw_paths(self) -> list[Path]:
        return sorted(self._dir.glob(f"{BATCH_PREFIX}*{STAGING_SUFFIX}"))

    def _read_outer_file(self, path: Path) -> dict | None:
        try:
            outer = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(outer, dict) or outer.get("format") != STAGING_FORMAT:
            return None
        return outer

    def _digest_index(self) -> dict[str, str]:
        """sha256 → batch_id，带**按文件名**的增量缓存。

        只读取「缓存里还没有的文件」；已删除的文件顺手剔除。批次文件的
        `source.sha256` 建好之后不会再变，所以这个缓存不会读到过期摘要。
        调用方负责持锁（或接受被另一进程插入一批的读侧竞态）。

        **`discarded` 的批次不算「已存在」**：用户丢掉的东西不该因为「判重命中」
        又被原样递回来（Q-11）。走 inbox 时有墓碑兜底，但直接调 `create_from_file`
        的路径（Web 端重新上传同一份文件）只有这一层，必须自己看状态。
        `committed` / `rolled_back` 仍然算已存在 —— 那是「这份内容我处理过了」，
        不该再建第二批（重启后的去重就靠它）。
        """
        try:
            names = {path.name for path in self._raw_paths()}
        except OSError:
            names = set()
        # 剔除已经不存在的文件（清理会删文件）
        for stale in [name for name in self._outer_index if name not in names]:
            self._outer_index.pop(stale, None)
        mapping: dict[str, str] = {}
        for name in names:
            cached = self._outer_index.get(name)
            if cached is None:
                outer = self._read_outer_file(self._dir / name)
                if outer is None:
                    continue
                digest = str((outer.get("source") or {}).get("sha256") or "")
                batch_id = str(outer.get("batch_id") or "")
                if not digest or not batch_id:
                    continue
                cached = (digest, batch_id, str(outer.get("status") or ""))
                self._outer_index[name] = cached
            # `cached[2]` 是带进来缓存时的 status，见 `_sync_outer_index_status()`。
            # 它是这里唯一能拿到的「这一批现在走到哪一步」的信息，所以那条同步不能省。
            if cached[2] in DEDUP_EXEMPT_STATUSES:
                continue
            mapping[cached[0]] = cached[1]
        return mapping

    def _sync_outer_index_status(self, outer: dict) -> None:
        """状态变更后同步 `_outer_index` 里那一份缓存。

        **这一行不能省，漏了就是一个很难查的 bug**。长驻进程（Web / MCP）里同一个
        `StagingStore` 实例要活很久，`_digest_index()` 为了让「一次扫 500 个文件」不至于
        退化成 O(n²)，会把 `文件名 → (sha256, batch_id, status)` 缓存下来，之后
        **按缓存读、不再碰磁盘**。于是出现这种情形：

            1. 进程读过这个批次文件 → 缓存里 status="drafted"
            2. 用户在界面点「丢弃」→ 磁盘上的文件确实变成 "discarded"，但缓存没更新
            3. 用户重新拖同一份文件进来 → `_digest_index()` 从缓存读到 "drafted"
               → 判重命中 → 把刚丢掉的那一批原样递回来

        跨进程反而不会出问题（新进程缓存是空的，会去读磁盘拿到真 status）。也就是说
        **只有长驻进程、且这个批次被读过一次之后才会复现** —— 恰好是用户日常所在的场景。

        所以状态一旦变化就得同步缓存，不能指望「下次重扫目录」来纠正：重扫只有在缓存里
        查不到这个文件名时才会发生。
        """
        batch_id = str(outer.get("batch_id") or "")
        if not batch_id:
            return
        key = f"{batch_id}{STAGING_SUFFIX}"
        cached = self._outer_index.get(key)
        if cached is not None and cached[2] != str(outer.get("status") or ""):
            self._outer_index[key] = (cached[0], cached[1], str(outer.get("status") or ""))

    def _remember_batch_file(self, batch_id: str, digest: str, status: str = "drafted") -> None:
        """把自己刚写完的批次文件登记进索引，省掉下一次全量读。"""
        self._outer_index[f"{batch_id}{STAGING_SUFFIX}"] = (digest, batch_id, status)

    def _forget_batch_file(self, batch_id: str) -> None:
        """显式失效：批次文件被删除/改名时调用，绝不让缓存留下「幽灵批次」。

        `_digest_index()` 本身也会剔除「名字已经不在目录里」的条目（这是第二道保险），
        但删除的**当场**就把条目摘掉更安全：同一个批次刚删完、目录里恰好又有同名文件
        被重建这种极端情况下，缓存不会把旧摘要当成新摘要。
        """
        if not batch_id:
            return
        self._outer_index.pop(f"{batch_id}{STAGING_SUFFIX}", None)

    def _load_outer(self, batch_id: str) -> dict:
        path = self._batch_path(batch_id)
        outer = self._read_outer_file(path) if path.exists() else None
        if outer is None:
            raise StagingNotFound(batch_id)
        return outer

    def _load_inner(self, outer: dict) -> dict:
        dek = self._require_dek()
        vault_id = str(outer.get("vault_id") or self._vault_id())
        batch_id = str(outer.get("batch_id") or "")
        raw = crypto.open_sealed(
            dek,
            outer.get("sealed") or {},
            self._aad(batch_id, vault_id),
            what="待整理草稿",
        )
        try:
            inner = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CorruptVault("待整理草稿解密成功但内容无法解析") from exc
        if not isinstance(inner, dict):
            raise CorruptVault("待整理草稿结构异常")
        inner.setdefault("schema", 1)
        inner.setdefault("items", [])
        return inner

    def _write_outer(self, outer: dict, inner: dict | None = None) -> None:
        """写回外层；给了 `inner` 就重新加密。锁必须已被调用方持有。"""
        vault_id = str(outer.get("vault_id") or "")
        batch_id = str(outer.get("batch_id") or "")
        if inner is not None:
            dek = self._require_dek()
            if not vault_id:
                vault_id = self._vault_id()
                outer["vault_id"] = vault_id
            payload = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            outer["sealed"] = crypto.seal(dek, payload, self._aad(batch_id, vault_id))
            outer["item_count"] = len(inner.get("items") or [])
        outer["format"] = STAGING_FORMAT
        outer["version"] = STAGING_VERSION
        outer["updated"] = _iso(self.now())
        path = self._batch_path(batch_id)
        data = json.dumps(outer, ensure_ascii=False, indent=2).encode("utf-8")
        try:
            atomic_write(path, data)
        except FileNotFoundError:
            # 目录被外部删掉了（用户清理 / 另一进程重建）：补建一次再写。
            # 正常情况下不进来 —— `__init__` 已经建过，所以不再每次写都 mkdir
            # （一次 mkdir 在 Windows 上约 1.2ms，500 个文件就是 1200 次多余的 syscall）。
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(path, data)

    def _batch_from(
        self,
        outer: dict,
        items: list[StagingItem] | None = None,
        *,
        deduped: bool = False,
    ) -> StagingBatch:
        loaded = items
        if loaded is None:
            if self.has_dek():
                try:
                    loaded = self._items(self._load_inner(outer))
                except VaultError:
                    loaded = []
            else:
                loaded = []
        return StagingBatch(
            batch_id=str(outer.get("batch_id") or ""),
            status=str(outer.get("status") or "detected"),
            source=dict(outer.get("source") or {}),
            items=loaded,
            origin=str(outer.get("origin") or "local"),  # type: ignore[arg-type]
            created=str(outer.get("created") or ""),
            updated=str(outer.get("updated") or ""),
            lease=outer.get("lease"),
            editor=outer.get("editor"),
            commit=outer.get("commit"),
            notes=str(outer.get("notes") or ""),
            item_count=int(outer.get("item_count") or 0),
            deduped=deduped,
        )

    def _items(self, inner: dict) -> list[StagingItem]:
        return [_item_from_dict(raw) for raw in (inner.get("items") or []) if isinstance(raw, dict)]

    # ------------------------------------------------------------- 状态机
    def _transition_outer(self, outer: dict, target: str) -> None:
        current = str(outer.get("status") or "detected")
        if target == current:
            return
        if not can_transition(current, target):
            raise StagingBusy(
                f"批次现在「{label_of(current)}」，不能变成「{label_of(target)}」。"
            )
        outer["status"] = target
        if target in ("review",) or target in FINISHED_STATUSES:
            outer["lease"] = None
        if target in FINISHED_STATUSES:
            outer["editor"] = None
            outer["lease"] = None
        # 缓存里的 status 必须跟着改，否则本进程会继续把这一批当成旧状态去判重。
        # 这里是**唯一**的状态变更入口，放在这里比逐个调用点补要可靠。
        self._sync_outer_index_status(outer)

    def transition(self, batch_id: str, to: str, *, reason: str = "") -> StagingBatch:
        """唯一状态变更入口。非法转换 → `StagingBusy`（不含记录内容）。"""
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.transition"):
            outer = self._load_outer(batch_id)
            self._transition_outer(outer, to)
            self._write_outer(outer)
            log_event("transition", scope="pv", id=batch_id, state=to)
            batch = self._batch_from(outer)
        return batch

    def _lease_valid(self, lease: dict | None) -> bool:
        if not lease:
            return False
        expires = _parse_iso(lease.get("expires"))
        return expires is not None and expires > self.now()

    def _editor_valid(self, editor: dict | None) -> bool:
        if not editor:
            return False
        since = _parse_iso(editor.get("since"))
        if since is None:
            return False
        return (self.now() - since) < timedelta(seconds=self._editor_lock_seconds())

    def _editor_record(self, holder: str, *, taken_over: bool = False) -> dict:
        """编辑锁的载荷。

        `pid` 必须记下来：`holder` 只是一句字符串标签（DESIGN §3 的默认值就是
        `"ui"`），两个进程都用默认值时它无法区分「同一个编辑者」和「另一个编辑者」。
        带上 pid 之后，「同标签 + 同进程」才算幂等重入（Q-03）。
        `taken_over` 是给 UI 的提示：这把锁是接管过期锁得来的，不是首占。
        """
        return {
            "holder": str(holder),
            "pid": os.getpid(),
            "since": _iso(self.now()),
            "taken_over": bool(taken_over),
        }

    @staticmethod
    def _same_editor(editor: dict | None, holder: str) -> bool:
        """这条编辑锁是不是「我」的：同标签 **且** 同进程。

        老数据没有 `pid`（v1.1 之前的批次）→ 判为 False，宁可让用户等 120 秒锁过期，
        也不要把「同一个 holder 字符串」当成「同一个编辑者」而让两边互相覆盖。
        """
        if not editor:
            return False
        if str(editor.get("holder") or "") != str(holder):
            return False
        try:
            return int(editor.get("pid")) == os.getpid()
        except (TypeError, ValueError):
            return False

    def expire_leases(self) -> int:
        """`refining` + 租约过期 → 有本地草稿回 `drafted`，否则 `failed`。"""
        healed = 0
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.expire"):
            for path in self._raw_paths():
                outer = self._read_outer_file(path)
                if outer is None or outer.get("status") != "refining":
                    continue
                if self._lease_valid(outer.get("lease")):
                    continue
                target = "drafted" if int(outer.get("item_count") or 0) > 0 else "failed"
                if not can_transition("refining", target):
                    continue
                outer["status"] = target
                outer["lease"] = None
                self._write_outer(outer)
                healed += 1
        return healed

    # ------------------------------------------------------------- 查询
    def list_batches(
        self,
        *,
        statuses: Sequence[str] | None = None,
        include_finished: bool = False,
    ) -> list[StagingBatch]:
        self.expire_leases()
        wanted = set(statuses) if statuses else None
        out: list[StagingBatch] = []
        for path in self._raw_paths():
            outer = self._read_outer_file(path)
            if outer is None:
                continue
            status = str(outer.get("status") or "")
            if wanted is not None and status not in wanted:
                continue
            if wanted is None and not include_finished and status in FINISHED_STATUSES:
                continue
            out.append(self._batch_from(outer))
        out.sort(key=lambda batch: str(batch.updated or batch.created), reverse=True)
        return out

    def get(self, batch_id: str) -> StagingBatch:
        self.expire_leases()
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.get"):
            outer = self._load_outer(batch_id)
        # 详情必须真解密：解不开要报错，不能静默当成空批次
        items = self._items(self._load_inner(outer))
        return self._batch_from(outer, items)

    def raw_text(self, batch_id: str) -> str:
        """取源文件原文（Agent 认领后归纳用）。文件已被归档也能找到。"""
        outer = self._load_outer(batch_id)
        source = outer.get("source") or {}
        candidates: list[Path] = []
        rel = source.get("inbox_rel_path")
        if rel:
            candidates.append(self._settings.home / str(rel))
        moved = source.get("moved_to")
        if moved:
            candidates.append(self._settings.home / str(moved))
        name = source.get("file_name")
        if name:
            candidates.append(self._settings.inbox_path / str(name))
        limit = int(getattr(self._settings, "staging_max_raw_bytes", 204800))
        for path in candidates:
            try:
                if path.is_file():
                    data = path.read_bytes()[:limit]
                    return _decode_text(data)
            except OSError:
                continue
        return ""

    def inbox_pending(self) -> int:
        inbox = self._settings.inbox_path
        if not inbox.is_dir():
            return 0
        try:
            return sum(1 for path in inbox.iterdir() if path.is_file() and path.suffix.lower() != ".lock")
        except OSError:
            return 0

    # ------------------------------------------------------------- 建批次
    def _build_items(
        self,
        drafts: Sequence[Record],
        notes: Sequence[tuple[int, str]] = (),
        *,
        origin: Origin = "local",
        existing: Sequence[Record] | None = None,
    ) -> list[StagingItem]:
        rows: list[list[Warning]] = []
        if drafts:
            if existing:
                rows = service.validate_records(list(existing), list(drafts), notes=list(notes))
            else:
                rows = service.validate_records(list(drafts), notes=list(notes))

        items: list[StagingItem] = []
        for index, draft in enumerate(drafts):
            warnings = rows[index] if index < len(rows) else []
            items.append(
                StagingItem(
                    item_id=ITEM_PREFIX + secrets.token_hex(4),
                    draft=draft,
                    origin=origin,
                    accepted=not any(warning.level == "error" for warning in warnings),
                    warnings=warnings,
                )
            )
        return items

    def create_from_file(
        self,
        *,
        path: Path | str,
        text: str,
        drafts: Sequence[Record],
        notes: Sequence[tuple[int, str]] = (),
        origin: Origin = "local",
        existing: Sequence[Record] | None = None,
        dedupe_index: MutableMapping[str, str] | None = None,
    ) -> StagingBatch:
        """从一个源文件建批次。

        同一份内容（按源文件 sha256）只会有一个批次。判重有**三层**，本方法是唯一入口：

        1. 调用方传入的 `dedupe_index`（`inbox.scan_once` 那一轮的「sha256 → batch_id」
           快照）——批量场景下省掉每建一批就重扫一遍 staging 目录（500 个文件时是
           O(n²)）；
        2. 快照未命中 → 本进程的 `_digest_index()`（按文件名的增量缓存）；
        3. 仍未命中 → **锁内**再问一次真实目录。

        第 3 层不能省：1、2 都是「进锁之前」的快照，两个进程同时扫同一份文件时它们
        都可能读到「还没有这个 sha256」。跨进程唯一可靠的判重点只有锁内。

        命中时**返回既有批次**（`deduped=True`）而不是抛错：调用方拿到返回值后还要
        `_seen.add(digest)` 并发事件，抛错会让单进程的正常路径也变。

        Args:
            dedupe_index: 可选的「sha256 → batch_id」可变映射。传入时本方法会把新建的
                批次登记进去，所以一串扫描循环共用同一个 dict 是安全的。
        """
        target = Path(path)
        try:
            data = target.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            size = len(data)
        except OSError:
            payload = (text or "").encode("utf-8", errors="replace")
            digest = hashlib.sha256(payload).hexdigest()
            size = len(payload)

        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.create"):
            # 判重第 1 层：调用方快照（便宜，但可能是进锁之前的状态）。
            existing_id = str((dedupe_index or {}).get(digest) or "")
            if not existing_id:
                # 判重第 2 层（也是权威层）：**锁内**读真实目录。这一层不能省 ——
                # 两个进程同时扫同一份文件时，第 1 层的快照都会读到「还没有这个
                # sha256」，于是各建一批（Q-05 的窗口就在这里）。
                existing_id = str(self._digest_index().get(digest) or "")
            if existing_id:
                try:
                    outer = self._load_outer(existing_id)
                except VaultError:
                    outer = {}
                if outer:
                    log_event("create_deduped", scope="pv", id=existing_id)
                    return self._batch_from(outer, deduped=True)

            batch_id = BATCH_PREFIX + secrets.token_hex(6)
            items = self._build_items(drafts, notes, origin=origin, existing=existing)
            stamp = _iso(self.now())
            outer = {
                "format": STAGING_FORMAT,
                "version": STAGING_VERSION,
                "vault_id": self._vault_id(),
                "batch_id": batch_id,
                "status": "detected",
                "origin": origin,
                "item_count": 0,
                "notes": "",
                "created": stamp,
                "updated": stamp,
                "source": {
                    "file_name": target.name or "粘贴内容",
                    "sha256": digest,
                    "size": size,
                    "inbox_rel_path": self._relative_to_home(target),
                    "moved_to": None,
                    "detected_at": stamp,
                    "format": (target.suffix.lower().lstrip(".") or "txt"),
                },
                "lease": None,
                "editor": None,
                "commit": None,
                "sealed": {},
            }
            inner = {"schema": 1, "items": [_item_to_dict(item) for item in items]}
            # 先落一个 detected（文件已被认领），再走状态机到 drafted / failed。
            # 两次写都在同一把锁内，外部永远观察不到中间态。
            self._write_outer(outer, inner)
            self._transition_outer(outer, "drafted" if items else "failed")
            self._write_outer(outer)
            self._remember_batch_file(batch_id, digest)
            if dedupe_index is not None:
                # 同一个扫描循环里后续文件也能立刻看到这一批，不必再重扫目录。
                dedupe_index[digest] = batch_id
            return self._batch_from(outer, items)

    def create_manual(self, *, source_name: str = "手动新建", origin: Origin = "local") -> StagingBatch:
        """本地解析不出东西时的出口：给一个空草稿让用户手填。"""
        blank = Record(title="")
        item = StagingItem(
            item_id=ITEM_PREFIX + secrets.token_hex(4),
            draft=blank,
            origin=origin,
            accepted=False,
            edited=True,
            warnings=[
                Warning(
                    code="title_missing",
                    level="error",
                    message="还没有标题，填好后再提交",
                    field="title",
                )
            ],
        )
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.manual"):
            batch_id = BATCH_PREFIX + secrets.token_hex(6)
            stamp = _iso(self.now())
            outer = {
                "format": STAGING_FORMAT,
                "version": STAGING_VERSION,
                "vault_id": self._vault_id(),
                "batch_id": batch_id,
                "status": "drafted",
                "origin": origin,
                "item_count": 1,
                "notes": "",
                "created": stamp,
                "updated": stamp,
                "source": {
                    "file_name": source_name,
                    "sha256": "",
                    "size": 0,
                    "inbox_rel_path": None,
                    "moved_to": None,
                    "detected_at": stamp,
                    "format": "manual",
                },
                "lease": None,
                "editor": None,
                "commit": None,
                "sealed": {},
            }
            inner = {"schema": 1, "items": [_item_to_dict(item)]}
            self._write_outer(outer, inner)
            return self._batch_from(outer, [item])

    def _relative_to_home(self, target: Path) -> str | None:
        try:
            return str(target.resolve().relative_to(self._settings.home.resolve())).replace("\\", "/")
        except (ValueError, OSError):
            return None

    # ------------------------------------------------------------- Agent 流程
    def claim(
        self,
        batch_id: str,
        *,
        holder: str = "agent",
        lease_seconds: int | None = None,
    ) -> StagingBatch:
        """认领批次 → `refining`。已有有效租约 / 已在人工确认 → `StagingBusy`。"""
        limit = int(lease_seconds or self._settings.staging_lease_seconds)
        limit = max(1, min(limit, int(self._settings.staging_lease_max_seconds)))

        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.claim"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if status in ("review", "reviewing"):
                raise StagingBusy("这个批次正在人工确认，暂时不能认领。")
            if status in FINISHED_STATUSES:
                raise StagingBusy(f"批次已经「{label_of(status)}」，不能再认领。")
            lease = outer.get("lease")
            if self._lease_valid(lease) and str((lease or {}).get("holder")) != holder:
                raise StagingBusy("这个批次正在被另一个整理者处理，请稍后再试。")
            if not can_transition(status, "refining"):
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能认领。")

            stamp = self.now()
            outer["status"] = "refining"
            outer["lease"] = {
                "holder": holder,
                "acquired": _iso(stamp),
                "expires": _iso(stamp + timedelta(seconds=limit)),
            }
            self._write_outer(outer)
            batch = self._batch_from(outer)
        return batch

    def _collect_secret_probes(
        self,
        records: Sequence[Record],
        existing_items: Sequence[StagingItem] = (),
    ) -> set[str]:
        """收集「绝对不该出现在明文总结里」的值：本次草稿 + 上一轮的草稿。"""
        probes: set[str] = set()
        drafts: list[Record] = [record for record in records]
        drafts.extend(item.draft for item in existing_items if item.draft is not None)
        for record in drafts:
            for value in (record.password, record.totp):
                text = str(value or "").strip()
                if len(text) >= MIN_SCRUB_PROBE_CHARS:
                    probes.add(text)
            for name, value in (record.fields or {}).items():
                if not is_sensitive_key(name):
                    continue
                text = str(value or "").strip()
                if len(text) >= MIN_SCRUB_PROBE_CHARS:
                    probes.add(text)
        return probes

    def _scrub_notes(
        self,
        text: str,
        records: Sequence[Record],
        *,
        existing_items: Sequence[StagingItem] = (),
    ) -> tuple[str, bool]:
        """总结落盘前的敏感内容扫描（O-2）。命中就**整条**替换，返回 (正文, 是否替换)。"""
        body = str(text or "")
        if not body.strip():
            return body, False
        for probe in self._collect_secret_probes(records, existing_items):
            if probe in body:
                return NOTES_REDACTED_TEXT, True
        for pattern in _SECRET_SHAPES:
            if pattern.search(body):
                return NOTES_REDACTED_TEXT, True
        return body, False

    def submit(
        self,
        batch_id: str,
        records: Sequence[Record],
        *,
        holder: str = "agent",
        summary: str = "",
    ) -> StagingBatch:
        """Agent 交回草稿 → `review`。持有效租约才允许。"""
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.submit"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if status in ("review", "reviewing"):
                raise StagingBusy("该批次正在被人工编辑，Agent 暂时不能改。")
            if status != "refining":
                raise StagingBusy(f"批次现在「{label_of(status)}」，需要先认领才能交回草稿。")
            lease = outer.get("lease")
            if not self._lease_valid(lease) or str((lease or {}).get("holder")) != holder:
                raise StagingBusy("租约已失效，请重新认领这个批次。")
            if not can_transition("refining", "review"):
                raise StagingBusy("批次当前状态不允许交回草稿。")

            items = self._build_items(list(records), (), origin="agent")
            if not items:
                raise StagingBusy("交回的草稿是空的。")
            if len(items) > int(self._settings.staging_max_items):
                raise StagingBusy("这个批次条目太多，请分批交回。")

            inner = {"schema": 1, "items": [_item_to_dict(item) for item in items]}
            # 上一轮的草稿也要当探针：Agent 最常泄漏的正是它刚从源文件里读到、
            # 但这次没交回来的那几个值。
            try:
                previous_items = self._items(self._load_inner(outer))
            except VaultError:
                previous_items = []
            notes_text, notes_redacted = self._scrub_notes(
                summary, list(records), existing_items=previous_items
            )
            outer["status"] = "review"
            outer["lease"] = None
            outer["origin"] = "agent"
            outer["notes"] = notes_text[:MAX_NOTES_CHARS]
            outer["notes_redacted"] = bool(notes_redacted)
            if notes_redacted:
                log_event("notes_redacted", scope="pv", level="WARN", id=batch_id)
            self._write_outer(outer, inner)
            batch = self._batch_from(outer, items)
        return batch

    # ------------------------------------------------------------- UI 流程
    def save_items(
        self,
        batch_id: str,
        items: Sequence[StagingItem],
        *,
        editor: str = "ui",
    ) -> StagingBatch:
        """保存条目编辑：重算警告，清掉 error 条目的 accepted。

        保存同时充当编辑锁的心跳（刷新 `since`）。但**不允许跨编辑者保存**：
        `save_items` 直接整批覆盖条目，如果别人正拿着有效的编辑锁，这次覆盖就是
        「把对方刚填的内容吞掉」—— 与 `begin_edit` 的 Q-03 是同一根因，所以同样拦。
        """
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.save_items"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if status not in ("review", "reviewing"):
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能编辑条目。")

            existing_editor = outer.get("editor") or {}
            if status == "reviewing" and self._editor_valid(existing_editor):
                if not self._same_editor(existing_editor, editor):
                    raise StagingBusy("这个批次正在被另一个窗口编辑，你的修改没有保存。")

            drafts = [item.draft for item in items]
            rows = service.validate_records(drafts) if drafts else []
            saved: list[StagingItem] = []
            for index, item in enumerate(items):
                warnings = rows[index] if index < len(rows) else list(item.warnings)
                item.warnings = warnings
                if any(warning.level == "error" for warning in warnings):
                    item.accepted = False
                saved.append(item)

            if len(saved) > int(self._settings.staging_max_items):
                raise StagingBusy("这个批次条目太多。")

            outer["editor"] = self._editor_record(
                editor, taken_over=bool(existing_editor.get("taken_over"))
            )
            inner = {"schema": 1, "items": [_item_to_dict(item) for item in saved]}
            self._write_outer(outer, inner)
            batch = self._batch_from(outer, saved)
        return batch

    def begin_edit(self, batch_id: str, *, holder: str | None = None) -> StagingBatch:
        """开始编辑（拿编辑锁）。

        `holder` 必须**标识编辑会话**，不是一句常量。默认值 `"ui"` 是设计签名里
        留下的（CLI 与单窗口场景够用），但它不足以区分两个浏览器窗口：
        两个进程都用默认值时，第二个 `begin_edit` 会静默成功，随后两边 `save_items`
        互相覆盖，用户刚填的内容被吞掉（Q-03）。所以幂等判定改成
        「同 holder + 同 pid」，接管过期锁会在 `editor.taken_over` 上留痕。
        Web 层应当传会话级 holder（如 `f"web:{token}"`），那样同进程的两个窗口也能区分。
        """
        label = str(holder) if holder is not None else "ui"
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.begin_edit"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if status == "reviewing":
                editor = outer.get("editor") or {}
                if self._editor_valid(editor):
                    if not self._same_editor(editor, label):
                        raise StagingBusy("这个批次正在被另一个窗口编辑。")
                    return self._batch_from(outer)
                # 编辑锁已过期（浏览器崩了/窗口关了）：允许接管，不至于锁死批次
                outer["editor"] = self._editor_record(label, taken_over=True)
                self._write_outer(outer)
                return self._batch_from(outer)
            if status != "review":
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能开始编辑。")
            self._transition_outer(outer, "reviewing")
            outer["editor"] = self._editor_record(label)
            self._write_outer(outer)
            batch = self._batch_from(outer)
        return batch

    def end_edit(self, batch_id: str) -> StagingBatch:
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.end_edit"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if status == "review":
                outer["editor"] = None
                self._write_outer(outer)
                return self._batch_from(outer)
            if status != "reviewing":
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能结束编辑。")
            self._transition_outer(outer, "review")
            outer["editor"] = None
            self._write_outer(outer)
            batch = self._batch_from(outer)
        return batch

    # ------------------------------------------------------------- 入库
    def _find_existing(self, records: Iterable[Record], draft: Record) -> Record | None:
        key = (draft.title.casefold().strip(), draft.username.casefold().strip())
        for record in records:
            if (record.title.casefold().strip(), record.username.casefold().strip()) == key:
                return record
        return None

    def commit(
        self,
        batch_id: str,
        *,
        store: VaultStore,
        accept_item_ids: set[str] | None = None,
        mode: Resolution = "skip",
        timeout: float | None = None,
    ) -> dict:
        """把批次写进库。原子：有冲突就**一个字节都不写**，状态退回 review。

        幂等：`on_id_conflict="skip"` + 已提交状态直接返回，重放不会插出重复记录。
        """
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.commit"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")

            if status == "committed":
                info = outer.get("commit") or {}
                return {
                    "status": "committed",
                    "already_committed": True,
                    "revision": info.get("revision"),
                    "added": 0,
                    "updated": 0,
                    "skipped": 0,
                    "rollback_hint": "这个批次已经入库过了，重复提交不会写入第二次。",
                }

            if status not in ("review", "reviewing"):
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能提交。")

            inner = self._load_inner(outer)
            items = self._items(inner)
            chosen = [
                item
                for item in items
                if (accept_item_ids is None or item.item_id in accept_item_ids)
                and item.accepted
                and not item.has_error
            ]
            if not chosen:
                raise StagingBusy("没有勾选任何可提交的条目。")

            # 先记意图：断电后能看出「当时准备提交哪几条」
            stamp = _iso(self.now())
            outer["commit"] = {
                "revision": None,
                "at": stamp,
                "intent": {"at": stamp, "item_ids": [item.item_id for item in chosen]},
                "result": None,
            }

            vault = store.vault
            ops: list[Operation] = []
            befores: dict[str, dict] = {}
            skipped = 0

            for item in chosen:
                existing = self._find_existing(vault.records, item.draft)
                if existing is None:
                    ops.append(Operation.add(item.draft, on_id_conflict="skip"))
                    continue
                resolution = str((item.conflict or {}).get("resolution") or mode)
                if resolution == "skip":
                    skipped += 1
                    continue
                if resolution == "overwrite":
                    befores[item.item_id] = existing.to_dict()
                    ops.append(
                        Operation.update(
                            existing.id,
                            _full_changes(item.draft),
                            expected_updated=existing.updated,
                        )
                    )
                    continue
                # append：作为新副本入库
                item.draft.id = new_id()
                ops.append(Operation.add(item.draft, on_id_conflict="skip"))

            if not ops:
                self._transition_outer(outer, "review")
                outer["commit"] = None
                self._write_outer(outer)
                return {
                    "status": "review",
                    "revision": store.revision(),
                    "added": 0,
                    "updated": 0,
                    "skipped": skipped,
                    "rollback_hint": "全部条目都按「跳过」处理，没有写入任何记录。",
                }

            result = store.commit(ops, timeout=timeout)

            if result.conflicts:
                self._transition_outer(outer, "review")
                outer["editor"] = None
                outer["commit"] = None
                self._write_outer(outer)
                return {
                    "status": "review",
                    "revision": result.revision,
                    "added": 0,
                    "updated": 0,
                    "skipped": skipped,
                    "conflicts": [conflict.to_dict() for conflict in result.conflicts],
                    "rollback_hint": "有记录刚被改过，请选择「跳过 / 覆盖 / 新建副本」后重试。",
                }

            intent = (outer.get("commit") or {}).get("intent")
            for item in chosen:
                item.before = befores.get(item.item_id)
            inner["items"] = [_item_to_dict(item) for item in items]
            self._transition_outer(outer, "committed")
            outer["editor"] = None
            outer["lease"] = None
            outer["commit"] = {
                "revision": result.revision,
                "at": stamp,
                "intent": intent,
                "result": {
                    "revision": result.revision,
                    "at": _iso(self.now()),
                    "added": result.added,
                    "updated": result.updated,
                    "skipped": skipped,
                },
            }
            moved = self._archive_source(outer)
            if moved:
                outer["source"]["moved_to"] = moved
            self._write_outer(outer, inner)

        return {
            "status": "committed",
            "revision": result.revision,
            "added": result.added,
            "updated": result.updated,
            "skipped": skipped,
            "rollback_hint": "入库成功后可以在待整理页撤销这个批次。",
        }

    def _archive_source(self, outer: dict) -> str | None:
        """把源文件移进 `inbox/processed/`。失败只记日志（不能让入库回滚）。"""
        if not getattr(self._settings, "inbox_archive_processed", True):
            return None
        source = outer.get("source") or {}
        name = str(source.get("file_name") or "")
        rel = source.get("inbox_rel_path")
        if not name or not rel:
            return None
        src = self._settings.home / str(rel)
        if not src.is_file():
            return None
        target_dir = self._settings.processed_dir
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / name
            counter = 1
            while target.exists():
                target = target_dir / f"{Path(name).stem}-{counter}{Path(name).suffix}"
                counter += 1
            shutil.move(str(src), str(target))
            return self._relative_to_home(target)
        except OSError as exc:  # noqa: BLE001
            log_event("archive_failed", scope="pv", level="WARN", code=type(exc).__name__)
            return None

    # ------------------------------------------------------------- 撤销
    def rollback(self, batch_id: str, *, store: VaultStore) -> dict:
        """按每条的 `before` 逐条回滚：add 型删除、overwrite 型还原字段。"""
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.rollback"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if status != "committed":
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能撤销。")
            inner = self._load_inner(outer)
            items = self._items(inner)

            ops: list[Operation] = []
            for item in items:
                if not item.accepted or item.has_error:
                    continue
                if item.before:
                    record_id = str(item.before.get("id") or "")
                    if not record_id:
                        continue
                    ops.append(
                        Operation.update(record_id, _changes_from_snapshot(item.before))
                    )
                elif item.draft.id:
                    ops.append(Operation.delete(item.draft.id))

            if not ops:
                raise StagingBusy("这个批次没有可撤销的条目。")

            result = store.commit(ops)
            if result.conflicts:
                raise StagingBusy("撤销时有记录已被改动，批次保持「已入库」，请先处理冲突。")
            if result.updated + result.deleted == 0:
                raise StagingBusy("这些记录已经不在库里了，撤销没有产生变化。")

            outer["status"] = "rolled_back"
            commit_info = dict(outer.get("commit") or {})
            commit_result = dict(commit_info.get("result") or {})
            commit_result.update(
                {
                    "rolled_back_at": _iso(self.now()),
                    "deleted": result.deleted,
                    "restored": result.updated,
                    "revision": result.revision,
                }
            )
            commit_info["result"] = commit_result
            outer["commit"] = commit_info
            self._write_outer(outer)

        return {
            "status": "rolled_back",
            "revision": result.revision,
            "deleted": result.deleted,
            "restored": result.updated,
        }

    # ------------------------------------------------------------- 丢弃与墓碑
    def discard(self, batch_id: str, *, delete_source: bool = False) -> None:
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.discard"):
            outer = self._load_outer(batch_id)
            status = str(outer.get("status") or "")
            if not can_transition(status, "discarded"):
                raise StagingBusy(f"批次现在「{label_of(status)}」，不能丢弃。")
            self._transition_outer(outer, "discarded")
            self._write_outer(outer)
            source = outer.get("source") or {}
            digest = str(source.get("sha256") or "")
            name = str(source.get("file_name") or "")

        self.tombstone(digest, name)
        if delete_source and source.get("inbox_rel_path"):
            path = self._settings.home / str(source["inbox_rel_path"])
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_tombstones(self) -> dict:
        path = self._settings.tombstones_path
        if not path.exists():
            return {"format": TOMBSTONE_FORMAT, "version": 1, "vault_id": "", "entries": []}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"format": TOMBSTONE_FORMAT, "version": 1, "vault_id": "", "entries": []}
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            return {"format": TOMBSTONE_FORMAT, "version": 1, "vault_id": "", "entries": []}
        return data

    def _write_tombstones(self, data: dict) -> None:
        path = self._settings.tombstones_path
        path.parent.mkdir(parents=True, exist_ok=True)
        data["format"] = TOMBSTONE_FORMAT
        data["version"] = 1
        entries = list(data.get("entries") or [])
        if len(entries) > MAX_TOMBSTONES:
            entries = entries[-MAX_TOMBSTONES:]
        data["entries"] = entries
        atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    def tombstone(self, sha256_hex: str, file_name: str, *, batch_id: str = "") -> None:
        """记一条墓碑：同一个文件不再反复建批次。

        **明文存储**（DESIGN §4.4 推翻 PRD §9 的「加密清单」）：内容只有文件指纹、
        文件名与时间，不含任何凭据；加密后未解锁时就无法判重，正好毁掉它的用途。

        墓碑约束的是「这个 sha256」，**不区分时刻**：DESIGN §4.4 与 T04 验收 ③ 把
        丢弃定义成「用户说过这一份不要了」。源文件常常还留在 `inbox/` 里，而扫描是
        2 秒一轮 —— 一旦按 mtime 放行，丢掉的那份会立刻再建一批，正好毁掉这个功能。
        """
        if not sha256_hex:
            return
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.tombstone"):
            data = self._read_tombstones()
            entries = [entry for entry in data.get("entries") or [] if entry.get("sha256") != sha256_hex]
            entries.append(
                {
                    "sha256": sha256_hex,
                    "file_name": file_name,
                    "discarded_at": _iso(self.now()),
                    "batch_id": batch_id,
                }
            )
            data["entries"] = entries
            data["vault_id"] = data.get("vault_id") or self._cached_vault_id
            self._write_tombstones(data)

    def _cleanup_tombstones(self) -> None:
        ttl_days = int(getattr(self._settings, "staging_ttl_days", 30))
        data = self._read_tombstones()
        entries = data.get("entries") or []
        if not entries:
            return
        cutoff = self.now() - timedelta(days=ttl_days)
        kept = [
            entry
            for entry in entries
            if (_parse_iso(entry.get("discarded_at")) or self.now()) >= cutoff
        ]
        if len(kept) != len(entries):
            data["entries"] = kept
            try:
                self._write_tombstones(data)
            except OSError:
                pass

    def seen_hashes(self) -> set[str]:
        return {
            str(entry.get("sha256"))
            for entry in (self._read_tombstones().get("entries") or [])
            if entry.get("sha256")
        }

    def batches_by_hash(self) -> dict[str, str]:
        """sha256 → batch_id。重启后去重靠它（墓碑只覆盖「被丢弃」的情况）。

        公开名，实现就是 `_digest_index()` —— 两者**同一份数据、同一份缓存**，
        没有第二套逻辑。`inbox.scan_once` 用这个公开名取读侧快照，
        `create_from_file` 直接用内部名（它要的是「锁内再看一眼」的语义）。
        """
        return self._digest_index()

    # ------------------------------------------------------------- 清理
    def purge_expired_batches(self, *, keep_days: int | None = None) -> int:
        """清理超过 `staging_ttl_days` 的已完结批次文件。"""
        days = int(keep_days if keep_days is not None else self._settings.staging_ttl_days)
        cutoff = self.now() - timedelta(days=days)
        removed = 0
        with self._lock.hold(timeout=self._lock_timeout(), purpose="staging.purge"):
            for path in self._raw_paths():
                outer = self._read_outer_file(path)
                if outer is None:
                    continue
                if str(outer.get("status")) not in FINISHED_STATUSES:
                    continue
                updated = _parse_iso(outer.get("updated")) or _parse_iso(outer.get("created"))
                if updated is None or updated >= cutoff:
                    continue
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
                # 缓存失效必须显式做（O 项要求）：文件没了，`_digest_index()` 里那条
                # 「文件名 → sha256」必须一起没，否则同一份内容再进 inbox 会被
                # 判成「已有批次」而静默不建批。
                self._forget_batch_file(str(outer.get("batch_id") or ""))
        return removed


def _decode_text(data: bytes) -> str:
    """逐级回退解码：utf-8 → utf-8-sig → gbk → latin-1（永远不抛异常）。"""
    for encoding in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


__all__ = [
    "ALLOWED_TRANSITIONS",
    "BatchStatus",
    "FINISHED_STATUSES",
    "STATUS_LABEL",
    "StagingBatch",
    "StagingItem",
    "StagingStore",
    "Warning",
    "can_transition",
    "label_of",
]
