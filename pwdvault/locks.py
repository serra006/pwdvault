"""跨进程写锁 + 记录级 rebase —— `data.enc` 的唯一写入口。

三个必须写对的点（架构实测结论，不是记忆）：

1. **同进程多线程不能靠文件锁互斥**。`msvcrt.locking` 同进程换个句柄再锁会立即
   `EACCES`，会被误翻译成「另一个窗口在写入」。所以第一层是进程内 `threading.RLock`
   （按锁文件路径缓存）。
2. **同线程重入绝不能再调 `msvcrt.locking`**。用 `threading.local` 记重入深度，
   depth > 0 直接放行。否则「暂存区 commit 里再调 VaultStore.commit」这类嵌套调用
   100% 失败，而且是「一个永远不会成功的操作」。
3. **超时必须自己控**。用 `LK_NBLCK` + 25ms 重试到 deadline；`LK_LOCK`（阻塞版）
   内部固定重试 10 次约 9s 后抛 `EDEADLOCK`，3 秒的 UI 超时形同虚设。

读路径永不加锁：`os.replace` 是原子的，读者读到的一定是完整旧版或完整新版。

依赖方向：本文件只认 `Vault` / `Record` / `Operation`，**不 import**
`service` / `staging` / `inbox` / `web` / `mcp_*` / `cli`。
记录级字段应用逻辑在 `Record.apply_changes`（models.py），所以这里不需要业务层。
"""

from __future__ import annotations

import os
import random
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, Sequence

from .config import Settings, log_event
from .errors import LockTimeout, StaleWrite, VaultError
from .models import MASK, Record, is_sensitive_key, new_id
from .redact import redact_record
from .vault import Vault, read_revision

OpKind = Literal["add", "update", "delete"]
ReloadPolicy = Literal["auto", "never", "force"]
ConflictKind = Literal["stale", "deleted"]

# ---------------------------------------------------------------- 重试常量
# 锁文件**首次创建**时的瞬时共享冲突：Windows 上两个进程同时 `os.open(...O_CREAT)`
# 同一个文件，其中一个会拿到 PermissionError(13)。这是瞬时的（对方只是创建 + 关句柄），
# 但一次都不重试的话它会一路冒到 cli.main 之外 —— 用户看到裸 traceback，
# 既不是 lock_timeout 也不是任何 VaultError。
# 退避序列与 vault.atomic_write / vault._read_text_retry 完全一致（20/40/80/160/320ms）。
OPEN_ATTEMPTS = 6
OPEN_BASE_DELAY = 0.02

# ---------------------------------------------------------------- 进程内状态
_THREAD_STATE = threading.local()
_RLOCK_GUARD = threading.Lock()
_RLOCKS: dict[str, threading.RLock] = {}


def _lock_key(path: Path) -> str:
    """锁文件的规范化键：Windows 上大小写不敏感，统一 casefold。"""
    try:
        resolved = str(path.resolve())
    except OSError:  # pragma: no cover - 极端路径异常
        resolved = str(path)
    return resolved.casefold() if sys.platform == "win32" else resolved


def _rlock_for(key: str) -> threading.RLock:
    with _RLOCK_GUARD:
        lock = _RLOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _RLOCKS[key] = lock
        return lock


def _thread_book() -> dict[str, "_Hold"]:
    book = getattr(_THREAD_STATE, "book", None)
    if book is None:
        book = {}
        _THREAD_STATE.book = book
    return book


class _Hold:
    """当前线程在某把锁上的持有状态（重入深度 + 文件句柄）。"""

    __slots__ = ("depth", "fd")

    def __init__(self) -> None:
        self.depth = 0
        self.fd: int | None = None


class LockManager:
    """`data.enc.lock` 的跨进程独占锁（可重入，超时自管）。"""

    def __init__(
        self,
        lock_path: Path,
        *,
        default_timeout: float = 3.0,
        poll_seconds: float = 0.025,
    ) -> None:
        self._path = Path(lock_path)
        self._default_timeout = float(default_timeout)
        self._poll = max(0.001, float(poll_seconds))
        self._key = _lock_key(self._path)
        self._rlock = _rlock_for(self._key)

    # ------------------------------------------------------------- 属性
    @property
    def path(self) -> Path:
        return self._path

    @property
    def default_timeout(self) -> float:
        return self._default_timeout

    # ------------------------------------------------------------- 对外
    @contextmanager
    def hold(self, *, timeout: float | None = None, purpose: str = "") -> Iterator[None]:
        """拿不到锁 → `LockTimeout`。同线程重入按深度放行。"""
        limit = self._default_timeout if timeout is None else float(timeout)
        book = _thread_book()
        entry = book.get(self._key)

        # ---- 第 2 层：同线程重入，绝不第二次碰文件锁
        if entry is not None and entry.depth > 0:
            entry.depth += 1
            try:
                yield
            finally:
                entry.depth -= 1
            return

        # ---- 第 1 层：进程内 RLock（让同进程的其他线程排队而不是空转 EACCES）
        deadline = time.monotonic() + max(0.0, limit)
        if not self._rlock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise LockTimeout(limit, purpose)
        try:
            fd = self._acquire_file_lock(deadline, limit, purpose)
        except BaseException:
            self._rlock.release()
            raise

        slot = _Hold()
        slot.depth = 1
        slot.fd = fd
        book[self._key] = slot
        try:
            yield
        finally:
            book.pop(self._key, None)
            self._release_file_lock(fd)
            self._rlock.release()

    def busy(self) -> bool:
        """非阻塞探测：别人（含同进程其他线程）是否持有。给 UI 状态条用。

        注意：**当前线程自己持锁时也会返回 True**（因为文件锁已被本进程持有）。
        """
        try:
            fd = self._open_fd()
        except OSError:
            return False
        try:
            if self._try_lock_once(fd):
                self._release_fd_only(fd)
                return False
            return True
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    # ------------------------------------------------------------- 文件锁
    def _open_fd(self) -> int:
        """打开（必要时创建）锁文件，并对**瞬时**共享冲突做有界重试。

        为什么必须重试（Q-01）：`os.open` 在 Windows 上遇到「另一个进程正在
        create/close 同一个文件」会返回 `PermissionError`。这不是真错误、也不会自己
        变成 `VaultError`，而是直接冒到最外层变成裸 traceback。`vault.atomic_write`
        与 `vault._read_text_retry` 早就为同类冲突写了 6 次指数退避，唯独锁文件
        打开这一处漏了 —— 于是「同时首次写库」有约 7% 的概率以 traceback 收场。
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = self._open_fd_with_retry()
        # 锁 1 个字节；文件为空时先落一个字节，避免个别文件系统上的奇怪行为
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
                os.fsync(fd)
        except OSError:
            pass
        return fd

    def _open_fd_with_retry(self) -> int:
        last: PermissionError | None = None
        for attempt in range(OPEN_ATTEMPTS):
            try:
                return os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
            except PermissionError as exc:
                last = exc
                if attempt == OPEN_ATTEMPTS - 1:
                    break
                time.sleep(OPEN_BASE_DELAY * (2**attempt))
        # 重试用尽：仍然交给调用方翻译成 LockTimeout（比裸 PermissionError 可诊断）
        raise last if last is not None else PermissionError(13, "无法打开锁文件")

    def _try_lock_once(self, fd: int) -> bool:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _acquire_file_lock(self, deadline: float, limit: float, purpose: str) -> int:
        try:
            fd = self._open_fd()
        except PermissionError as exc:
            # 重试用尽仍打不开 → 对用户来说是「拿不到锁」，必须是 VaultError 家族：
            # CLI 才能给出人话提示与固定退出码，而不是裸 traceback。
            raise LockTimeout(limit, purpose) from exc
        try:
            while True:
                if self._try_lock_once(fd):
                    return fd
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockTimeout(limit, purpose)
                # 加一点抖动：50 个进程同频轮询会形成「车队」，抖动显著降低饥饿概率
                time.sleep(min(self._poll, remaining) * (0.5 + random.random()))
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _release_fd_only(self, fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass

    def _release_file_lock(self, fd: int | None) -> None:
        if fd is None:
            return
        self._release_fd_only(fd)
        try:
            os.close(fd)
        except OSError:
            pass


# ---------------------------------------------------------------- 操作与结果
@dataclass(frozen=True)
class Operation:
    """一条记录级写操作。所有写入都表达成它的列表，永不「保存整个 vault」。"""

    kind: OpKind
    record_id: str | None = None
    record: Record | None = None
    changes: dict[str, Any] | None = None
    expected_updated: str | None = None
    on_id_conflict: Literal["reassign", "skip"] = "reassign"

    @classmethod
    def add(cls, record: Record, *, on_id_conflict: Literal["reassign", "skip"] = "reassign") -> "Operation":
        return cls(
            kind="add",
            record_id=record.id,
            record=record,
            on_id_conflict=on_id_conflict,
        )

    @classmethod
    def update(
        cls,
        record_id: str,
        changes: dict[str, Any],
        *,
        expected_updated: str | None = None,
    ) -> "Operation":
        return cls(
            kind="update",
            record_id=record_id,
            changes=dict(changes or {}),
            expected_updated=expected_updated,
        )

    @classmethod
    def delete(cls, record_id: str) -> "Operation":
        return cls(kind="delete", record_id=record_id)


@dataclass(frozen=True)
class Conflict:
    """记录级冲突。`theirs` 一定是脱敏过的，绝不把明文带进冲突结构。"""

    record_id: str
    kind: ConflictKind = "stale"
    mine: dict = field(default_factory=dict)
    theirs: dict | None = None

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "kind": self.kind,
            "mine": dict(self.mine),
            "theirs": dict(self.theirs) if self.theirs is not None else None,
        }


@dataclass
class CommitResult:
    revision: int = 0
    added: int = 0
    updated: int = 0
    deleted: int = 0
    applied_ids: list[str] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    reloaded: bool = False
    disk_revision: int = 0

    @property
    def ok(self) -> bool:
        return not self.conflicts


def _public_changes(changes: dict) -> dict:
    """冲突结构里的「我的意图」：敏感键只留掩码，不带明文。"""
    out: dict[str, Any] = {}
    for key, value in (changes or {}).items():
        if isinstance(key, str) and is_sensitive_key(key):
            out[key] = MASK if value not in (None, "") else value
        elif key == "fields" and isinstance(value, dict):
            out[key] = {
                name: (MASK if is_sensitive_key(name) else item) for name, item in value.items()
            }
        else:
            out[key] = value
    return out


class VaultStore:
    """全项目唯一允许写 `data.enc` 的对象：持有一份 Vault + 一把 LockManager。"""

    def __init__(
        self,
        settings: Settings,
        vault: Vault,
        *,
        on_revision: Callable[[int, int], None] | None = None,
        lock: LockManager | None = None,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._dek = vault.dek
        self._on_revision = on_revision
        self._lock = lock or LockManager(
            settings.lock_path,
            default_timeout=getattr(settings, "lock_timeout_seconds", 3.0),
            poll_seconds=getattr(settings, "lock_poll_seconds", 0.025),
        )
        self._last_self_revision = vault.revision
        # 内存里是否可能残留「上一轮没写盘就被中断的改动」（见 `_restore_from_disk`）。
        # 只要它为 True，下一次写操作入口必须先 reload，绝不能在脏快照上继续写。
        self._stale_memory = False

    # ------------------------------------------------------------- 属性
    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def lock(self) -> LockManager:
        return self._lock

    @property
    def dek(self) -> bytes:
        """已被 KEK 解包的 DEK（暂存区复用它加密草稿，不派生新密钥）。"""
        return self._dek

    @property
    def vault(self) -> Vault:
        """当前视图。**必须在锁内使用且不得长期缓存**：rebase 会换掉这个对象。"""
        return self._vault

    def revision(self) -> int:
        return self._vault.revision

    def disk_revision(self) -> int:
        return read_revision(self._settings.vault_path)

    # ------------------------------------------------------------- 读
    def refresh(self) -> bool:
        """盘上 revision 变了（或内存已被标记为脏）就 reload，返回视图是否变化。

        不加锁：`os.replace` 保证读到的必然是完整版本。SSE 轮询线程调它。
        """
        try:
            disk = read_revision(self._settings.vault_path)
        except VaultError:
            return False
        stale = getattr(self, "_stale_memory", False)
        if not stale and disk == self._vault.revision:
            return False
        before = self._vault.revision
        try:
            self._vault = self._reload()
        except VaultError as exc:
            log_event("refresh_failed", scope="pv", level="WARN", code=exc.code)
            return False
        self._stale_memory = False
        return self._vault.revision != before

    def _restore_from_disk(self) -> bool:
        """把内存视图恢复到盘上状态，返回是否恢复成功。

        用在「这次写没成功」的每一条路径上（异常 / 冲突）：`Record.apply_changes`
        是**就地**改对象，异常前可能已经改了一半；而 `vault.save()` 没跑，盘上
        revision 不变 —— 于是下一次 commit 看到 `disk == self._vault.revision`
        判定「无需 reload」，把上一轮失败留下的脏数据一起写进去。
        用户视角：一个明确报错的操作，在几分钟后因为一次无关的写入悄悄生效了（Q-02）。

        恢复不出来（盘损坏等）就留着 `_stale_memory=True`，让下一次写操作入口再试。
        """
        self._stale_memory = True
        try:
            self._vault = self._reload()
        except VaultError as exc:
            log_event("reload_failed", scope="pv", level="WARN", code=exc.code)
            return False
        except Exception as exc:  # noqa: BLE001 - 不能让恢复动作掩盖原始异常
            log_event("reload_failed", scope="pv", level="WARN", code=type(exc).__name__)
            return False
        self._stale_memory = False
        return True

    # ------------------------------------------------------------- 写
    def commit(
        self,
        operations: Sequence[Operation],
        *,
        expected_revision: int | None = None,
        timeout: float | None = None,
        reload_policy: ReloadPolicy = "auto",
    ) -> CommitResult:
        """唯一写路径。返回时锁已释放。有 conflicts → 一个字节都没写。"""
        ops = list(operations or [])
        limit = self._settings.lock_timeout_seconds if timeout is None else float(timeout)

        with self._lock.hold(timeout=limit, purpose="commit"):
            path = self._settings.vault_path
            disk = read_revision(path)
            reloaded = False

            if self._stale_memory or disk != self._vault.revision or reload_policy == "force":
                if reload_policy == "never":
                    raise StaleWrite(
                        f"内存修订是 {self._vault.revision}，盘上已是 {disk}；按 never 策略拒绝写入。"
                    )
                self._vault = self._reload()
                self._stale_memory = False
                reloaded = True

            vault = self._vault

            # 调用方声称「我基于 R 提交」：盘上已经越过 R，且有没有乐观锁的 update，
            # 就无法判断是否会覆盖别人的改动 → 直接拒绝（不静默覆盖）。
            if expected_revision is not None and disk != expected_revision:
                blind = [op for op in ops if op.kind == "update" and not op.expected_updated]
                if blind:
                    raise StaleWrite(
                        f"这次提交基于修订 {expected_revision}，盘上已是 {disk}。"
                    )

            added = updated = deleted = 0
            applied: list[str] = []
            conflicts: list[Conflict] = []
            by_id: dict[str, Record] = {record.id: record for record in vault.records}

            # `finished` 只有在「真的写盘成功」或「确认内存没被动过」时才置 True。
            # 其余所有出口（异常、冲突、净变化为 0 之外的提前 return）都会走 finally
            # 把内存恢复到盘上状态 —— 见 `_restore_from_disk` 与 Q-02 的说明。
            finished = False
            try:
                for op in ops:
                    if op.kind == "add":
                        record = op.record
                        if record is None:
                            continue
                        if record.id in by_id:
                            if op.on_id_conflict == "skip":
                                continue
                            record.id = new_id()
                        vault.records.append(record)
                        by_id[record.id] = record
                        added += 1
                        applied.append(record.id)
                        continue

                    target = by_id.get(op.record_id or "")

                    if op.kind == "update":
                        if target is None:
                            conflicts.append(
                                Conflict(
                                    record_id=op.record_id or "",
                                    kind="deleted",
                                    mine=_public_changes(op.changes or {}),
                                    theirs=None,
                                )
                            )
                            continue
                        if op.expected_updated is not None and target.updated != op.expected_updated:
                            conflicts.append(
                                Conflict(
                                    record_id=target.id,
                                    kind="stale",
                                    mine=_public_changes(op.changes or {}),
                                    theirs=redact_record(target, profile="web"),
                                )
                            )
                            continue
                        target.apply_changes(dict(op.changes or {}))
                        updated += 1
                        applied.append(target.id)
                        continue

                    if op.kind == "delete":
                        if target is None:
                            continue  # 幂等：已经没了就当成功
                        vault.records = [record for record in vault.records if record.id != target.id]
                        by_id.pop(target.id, None)
                        deleted += 1
                        applied.append(target.id)
                        continue

                if conflicts:
                    # 有冲突 → 一个字节都没写，但前面无冲突的 op 已经就地改了内存
                    return CommitResult(
                        revision=disk,
                        conflicts=conflicts,
                        reloaded=reloaded,
                        disk_revision=disk,
                    )

                if added == 0 and updated == 0 and deleted == 0:
                    # 净变化为 0：不空转 bump revision，内存也没被动过
                    finished = True
                    return CommitResult(revision=disk, reloaded=reloaded, disk_revision=disk)

                vault.save(expected_revision=disk)
                new_revision = vault.revision
                self._last_self_revision = new_revision
                finished = True
            finally:
                if not finished:
                    self._restore_from_disk()

        self._emit(disk, new_revision)
        return CommitResult(
            revision=new_revision,
            added=added,
            updated=updated,
            deleted=deleted,
            applied_ids=applied,
            conflicts=[],
            reloaded=reloaded,
            disk_revision=new_revision,
        )

    def mutate(
        self,
        fn: Callable[[Vault], bool],
        *,
        timeout: float | None = None,
        purpose: str = "mutate",
    ) -> CommitResult:
        """读-改-写：锁内 reload → `fn(fresh_vault)` → 写盘。

        `fn` 返回 False 表示「没有实际改动」，此时不写盘（不空转 bump revision）。
        这是 CLI 的 `edit` / `rm` / `import` 与 header 类操作的安全通道。
        """
        limit = self._settings.lock_timeout_seconds if timeout is None else float(timeout)
        with self._lock.hold(timeout=limit, purpose=purpose):
            disk = read_revision(self._settings.vault_path)
            reloaded = False
            if self._stale_memory or disk != self._vault.revision:
                self._vault = self._reload()
                self._stale_memory = False
                reloaded = True

            vault = self._vault
            before = len(vault.records)
            finished = False
            try:
                changed = bool(fn(vault))
                if not changed:
                    # `fn` 返回 False 只表示「它认为没改动」，而它是**就地**改对象的：
                    # 完全可能改了却返回 False（Q-10）。盘上这次什么都没写，所以盘是
                    # 唯一真相 —— 无条件按盘恢复一次。宁可多一次解密，也不要把脏数据
                    # 留给下一次无关的写入悄悄带上盘。
                    self._restore_from_disk()
                    finished = True
                    return CommitResult(revision=disk, reloaded=reloaded, disk_revision=disk)

                vault.save(expected_revision=disk)
                new_revision = vault.revision
                self._last_self_revision = new_revision
                finished = True
            finally:
                if not finished:
                    # fn 就地改了内存却抛了/没写盘 → 丢掉脏改动（Q-02 同一根因）
                    self._restore_from_disk()

        delta = len(self._vault.records) - before
        self._emit(disk, new_revision)
        return CommitResult(
            revision=new_revision,
            added=max(0, delta),
            deleted=max(0, -delta),
            reloaded=reloaded,
            disk_revision=new_revision,
        )

    def mutate_header(
        self,
        fn: Callable[[dict], None],
        *,
        timeout: float | None = None,
    ) -> int:
        """改主密码 / 本机免密 / 恢复码专用：锁内 reload → 改 header → 写盘。

        防止用旧 header 覆盖别人的记录变更（header 里含 payload 密文）。
        """
        limit = self._settings.lock_timeout_seconds if timeout is None else float(timeout)
        with self._lock.hold(timeout=limit, purpose="mutate_header"):
            disk = read_revision(self._settings.vault_path)
            if self._stale_memory or disk != self._vault.revision:
                self._vault = self._reload()
                self._stale_memory = False
            finished = False
            try:
                fn(self._vault.header)
                self._vault.save(expected_revision=disk)
                new_revision = self._vault.revision
                self._last_self_revision = new_revision
                finished = True
            finally:
                if not finished:
                    self._restore_from_disk()

        self._emit(disk, new_revision)
        return new_revision

    # ------------------------------------------------------------- 内部
    def _reload(self) -> Vault:
        return Vault.open_with_dek(
            self._settings,
            self._dek,
            expected_vault_id=self._vault.vault_id,
        )

    def _emit(self, old: int, new: int) -> None:
        """通知 revision 变化。**不 import web**，只调回调。"""
        if self._on_revision is None:
            return
        try:
            self._on_revision(int(old), int(new))
        except Exception:  # noqa: BLE001 - 回调失败绝不能影响已完成的写入
            log_event("revision_callback_failed", level="WARN")


__all__ = [
    "CommitResult",
    "Conflict",
    "LockManager",
    "Operation",
    "VaultStore",
]
