"""inbox 目录监听：2 秒轮询 + 三重去重 + 墓碑 + processed 归档 + 干净停止。

为什么是「轮询」而不是 watchdog/IPC：
  - `watchdog` 是第三方依赖（本迭代零新增依赖）；
  - 自建 IPC 要处理连接、重连、对方不在，代码量与故障面都比问题本身大。

为什么去重要三重（缺一个就会重复建批次）：
  1. `tombstones`      —— 用户丢弃过的文件永不打扰；
  2. `batches_by_hash` —— **进程重启后**同一个文件不能再建一批（内存集合在这里是瞎的）；
  3. `self._seen`      —— 本轮会话内已经建过批的。

线程纪律：`daemon=True`、`stop_event.wait(interval)`（不是 `time.sleep`）、
内部异常全捕获（静默失去功能比崩溃更难查）。
"""

from __future__ import annotations

import hashlib
import threading
from typing import Callable

from . import importers
from .config import Settings, log_event
from .errors import VaultError
from .models import now_iso
from .staging import StagingStore

INBOX_SUFFIXES = frozenset({".txt", ".md", ".csv", ".tsv", ".json", ".log", ".dat", ".ini"})
DEFAULT_INTERVAL = 2.0
BACKOFF_INTERVAL = 10.0
BACKOFF_AFTER_ERRORS = 5


def decode_bytes(data: bytes) -> str:
    """逐级回退解码：utf-8 → utf-8-sig → gbk → latin-1。**永远不抛异常**。"""
    for encoding in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


class InboxWatcher:
    """inbox 目录的单线程监听器。`scan_once()` 供测试同步调用，不依赖线程时序。"""

    def __init__(
        self,
        settings: Settings,
        staging: StagingStore,
        *,
        on_event: Callable[[str, dict], None] | None = None,
        interval: float | None = None,
    ) -> None:
        self._settings = settings
        self._staging = staging
        self._on_event = on_event
        self._base_interval = float(
            interval if interval is not None else getattr(settings, "inbox_interval_seconds", DEFAULT_INTERVAL)
        )
        self._stop = threading.Event()
        self._guard = threading.Lock()
        self._thread: threading.Thread | None = None
        self._seen: set[str] = set()
        self._sigs: dict[str, tuple[int, int]] = {}
        self._last_mtime_ns = 0
        self._last_scan: str | None = None
        self._pending = 0
        self._oversize = 0
        self._errors = 0
        self._consecutive_errors = 0

    # ------------------------------------------------------------- 生命周期
    def start(self) -> None:
        """只起一个线程（幂等）。"""
        with self._guard:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="pv-inbox", daemon=True)
            self._thread.start()

    def stop(self, *, timeout: float = 3.0) -> None:
        """干净停止：`stop_event.wait()` 会让循环立刻退出，不用等满一个周期。"""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():  # pragma: no cover - daemon 会被进程带走
                log_event("inbox_stop_timeout", scope="pv", level="WARN")
        self._thread = None

    def _loop(self) -> None:
        interval = self._base_interval
        while not self._stop.wait(interval):
            try:
                self.scan_once()
                self._consecutive_errors = 0
                interval = self._base_interval
            except Exception as exc:  # noqa: BLE001 - 绝不让异常杀死监听线程
                self._consecutive_errors += 1
                self._errors += 1
                log_event(
                    "inbox_tick_failed",
                    scope="pv",
                    level="ERROR",
                    code=type(exc).__name__,
                )
                if self._consecutive_errors >= BACKOFF_AFTER_ERRORS:
                    interval = max(interval, BACKOFF_INTERVAL)

    # ------------------------------------------------------------- 扫描
    def scan_once(self) -> list[str]:
        """同步扫一遍，返回**新建**的 batch_id 列表。幂等：同一个文件只建一批。"""
        created: list[str] = []
        inbox = self._settings.inbox_path
        if not inbox.is_dir():
            self._last_scan = now_iso()
            self._pending = 0
            return created

        max_bytes = int(getattr(self._settings, "inbox_max_file_bytes", 2 * 1024 * 1024))
        tombstones = self._staging.seen_hashes()
        known = self._staging.batches_by_hash()
        pending = 0

        try:
            entries = sorted(path for path in inbox.iterdir() if path.is_file())
        except OSError:
            entries = []

        for path in entries:
            if path.suffix.lower() not in INBOX_SUFFIXES:
                continue
            key = str(path)
            try:
                stat = path.stat()
            except OSError:
                continue
            if max_bytes and stat.st_size > max_bytes:
                # 超大文件不建批次、不报错，只在 status 里计数（UI 会显示）
                self._oversize += 1
                self._sigs[key] = (stat.st_size, stat.st_mtime_ns, "")
                continue

            signature = (stat.st_size, stat.st_mtime_ns)

            # 为什么每轮都要读全文算 sha256（Q-06）：
            # size+mtime 不是内容的可靠代理 —— `cp -p` / 某些同步与还原工具会保留
            # mtime，于是「内容换了但大小与 mtime 都没变」的文件会被旧实现**永久**
            # 静默跳过（用户看不到任何报错）。判重依据本来就是 sha256，那就让
            # sha256 成为唯一的判据；`_sigs` 只承担「这个 digest 已经解析/建批过，
            # 不必再走一遍解析与建批」的缓存职责，不再扮演「跳过读取」的捷径。
            # 代价可接受：inbox 是丢弃目录，单文件上限 2MB、数量级通常是几十个。
            try:
                data = path.read_bytes()
            except OSError:
                continue

            digest = hashlib.sha256(data).hexdigest()
            self._last_mtime_ns = max(self._last_mtime_ns, stat.st_mtime_ns)

            cached = self._sigs.get(key)
            if cached is not None and cached[2] == digest:
                continue  # 内容确实没变（digest 才算数）

            # 墓碑 = 「用户说过这一份不要了，别再来烦我」（DESIGN §4.4 / T04 验收 ③）。
            # 只要 sha256 在墓碑里就跳过，不看时刻 —— 源文件往往还留在 inbox 里，
            # 2 秒一轮的扫描必须对它保持安静。
            if digest in tombstones or digest in known or digest in self._seen:
                self._sigs[key] = (signature[0], signature[1], digest)
                continue

            if not self._staging.has_dek():
                # 未解锁：本轮不建批次，只在 status 里暴露 pending，解锁后下一 tick 补上
                pending += 1
                continue

            text = decode_bytes(data)
            notes: list[tuple[int, str]] = []
            try:
                drafts = importers.parse_any(
                    text,
                    filename=path.name,
                    source_name=path.name,
                    notes=notes,
                )
            except VaultError:
                drafts = []  # 解析不出来 → failed 批次（UI 给「手动新建」出口）
            except Exception as exc:  # noqa: BLE001 - 解析器再怪也不能让监听线程死
                log_event("inbox_parse_failed", scope="pv", level="WARN", code=type(exc).__name__)
                drafts = []

            try:
                batch = self._staging.create_from_file(
                    path=path,
                    text=text,
                    drafts=drafts,
                    notes=notes,
                    origin="local",
                    dedupe_index=known,
                )
            except VaultError as exc:
                # 例如「刚检查完 DEK，用户就锁了库」：不建批次，下一轮再试
                log_event("inbox_create_failed", scope="pv", level="WARN", code=exc.code)
                pending += 1
                continue
            self._seen.add(digest)
            self._sigs[key] = (signature[0], signature[1], digest)
            if batch.deduped:
                # 另一个进程刚建过同一份内容的批次（Q-05 的锁内二次确认命中）：
                # 只把它记成「已见」，不要再算作本进程新建，也不要重复发事件。
                log_event("inbox_deduped", scope="pv", id=batch.batch_id)
                continue

            created.append(batch.batch_id)
            self._emit(
                "staging",
                {
                    "batch_id": batch.batch_id,
                    "status": batch.status,
                    "item_count": batch.item_count or len(batch.items),
                    "origin": batch.origin,
                    "updated": batch.updated,
                },
            )

        self._pending = pending
        self._last_scan = now_iso()
        return created

    def _emit(self, event: str, data: dict) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(event, data)
        except Exception:  # noqa: BLE001 - 回调失败不影响扫描
            log_event("inbox_callback_failed", scope="pv", level="WARN")

    # ------------------------------------------------------------- 状态
    def status(self) -> dict:
        thread = self._thread
        return {
            "watching": bool(thread is not None and thread.is_alive()),
            "dir": str(self._settings.inbox_path),
            "interval": self._base_interval,
            "last_scan": self._last_scan,
            "pending": self._pending,
            "oversize": self._oversize,
            "error_count": self._errors,
        }


__all__ = ["INBOX_SUFFIXES", "InboxWatcher", "decode_bytes"]
