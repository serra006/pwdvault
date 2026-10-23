"""Web 进程的全局状态（L4）：Vault 会话、DEK、空闲自锁、revision 轮询、Agent 探测。

为什么 revision 只能用「2 秒轮询」
---------------------------------
Web 进程与 MCP 进程之间**没有共享内存**，MCP 又是 stdio 子进程（不监听端口），
所以「MCP 写了盘」这件事 Web 侧唯一的观测手段就是看文件。可选方案与结论：

- `watchdog`：第三方依赖，违反「零新增第三方依赖」。
- `ReadDirectoryChangesW`：Windows 上对网盘同步目录（OneDrive/坚果云）误报频繁，
  而且 `os.replace` 的 rename 事件语义不可靠（同一目标会被报成 DELETE+CREATE）。
- 自建 IPC（named pipe / socket）：等于在自己项目里再实现一套分布式系统。

因此就是最笨也最可靠的做法：每 2 秒 `os.stat()` 一次，用 `(mtime_ns, size)` 门控；
门控通过才 `read_revision()` 解析头部，变了就 `store.refresh()` 并推 SSE。
绝大多数 tick 只花一次 syscall。线程纪律：`daemon=True` + `stop_event.wait()`，
绝不用 `time.sleep()`（否则 Ctrl+C 要等满 2 秒）。

安全边界（必须诚实）
--------------------
空闲自锁只是**缩短 DEK 在内存里的时间窗**，不是安全边界。真正的边界是锁屏/关机：
`lock()` 把 DEK 从内存里丢掉，但浏览器里已渲染的明文、以及本仓库其它进程拿到的
明文，都不受它控制。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from ..config import Settings, log_event
from ..errors import Locked, VaultError
from ..inbox import InboxWatcher
from ..locks import LockManager, VaultStore
from ..staging import StagingStore
from ..vault import Vault, read_header, read_revision
from .events import EventBus

#: 空闲自锁默认 900 秒（DESIGN §4.3 `[mcp] auto_lock_seconds`）。
DEFAULT_AUTO_LOCK_SECONDS = 900.0

#: revision 轮询间隔（DESIGN §6.3）。
DEFAULT_POLL_SECONDS = 2.0

#: 空闲检查间隔上限。自锁阈值很小时（测试）会自动收缩，保证 1 秒阈值也能准时锁。
DEFAULT_IDLE_CHECK_SECONDS = 1.0

#: SSE 心跳间隔（DESIGN §3.8：每 15 秒一条注释行）。
DEFAULT_HEARTBEAT_SECONDS = 15.0


class AppState:
    """进程内唯一的 Web 全局状态，被所有 HTTP handler 线程共享。

    线程安全策略：
      - `_guard`（RLock）只保护「解锁/上锁/换 VaultStore」这类状态跃迁，临界区里
        不做 IO（Vault.open 的 KDF 在锁外完成后再一次性换上），避免自锁线程与
        HTTP 线程互相等待时把整个 UI 卡住。
      - `store` / `vault` / `dek` 的读一律先取本地引用再判断，不做「先检查再加锁」。
    """

    def __init__(
        self,
        settings: Settings,
        *,
        token: str = "",
        port: int = 0,
        bus: EventBus | None = None,
        auto_lock_seconds: float | None = None,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        idle_check_seconds: float = DEFAULT_IDLE_CHECK_SECONDS,
        heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
        clock: Callable[[], float] | None = None,
        start_inbox: bool = True,
        staging: StagingStore | None = None,
    ) -> None:
        self.settings = settings
        self.token = str(token or "")
        self.port = int(port or 0)
        self.bus = bus if bus is not None else EventBus()
        self.heartbeat_seconds = max(0.05, float(heartbeat_seconds))

        limit = (
            float(auto_lock_seconds)
            if auto_lock_seconds is not None
            else float(getattr(settings, "mcp_auto_lock_seconds", DEFAULT_AUTO_LOCK_SECONDS))
        )
        self._auto_lock_seconds = max(0.0, limit)
        self._poll_seconds = max(0.05, float(poll_seconds))
        self._idle_check_seconds = max(0.05, float(idle_check_seconds))
        self._clock = clock or time.monotonic
        self._start_inbox = bool(start_inbox)

        self._guard = threading.RLock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started = False

        self._store: VaultStore | None = None
        self._vault: Vault | None = None
        self._dek: bytes | None = None
        self._last_active = self._clock()
        self._last_stat: tuple[int, int] | None = None
        self._own_revision = 0
        self._last_count = 0

        self._lock_manager = LockManager(
            settings.lock_path,
            default_timeout=float(getattr(settings, "lock_timeout_seconds", 3.0)),
            poll_seconds=float(getattr(settings, "lock_poll_seconds", 0.025)),
        )
        # 未解锁时 dek_provider() 返回 None —— 暂存区据此只读墓碑、不建批次。
        self._staging = staging or StagingStore.shared(settings, self._provide_dek)
        self._watcher: InboxWatcher | None = None
        self._watcher_guard = threading.Lock()

    # ------------------------------------------------------------- 只读属性
    @property
    def stop_event(self) -> threading.Event:
        return self._stop

    @property
    def staging(self) -> StagingStore:
        return self._staging

    @property
    def watcher(self) -> InboxWatcher | None:
        return self._watcher

    @property
    def store(self) -> VaultStore | None:
        return self._store

    @property
    def vault(self) -> Vault | None:
        return self._vault

    @property
    def unlocked(self) -> bool:
        return self._store is not None

    @property
    def revision(self) -> int:
        store = self._store
        return int(store.revision()) if store is not None else 0

    @property
    def count(self) -> int:
        vault = self._vault
        return len(vault.records) if vault is not None else 0

    @property
    def auto_lock_seconds(self) -> float:
        return self._auto_lock_seconds

    @property
    def last_active(self) -> float:
        return self._last_active

    # ------------------------------------------------------------- 会话
    def unlock(
        self,
        *,
        password: str | None = None,
        recovery_code: str | None = None,
        use_dpapi: bool = False,
    ) -> VaultStore:
        """解锁并返回 VaultStore。已解锁时幂等返回现有 store。

        三种凭据互斥；`use_dpapi=True` 时**只**走 DPAPI 分支（`allow_dpapi=True`
        且不传密码），不会静默地用别的方式成功 —— 否则 UI 上「用这台电脑进入」
        失败时会莫名其妙地进了库，用户无法理解发生了什么。
        """
        current = self._store
        if current is not None:
            self.touch()
            return current

        started = time.monotonic()
        vault = Vault.open(
            self.settings,
            password=password,
            recovery_code=recovery_code,
            allow_dpapi=bool(use_dpapi),
        )

        store = VaultStore(
            self.settings,
            vault,
            on_revision=self._on_store_revision,
            lock=self._lock_manager,
        )
        with self._guard:
            self._vault = vault
            self._dek = vault.dek
            self._store = store
            self._own_revision = store.revision()
            self._last_count = len(vault.records)
            self._last_stat = self._stat_signature()
            self.touch()

        log_event(
            "unlock",
            scope="pv web",
            method=vault.unlocked_by,
            revision=store.revision(),
            count=self.count,
            ms=int((time.monotonic() - started) * 1000),
        )
        self._ensure_inbox()
        self._publish_session()
        return store

    def lock(self) -> None:
        """丢弃 DEK 与内存 Vault，停掉 inbox 监听，广播 session 事件。幂等。"""
        with self._guard:
            had = self._store is not None
            self._store = None
            self._vault = None
            self._dek = None
            self._last_stat = None
        if not had:
            return
        self._stop_inbox()
        log_event("lock", scope="pv web", reason="manual_or_idle")
        self._publish_session()

    def touch(self) -> None:
        """刷新活跃时间。每个 `/api/*` 请求都会调它。"""
        self._last_active = self._clock()

    def try_vault(self) -> VaultStore | None:
        """有会话就返回 store，否则 None（不抛异常）。"""
        return self._store

    def require_unlocked(self) -> VaultStore:
        """没有会话就抛 `Locked`（HTTP 层翻译成 409 + `code="locked"`）。"""
        store = self._store
        if store is None:
            raise Locked()
        return store

    def idle_seconds(self) -> int:
        return int(max(0.0, self._clock() - self._last_active))

    def auto_lock_in_seconds(self) -> int:
        """距离空闲自锁还剩多少秒。`auto_lock_seconds<=0` 表示永不自动锁。"""
        if self._auto_lock_seconds <= 0:
            return -1
        return int(max(0.0, self._auto_lock_seconds - (self._clock() - self._last_active)))

    def agent_status(self) -> str:
        """Agent（MCP 进程）连接状态。

        TODO(P1)：现在没有可靠的观测手段 —— `runtime.json` 是本进程自己写的，
        读它只能证明「Web 在跑」，不能证明「MCP 在跑」。用「最近 N 秒内是否有 MCP
        握手」也需要 MCP 侧写一份独立心跳（P1 的代理模式才有握手）。在那之前
        诚实地返回 `"unknown"`，前端显示「Agent 状态未知」而不是伪造「未运行」。
        """
        return "unknown"

    def inbox_status(self) -> dict | None:
        watcher = self._watcher
        if watcher is None:
            return None
        try:
            return watcher.status()
        except Exception:  # noqa: BLE001 - 状态查询失败不影响会话返回
            return None

    def session_payload(self) -> dict:
        """`GET /api/session` 的响应体（键名与 SSE `session` 事件一致）。"""
        summary = self._header_summary()
        payload: dict[str, Any] = {
            "unlocked": self.unlocked,
            "revision": self.revision,
            "count": self.count,
            "auto_lock_seconds": int(self._auto_lock_seconds),
            "auto_lock_in_seconds": self.auto_lock_in_seconds(),
            "agent": self.agent_status(),
            "port": self.port,
            "vault_exists": summary["vault_exists"],
            "label": summary["label"],
            "methods": summary["methods"],
            "inbox": self.inbox_status(),
        }
        try:
            payload["staging_pending"] = int(self._staging.inbox_pending())
        except Exception:  # noqa: BLE001 - 徽标数字失败不能连累会话
            payload["staging_pending"] = 0
        return payload

    # ------------------------------------------------------------- 后台线程
    def start_background(self, *, port: int | None = None) -> None:
        """起两个 daemon 线程（revision 轮询 / 空闲自锁）。幂等。"""
        if port is not None:
            self.port = int(port)
        if self._started:
            return
        self._started = True
        self._stop.clear()
        for target, name in (
            (self._revision_loop, "pv-web-revision"),
            (self._idle_loop, "pv-web-idle"),
        ):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)

    def close(self) -> None:
        """停止后台线程、停 inbox、丢弃 DEK、关闭事件总线。幂等，最多等 2 秒。"""
        self._stop.set()
        for thread in list(self._threads):
            thread.join(timeout=1.0)
        self._threads.clear()
        self._stop_inbox()
        with self._guard:
            # 进程退出前主动丢掉 DEK 与内存记录，缩短明文的存活时间
            self._store = None
            self._vault = None
            self._dek = None
        self.bus.close()

    def _revision_loop(self) -> None:
        while not self._stop.wait(self._poll_seconds):
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - 轮询线程绝不能被异常杀死
                log_event(
                    "revision_poll_failed",
                    scope="pv web",
                    level="WARN",
                    code=type(exc).__name__,
                )

    def _idle_loop(self) -> None:
        # 阈值很小时（测试/自定义配置）把检查间隔一起收缩，否则 1 秒阈值要等 1 秒才生效
        interval = self._idle_check_seconds
        if self._auto_lock_seconds > 0:
            interval = min(interval, max(0.05, self._auto_lock_seconds / 4.0))
        while not self._stop.wait(interval):
            try:
                self.lock_if_idle()
            except Exception as exc:  # noqa: BLE001
                log_event(
                    "idle_check_failed",
                    scope="pv web",
                    level="WARN",
                    code=type(exc).__name__,
                )

    def poll_once(self) -> int:
        """比一次盘上 revision；有变化就 reload 并推 SSE。返回新 revision（无变化返回 0）。

        测试直接调它，不依赖线程时序。
        """
        store = self._store
        if store is None:
            return 0

        signature = self._stat_signature()
        if signature is not None and signature == self._last_stat:
            return 0
        self._last_stat = signature

        try:
            disk = read_revision(self.settings.vault_path)
        except VaultError as exc:
            log_event("revision_read_failed", scope="pv web", level="WARN", code=exc.code)
            return 0

        if disk == store.revision():
            return 0

        before_count = len(store.vault.records)
        try:
            reloaded = store.refresh()
        except Exception as exc:  # noqa: BLE001 - refresh 内部已捕获 VaultError，这里兜底
            log_event("revision_refresh_failed", scope="pv web", level="WARN", code=type(exc).__name__)
            return 0
        if not reloaded:
            return 0

        with self._guard:
            self._vault = store.vault
            after_count = len(store.vault.records)
            self._last_count = after_count
        source = "ui" if disk == self._own_revision else "agent"
        self.bus.publish(
            "revision",
            {
                "revision": disk,
                "count": after_count,
                "delta": after_count - before_count,
                "source": source,
                "reloaded": True,
            },
        )
        log_event(
            "revision_reloaded",
            scope="pv web",
            revision=disk,
            count=after_count,
            source=source,
        )
        return disk

    def lock_if_idle(self) -> bool:
        """空闲超过阈值就上锁。返回是否真的锁了。测试可同步调用。"""
        if self._store is None or self._auto_lock_seconds <= 0:
            return False
        if (self._clock() - self._last_active) < self._auto_lock_seconds:
            return False
        log_event("auto_lock", scope="pv web", idle=self.idle_seconds())
        self.lock()
        return True

    # ------------------------------------------------------------- 内部
    def _provide_dek(self) -> bytes | None:
        """暂存区的 DEK 提供者：未解锁时返回 None（Design §3.3）。"""
        return self._dek

    def _stat_signature(self) -> tuple[int, int] | None:
        try:
            st = self.settings.vault_path.stat()
        except OSError:
            return None
        return (int(st.st_mtime_ns), int(st.st_size))

    def _header_summary(self) -> dict:
        """不解锁就读头部：解锁视图需要知道「库在不在、有没有本机免密」。"""
        try:
            header = read_header(self.settings.vault_path)
        except VaultError:
            return {
                "vault_exists": self.settings.vault_path.exists(),
                "label": "",
                "methods": [],
            }
        return {
            "vault_exists": True,
            "label": str(header.get("label") or ""),
            "methods": sorted((header.get("wraps") or {}).keys()),
        }

    def _on_store_revision(self, old: int, new: int) -> None:
        """VaultStore 写盘成功后的回调（本进程写的 → source="ui"）。"""
        store = self._store
        count = len(store.vault.records) if store is not None else self._last_count
        with self._guard:
            delta = count - self._last_count
            self._last_count = count
            self._own_revision = int(new)
            if store is not None:
                self._vault = store.vault
            self._last_stat = self._stat_signature()
        self.bus.publish(
            "revision",
            {
                "revision": int(new),
                "count": count,
                "delta": delta,
                "source": "ui",
                "reloaded": False,
            },
        )
        log_event("revision", scope="pv web", revision=f"{old}->{new}", count=count)

    def _on_inbox_event(self, event: str, data: dict) -> None:
        """InboxWatcher 的回调：原样广播（事件名由 inbox 决定，目前是 staging）。"""
        self.bus.publish(event, data)

    def _ensure_inbox(self) -> None:
        """惰性启动 inbox 监听：只有解锁后才建（建批次需要 DEK）。"""
        if not self._start_inbox or not self.unlocked:
            return
        if not bool(getattr(self.settings, "inbox_enabled", True)):
            return
        with self._watcher_guard:
            if self._watcher is not None:
                return
            watcher = InboxWatcher(self.settings, self._staging, on_event=self._on_inbox_event)
            watcher.start()
            self._watcher = watcher
        log_event("inbox_started", scope="pv web", path=self.settings.inbox_path)

    def _stop_inbox(self) -> None:
        with self._watcher_guard:
            watcher = self._watcher
            self._watcher = None
        if watcher is None:
            return
        try:
            watcher.stop(timeout=1.0)
        except Exception:  # noqa: BLE001 - 停止失败不影响退出
            pass

    def _publish_session(self) -> None:
        try:
            payload = self.session_payload()
        except Exception:  # noqa: BLE001
            payload = {"unlocked": self.unlocked, "revision": self.revision, "count": self.count}
        self.bus.publish("session", payload)


__all__ = [
    "AppState",
    "DEFAULT_AUTO_LOCK_SECONDS",
    "DEFAULT_HEARTBEAT_SECONDS",
    "DEFAULT_IDLE_CHECK_SECONDS",
    "DEFAULT_POLL_SECONDS",
]
