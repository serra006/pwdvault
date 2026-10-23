"""MCP 工具层（L4）：工具定义（schema）、参数校验、handler、解锁链。

分层与依赖方向
--------------
    mcp_server.py（L5，只懂 JSON-RPC 与帧）  ──>  mcp_tools.py（L4，懂业务）
    mcp_tools.py                             ──>  service / vault / redact / staging

本文件**不得**被任何下层 import（它是 L4，只允许向上被 `mcp_server` 与 `cli` 使用）。

三条不可谈判的硬约束
--------------------
1. **唯一脱敏出口**：任何进入响应的记录数据都必须由 `redact.redact_record()` 产生。
   本文件里不允许把 `Record` 序列化成 dict 再手工删字段，也不允许把 `Record` 的
   password 属性直接塞进响应 dict —— `tests/test_mcp_tools.py` 用**源码级断言**
   守住这一条（断言本文件里不出现那两种写法）。
2. **明文不出进程**：`vault_copy` 只返回回执（`copied/title/field/auto_clear_in/host`），
   明文只作为 `service.copy_field()` 内的局部变量存在，取完摘要立刻 `del`。
   回执里的 `auto_clear_in` **只在定时器真的装上时才出现**，装不上就明说
   `auto_clear=false` 并给 `hint`（v1.0 的缺陷就是回执硬写 30 秒）。
3. **绝不交互式读密码**：stdio 的 stdin 属于协议通道。任何 `input()` / `getpass()`
   都会把提示写进 stdout（毁掉协议）并吞掉下一条 JSON-RPC 消息。解锁链只有
   DPAPI → `PV_MASTER_PASSWORD` 两条，都不行就返回 `locked`。

T07 新增的 5 个工具（批量整理 + 单条写入）
------------------------------------------
`vault_staging_list` / `vault_staging_claim` / `vault_staging_submit` 是「Agent 归纳、
人确认、人入库」三段式的中间两段：Agent 能认领批次、能交回草稿，但**没有落库权限**
（`vault_staging_commit` 根本不存在，调它就是 -32602 Unknown tool）。
`vault_add` / `vault_update` 是单条写入：新增默认 `dry_run=true`（绝不写库），
更新必须带 `expected_updated` 乐观锁（过期就 `record_conflict`，一个字节都不覆盖）。

所有写操作都会向 `audit.py` 记一行「谁对哪个 id 的哪个字段做了什么」，
**永远不含字段值**。

错误语义
--------
- 业务错误（未解锁 / 歧义 / 未找到 / 无此字段 / 批次忙 / 记录冲突）→ `VaultError` 派生，
  由 `call_tool()` 翻译成 `isError=true` 的**正常 result**，`code` 原样复用
  `errors.py` 的 `VaultError.code`（CLI 与 MCP 同一套错误语汇）。
- 协议错误（未知工具 / 参数不合法）→ `ToolError` 派生，由 `mcp_server`
  映射成 JSON-RPC `-32602`。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from . import audit, service
from .config import Settings, log_event
from .errors import (
    AmbiguousRecord,
    AuthenticationFailed,
    CorruptVault,
    DpapiUnavailable,
    InvalidRecord,
    Locked,
    RecordNotFound,
    StagingBusy,
    StagingNotFound,
    VaultError,
    VaultNotFound,
)
from .locks import Operation, VaultStore
from .models import Record, now_iso
from .redact import public_error, redact_record
from .runtime import ProxyBackend, is_alive, read_runtime
from .staging import StagingStore
from .vault import Vault, read_header, read_revision

# 环境变量名：与 cli.py 保持一致（cli 属 L7，L4 不能 import 它，所以常量各写一份）
ENV_MASTER_PASSWORD = "PV_MASTER_PASSWORD"

LOCKED_HINT = "先运行 pv local-unlock on 启用本机免密；只在 Web 界面解锁不会让这里能用。"
LOCKED_MESSAGE = "密码库现在是锁着的。"

# `record.id` 长度与形态（供错误提示与候选列表使用，不是校验规则）
CANDIDATE_LIMIT = 5
SEARCH_LIMIT_DEFAULT = 10
SEARCH_LIMIT_MAX = 50

# --------------------------------------------------------------------- T07 常量
# 认领者的固定身份：staging.py 的租约按 holder 比对，MCP 只有一个「Agent」身份
AGENT_HOLDER = "agent"
# 暂存列表一次最多回多少批（Agent 不需要全量，列表还会随时间增长）
STAGING_LIST_LIMIT = 50
DEFAULT_LEASE_SECONDS = 180
MAX_LEASE_SECONDS = 600
# `vault_update` 一次最多改多少个字段（多字段混改容易把人工确认变成赌博）
MAX_CHANGES = 32
# 这些键**不允许**被 `vault_update` 改写：id/时间戳是系统字段，meta 是来源标记，
# 让调用方改等于允许伪造「这是 web 写的」。
FORBIDDEN_CHANGE_KEYS = frozenset({"id", "created", "updated", "pw_changed", "meta"})


# --------------------------------------------------------------------- 协议错误
class ToolError(Exception):
    """工具名或参数不合法 —— 属于 JSON-RPC 协议错误（映射为 -32602）。"""


class UnknownTool(ToolError):
    """`tools/call` 里点了不存在的工具。"""


class InvalidArguments(ToolError):
    """参数不满足 `inputSchema`。"""


class AmbiguousRecords(AmbiguousRecord):
    """多条命中。

    继承 `AmbiguousRecord`（业务错误码 `ambiguous_record`），额外带上
    **已脱敏**的候选列表，让 Agent 能把不确定性还给用户而不是猜。
    候选只含 `{id,title,username}`，永远不含任何字段值。
    """

    def __init__(self, ref: str, records: list[Record]) -> None:
        candidates = [_candidate(record) for record in records[:CANDIDATE_LIMIT]]
        super().__init__(ref, [f"{item['title']}({item['id']})" for item in candidates])
        self.candidates = candidates


# --------------------------------------------------------------------- 结果体
@dataclass(frozen=True)
class ToolOutcome:
    """一次工具调用的结果：`payload` 进 `structuredContent`，`is_error` 进 `isError`。"""

    payload: dict
    is_error: bool = False


# --------------------------------------------------------------------- 摘要投影
# 搜索结果的键集合（PRD §7.2）。**显式白名单**而不是「从脱敏结果里删几个键」：
# 将来 redact 加了新键，也不会自动流进搜索列表。
SUMMARY_KEYS = (
    "id",
    "title",
    "username",
    "url",
    "tags",
    "has_password",
    "has_totp",
    "secret_field_names",
    "updated",
)

# 复制回执的键集合（白名单硬投影）。**故意是 7 键的并集**：回执只有两种互斥形态 ——
# 定时器真的装上时给 `{copied,title,field,auto_clear_in,host}`（v1.0 的 5 键契约），
# 装不上时给 `{copied,title,field,auto_clear:false,host,hint}`。见 `_copy_receipt()`。
COPY_KEYS = ("copied", "title", "field", "auto_clear", "auto_clear_in", "host", "hint")

# 暂存草稿的外形（严格白名单：不含 password / totp 的值，只给「有没有」）
DRAFT_KEYS = (
    "id",
    "title",
    "username",
    "url",
    "tags",
    "notes",
    "has_password",
    "has_totp",
    "secret_field_names",
    "fields",
)


def _candidate(record: Record) -> dict:
    """歧义候选：只有定位信息，没有值。"""
    safe = redact_record(record, profile="agent")
    return {"id": safe["id"], "title": safe["title"], "username": safe["username"]}


def _summary(record: Record) -> dict:
    """搜索结果单条：从脱敏结果里投影白名单键（不含 notes、不含任何值）。"""
    safe = redact_record(record, profile="agent")
    return {key: safe[key] for key in SUMMARY_KEYS}


def _copy_receipt(receipt: dict) -> dict:
    """把 `service.copy_field()` 的回执投影成两个互斥形态之一。

    - 定时器真的装上 → `{copied, title, field, auto_clear_in, host}`（旧契约不变）
    - 没装上         → `{copied, title, field, auto_clear: false, host, hint}`

    这样 Agent 不可能从回执里读出一个「其实不存在的 30 秒」。
    """
    if receipt.get("auto_clear"):
        keys = ("copied", "title", "field", "auto_clear_in", "host")
    else:
        keys = ("copied", "title", "field", "auto_clear", "host", "hint")
    return {key: receipt[key] for key in keys if key in receipt}


def _draft_view(item: Any) -> dict:
    """一条暂存草稿的对外形态：走 `redact_record(profile="agent")` 再投影白名单。

    密码与 TOTP 的值在这里恒为掩码（甚至不出现），Agent 想核对原文请读 `raw_text`。
    """
    safe = redact_record(item.draft, profile="agent")
    view = {key: safe[key] for key in DRAFT_KEYS if key in safe}
    view["item_id"] = str(getattr(item, "item_id", ""))
    view["accepted"] = bool(getattr(item, "accepted", True))
    view["has_error"] = bool(getattr(item, "has_error", False))
    view["warnings"] = [warning.to_dict() for warning in (getattr(item, "warnings", None) or [])]
    return view


def _warning_rows(item: Any) -> list[dict]:
    """单条的警告列表（`Warning.message` 里只有字段名与规则，绝无字段值）。"""
    rows: list[dict] = []
    for warning in getattr(item, "warnings", None) or []:
        row = warning.to_dict()
        row["item_id"] = str(getattr(item, "item_id", ""))
        rows.append(row)
    return rows


def _age_seconds(stamp: str) -> int:
    """`created` 时间戳到今天多少秒（解析失败按 0 处理，不抛异常）。"""
    text = str(stamp or "")
    if not text:
        return 0
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return 0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - moment).total_seconds()))


# --------------------------------------------------------------------- 会话
class McpSession:
    """一个 MCP stdio 进程的解锁状态。

    设计要点：
      1. `Vault` **不缓存在调用方**：每次都走 `require_vault()` 现取。reload 之后
         旧 `Vault` 对象是过期快照，拿它做判断会读到已删除的记录。
         本类只持有「本进程的解锁结果」，不持有业务快照。
      2. `last_call` 供空闲自锁使用：解锁后如果超过 `mcp_auto_lock_seconds` 没有任何
         工具调用，下一次调用开始时先丢掉 DEK，再重新走解锁链。时钟可注入，
         测试用小阈值（如 0.05 秒）验证，**不需要真 sleep**。
      3. `try_vault()` 与 `require_vault()` 的区别是「失败是否抛异常」：
         状态工具要能在锁着的时候回答，所以它用前者。
    """

    def __init__(
        self,
        settings: Settings,
        *,
        vault: Vault | None = None,
        unlocked_by: str = "",
        clock: Callable[[], float] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._unlocked_by = unlocked_by or ("preopened" if vault is not None else "")
        self._clock = clock or time.time
        self._env = env if env is not None else os.environ
        self._staging: StagingStore | None = None
        self.last_call = 0.0
        # 空闲自锁发生过几次（测试/诊断用，不含任何业务数据）
        self.auto_lock_count = 0

    # ---------------------------------------------------------- 只读属性
    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def vault(self) -> Vault | None:
        """当前已解锁的 Vault（可能为 None）。调用方**不得**长期持有它。"""
        return self._vault

    @property
    def unlocked_by(self) -> str:
        """`dpapi` / `env` / `proxy` / `preopened`，未解锁为空串。"""
        return self._unlocked_by

    def now(self) -> float:
        """当前时间（秒）。可注入 —— 测试里禁止真 `sleep`，TOTP 用它做确定性断言。"""
        return float(self._clock())

    @property
    def auto_lock_seconds(self) -> float:
        """空闲自锁阈值（秒）。配错/缺失按 0 = 不自锁处理，绝不因此报错。"""
        try:
            return max(0.0, float(getattr(self._settings, "mcp_auto_lock_seconds", 0) or 0))
        except (TypeError, ValueError):
            return 0.0

    def idle_seconds(self) -> float:
        """距离上一次工具调用过了多久（还没调用过则为 0）。"""
        if self.last_call <= 0.0:
            return 0.0
        return max(0.0, self.now() - self.last_call)

    def auto_lock_in_seconds(self) -> int:
        """还差几秒自动上锁（已锁着时返回完整阈值），供 `vault_status` 如实上报。"""
        limit = self.auto_lock_seconds
        if self._vault is None:
            return int(limit)
        return int(max(0.0, limit - self.idle_seconds()))

    # ---------------------------------------------------------- 生命周期
    def begin_call(self) -> None:
        """每次工具调用的统一入口钩子：先判空闲自锁，再记时间戳。

        顺序很重要：**先 drop 再记时间**。否则解锁失败的调用也会把时间戳推进，
        下一次调用就又要等满一整个阈值才重试。
        """
        now = self.now()
        limit = self.auto_lock_seconds
        if self._vault is not None and self.last_call > 0.0 and limit > 0 and (now - self.last_call) >= limit:
            self.drop()
            self.auto_lock_count += 1
            log_event("auto_lock", scope="pv mcp", code="idle")
        self.last_call = now

    def drop(self) -> None:
        """丢弃解锁状态（进程退出或空闲自锁时调用）。"""
        self._vault = None
        self._unlocked_by = ""
        self.last_call = 0.0

    def adopt(self, vault: Vault) -> None:
        """写库之后把 store 里那份最新的 Vault 接过来，避免继续读过期快照。"""
        if vault is None:  # pragma: no cover - 防御性
            return
        self._vault = vault
        if not self._unlocked_by:
            self._unlocked_by = "preopened"

    def dek_or_none(self) -> bytes | None:
        vault = self._vault
        return vault.dek if vault is not None else None

    def staging(self) -> StagingStore:
        """暂存区单例（按 staging 目录缓存）。未解锁时只读元数据。"""
        if self._staging is None:
            self._staging = StagingStore.shared(self._settings, self.dek_or_none, clock=None)
        return self._staging

    # ---------------------------------------------------------- 解锁
    def require_vault(self) -> Vault:
        """拿到已解锁的 Vault；拿不到抛 `Locked`（业务错误，不是协议错误）。"""
        if self._vault is not None:
            return self._vault
        vault, how = unlock_chain(self._settings, env=self._env)
        self._vault = vault
        self._unlocked_by = how
        return vault

    def try_vault(self) -> Vault | None:
        """尽力解锁但不抛异常（状态工具用）。"""
        try:
            return self.require_vault()
        except VaultError:
            return None


# --------------------------------------------------------------------- 解锁链
def unlock_chain(
    settings: Settings,
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[Vault, str]:
    """按 P1 代理 → 「库不存在」→ DPAPI 本机免密 → 环境变量 → 放弃 的顺序解锁。

    返回 `(vault, 解锁方式)`；全部失败抛 `Locked`（库文件不存在抛 `VaultNotFound`，
    文件损坏抛 `CorruptVault` —— 三种情况给用户的话术完全不同，不能混成一个）。

    为什么这里没有第三档「交互输入主密码」：stdio 下 stdin 是协议通道，
    读它既会毁掉协议、又会让用户看到一个永远等不到输入的提示。所以
    `pv mcp` 的用户前提是「已启用本机免密」或「客户端配置里写了环境变量」。
    """
    environ = env if env is not None else os.environ

    # 1) P1 代理：Web 进程在跑就把调用转发过去（单写者、单份 DEK）
    info = read_runtime(settings.home)
    if info and getattr(settings, "mcp_proxy", True) and is_alive(info.get("pid")):
        try:
            return ProxyBackend(info).open(settings), "proxy"
        except NotImplementedError:
            # 本迭代故意不实现；只需静默落到下一条，不能让用户看到工具报错
            pass

    # 2) 库文件不存在：报「没有库」比报「锁着」诚实 —— 用户根本没有可解锁的东西
    if not settings.vault_path.exists():
        raise VaultNotFound(str(settings.vault_path))

    # 3) 本机免密（DPAPI）：只有头部真的带 dpapi 包裹才尝试，避免无谓的 KDF
    wraps: dict = {}
    try:
        wraps = read_header(settings.vault_path).get("wraps") or {}
    except CorruptVault:
        # 头部都读不出来 → 如实报损坏，不要伪装成「锁着」让用户去猜密码
        raise
    except VaultError:
        wraps = {}
    if "dpapi" in wraps:
        try:
            return Vault.open(settings, allow_dpapi=True), "dpapi"
        except (AuthenticationFailed, DpapiUnavailable):
            # DPAPI 包裹可能是「换了机器/改了用户」留下的死数据 —— 落到下一档
            pass
        except CorruptVault:
            # 文件本身坏了：必须如实报出来，不能伪装成「锁着」
            raise

    # 4) 环境变量（客户端配置里可以写 PV_MASTER_PASSWORD）
    password = environ.get(ENV_MASTER_PASSWORD) or ""
    if password:
        try:
            return Vault.open(settings, password=str(password)), "env"
        except AuthenticationFailed as exc:
            raise Locked(
                "主密码库现在是锁着的：环境变量里的主密码不正确。",
                hint=(
                    "环境变量里的主密码不对。检查客户端配置里的 PV_MASTER_PASSWORD，"
                    "或改用 pv local-unlock on 启用本机免密。"
                ),
            ) from exc

    # 5) 放弃：不猜、不交互
    raise Locked(LOCKED_MESSAGE, hint=LOCKED_HINT)


# --------------------------------------------------------------------- 定位
def _locate(session: McpSession, arguments: dict) -> tuple[Record, str | None]:
    """按 `id`（优先）或 `query` 定位唯一一条记录。

    返回 `(record, note)`。`note` 只在「两个都给了」时非空，用来告诉 Agent
    「你说的是 id，query 我看了一眼没用上」—— 静默忽略参数会让模型以为
    自己的 query 生效了，出错时无从排查。
    """
    vault = session.require_vault()

    raw_id = arguments.get("id")
    raw_query = arguments.get("query")
    record_id = str(raw_id).strip() if raw_id is not None else ""
    query = str(raw_query).strip() if raw_query is not None else ""

    if record_id:
        record = vault.find_by_id(record_id)
        if record is None:
            raise RecordNotFound(record_id)
        note = "已按 id 定位；同时给出的 query 被忽略。" if query else None
        return record, note

    if not query:
        # schema 层的 anyOf 已经拦过，走到这里是调用方绕过了校验
        raise InvalidArguments("missing one of id/query")

    matches = service.search(vault, query, limit=SEARCH_LIMIT_MAX)
    if not matches:
        raise RecordNotFound(query)
    if len(matches) > 1:
        raise AmbiguousRecords(query, matches)
    return matches[0], None


# --------------------------------------------------------------------- 工具实现
def tool_vault_status(session: McpSession, arguments: dict) -> dict:
    """库的现状。**永远不会失败**：锁着/未创建都要能回答。"""
    del arguments  # 该工具没有入参
    settings = session.settings
    exists = settings.vault_path.exists()

    revision = 0
    if exists:
        try:
            revision = read_revision(settings.vault_path)
        except VaultError:
            revision = 0

    vault = session.try_vault() if exists else None
    payload: dict = {
        "exists": bool(exists),
        "unlocked": vault is not None,
        "revision": int(revision),
        "count": len(vault.records) if vault is not None else 0,
        "auto_lock_in_seconds": session.auto_lock_in_seconds(),
        "pending_staging": _pending_staging(session),
        "inbox_pending": _inbox_pending(session),
        "last_snapshot_age_days": _snapshot_age_days(settings),
        "unlocked_by": session.unlocked_by or None,
    }
    if not exists:
        payload["hint"] = "还没有创建密码库：先运行 pv init。"
    elif vault is None:
        # 「在 Web 界面解锁」对 MCP 进程**没有帮助**（两个进程各有各的 DEK），
        # 所以这里只提本机免密，别再给用户一条走不通的路。
        payload["hint"] = (
            "库是锁着的。要读密码请先启用本机免密（pv local-unlock on）；"
            "只在 Web 界面解锁不会让 MCP 进程可读。"
        )
    return payload


def tool_vault_search(session: McpSession, arguments: dict) -> dict:
    """按关键词找记录，只返回定位信息（永远不含值）。"""
    vault = session.require_vault()
    query = str(arguments.get("query") or "").strip()
    if not query:
        raise InvalidArguments("query 不能为空")
    limit = int(arguments.get("limit") or SEARCH_LIMIT_DEFAULT)
    records = service.search(vault, query, limit=max(1, min(limit, SEARCH_LIMIT_MAX)))
    return {"count": len(records), "records": [_summary(record) for record in records]}


def tool_vault_get(session: McpSession, arguments: dict) -> dict:
    """单条详情：备注 + 非敏感自定义字段值 + 敏感字段名（值恒为掩码）。"""
    record, note = _locate(session, arguments)
    # 唯一出口：profile="agent" 时 reveal_fields 被强制忽略（密码恒为 MASK）
    payload = redact_record(record, profile="agent")
    # 审计只记「看了哪条」，不记内容（查看备注也算一次 reveal）
    audit.append(session.settings, action="reveal", actor="agent", record_id=record.id, count=1)
    if note:
        payload["note"] = note
    return payload


def tool_vault_copy(session: McpSession, arguments: dict) -> dict:
    """把某个字段复制到本机剪贴板，只回执、不返回明文。"""
    record, note = _locate(session, arguments)
    field = str(arguments.get("field") or "password").strip() or "password"
    seconds = int(getattr(session.settings, "clipboard_seconds", 30) or 30)

    # 明文只存在于 service.copy_field 内部的局部变量，取完摘要立刻 del；
    # 这里拿到的 receipt 用白名单投影一次（防止将来 service 加键带出明文）。
    #
    # ⚠ `spawn=False`：MCP 是长驻进程，用进程内 daemon 定时器清空。
    # 旧实现用分离子进程，但它要求 `sys.argv[0]` 认 `_clipwatch` 子命令，
    # `python -m pwdvault.mcp_server` 启动时看门狗立刻退出 —— 30 秒清空根本没发生，
    # 而回执却写 `auto_clear_in=30`。这就是「回执说谎」的根因，已按 spawn=False 修掉。
    receipt = service.copy_field(record, field=field, seconds=seconds, spawn=False)
    audit.append(
        session.settings,
        action="copy",
        actor="agent",
        record_id=record.id,
        field_name=field,
        count=1,
        ok=bool(receipt.get("copied")),
    )
    payload = _copy_receipt(receipt)
    if note:
        payload["note"] = note
    return payload


def tool_vault_totp(session: McpSession, arguments: dict) -> dict:
    """当前 6 位动态码。允许返回明文：用户本来就要看到它才能填进登录框。"""
    record, note = _locate(session, arguments)
    secret = str(record.totp or "").strip()
    if not secret:
        raise InvalidRecord(f"{record.title} 没有动态码（TOTP）种子")
    code, remaining = service.totp_code(secret, at=session.now())
    audit.append(
        session.settings,
        action="reveal",
        actor="agent",
        record_id=record.id,
        field_name="totp",
        count=1,
    )
    payload = {
        "code": code,
        "remaining_seconds": int(remaining),
        "title": record.title,
        "id": record.id,
    }
    if note:
        payload["note"] = note
    return payload


# --------------------------------------------------------------------- T07 整理
def tool_vault_staging_list(session: McpSession, arguments: dict) -> dict:
    """待整理批次一览：**只有元数据，没有正文，也没有草稿条目**。

    这是 Agent 的第一站：先看有哪些批次等着整理，再拿 `id` 去 `vault_staging_claim`。
    未解锁也能列（只要批次外层 JSON 可读）—— 但拿不到正文。
    """
    del arguments  # 该工具没有入参
    store = session.staging()
    batches = store.list_batches(include_finished=False)
    rows: list[dict] = []
    for batch in batches[:STAGING_LIST_LIMIT]:
        rows.append(
            {
                "id": batch.batch_id,
                "source_file": batch.file_name,
                "status": batch.status,
                "item_count": int(batch.item_count or len(batch.items)),
                "origin": batch.origin,
                "age_seconds": _age_seconds(batch.created),
            }
        )
    payload: dict = {"count": len(rows), "batches": rows}
    if not rows:
        payload["hint"] = "现在没有待整理的批次。用户把文件放进 inbox 目录后会自动出现在这里。"
    return payload


def _staging_status(store: StagingStore, batch_id: str) -> str | None:
    """只读批次状态（不解密条目）。找不到返回 None。"""
    for batch in store.list_batches(include_finished=True):
        if batch.batch_id == batch_id:
            return batch.status
    return None


def tool_vault_staging_claim(session: McpSession, arguments: dict) -> dict:
    """认领一个批次（refining + 租约），拿到源文件原文与本地草稿做参考。

    认领期间别的整理者拿不到这个批次；租约到点自动失效，批次回到可认领状态。
    交回草稿用 `vault_staging_submit`，**你没有落库权限**（提交入库只能由人做）。
    """
    # 先确认已解锁：`claim` 本身只写外层元数据（不需要 DEK），若不先拦，
    # 锁着的时候会先把批次改成 refining/带租约，然后取草稿时才失败 —— 那等于
    # 「工具报错但盘上状态被改了」。宁可一开始就返回 locked。
    session.require_vault()

    settings = session.settings
    batch_id = str(arguments.get("batch_id") or "").strip()
    default_lease = int(getattr(settings, "staging_lease_seconds", DEFAULT_LEASE_SECONDS) or DEFAULT_LEASE_SECONDS)
    ceiling = int(getattr(settings, "staging_lease_max_seconds", MAX_LEASE_SECONDS) or MAX_LEASE_SECONDS)
    raw_lease = arguments.get("lease_seconds")
    want = default_lease if raw_lease is None else int(raw_lease)
    lease = max(1, min(want, MAX_LEASE_SECONDS, max(1, ceiling)))

    store = session.staging()
    status = _staging_status(store, batch_id)
    if status is None:
        raise StagingNotFound(batch_id)
    if status == "refining":
        # 第二次认领同一批次（哪怕都是 agent）：如实拒绝，而不是偷偷续租
        raise StagingBusy("这个批次正在被整理中（可能就是你刚才认领的那次），等租约过期再试。")

    store.claim(batch_id, holder=AGENT_HOLDER, lease_seconds=lease)
    batch = store.get(batch_id)

    drafts = [_draft_view(item) for item in batch.items]
    warnings: list[dict] = []
    for item in batch.items:
        warnings.extend(_warning_rows(item))

    return {
        "batch_id": batch.batch_id,
        "status": batch.status,
        "lease_seconds": lease,
        "raw_text": store.raw_text(batch_id),
        "local_draft": drafts,
        "warnings": warnings,
        "max_items_hint": int(getattr(settings, "staging_max_items", 0) or 0),
        "next_step": (
            "把 raw_text 归纳成 records[] 后用 vault_staging_submit 交回草稿；"
            "入库这一步由人在界面上确认，你不要尝试。"
        ),
    }


def tool_vault_staging_submit(session: McpSession, arguments: dict) -> dict:
    """把归纳好的草稿交回批次 → `review`，等人工确认。**只写草稿，不落库。**"""
    session.require_vault()  # 草稿要重新加密，锁着时先如实报 locked
    settings = session.settings
    batch_id = str(arguments.get("batch_id") or "").strip()
    raw_records = arguments.get("records")
    summary = str(arguments.get("summary") or "").strip()

    if not isinstance(raw_records, list) or not raw_records:
        raise InvalidArguments(_wrap("vault_staging_submit", "records 必须是非空数组"))
    limit = int(getattr(settings, "staging_max_items", 0) or 0)
    if limit > 0 and len(raw_records) > limit:
        raise InvalidArguments(
            _wrap("vault_staging_submit", f"一次最多 {limit} 条，请分批交回（收到 {len(raw_records)} 条）")
        )

    drafts: list[Record] = []
    for index, raw in enumerate(raw_records, start=1):
        if not isinstance(raw, dict):
            raise InvalidArguments(_wrap("vault_staging_submit", f"第 {index} 条不是键值对象"))
        try:
            drafts.append(Record.from_dict(raw))
        except InvalidRecord as exc:
            # 只回传「第几条 + 规则原因」，绝不回传这条的任何字段值
            raise InvalidRecord(f"第 {index} 条不合法：{exc.message}") from exc

    store = session.staging()
    store.submit(batch_id, drafts, holder=AGENT_HOLDER, summary=summary)
    batch = store.get(batch_id)

    warnings_by_item = [
        {"item_id": item.item_id, "index": index, "warnings": [w.to_dict() for w in item.warnings]}
        for index, item in enumerate(batch.items, start=1)
    ]
    return {
        "batch_id": batch.batch_id,
        "status": batch.status,
        "accepted": len(batch.accepted_items()),
        "item_count": len(batch.items),
        "warnings_by_item": warnings_by_item,
        "hint": "草稿已交回，等用户在界面上确认入库。你不要再尝试提交入库。",
    }


# --------------------------------------------------------------------- T07 写入
def tool_vault_add(session: McpSession, arguments: dict) -> dict:
    """新增一条记录。**默认 `dry_run=true`，一个字节都不写库。**

    用户口头给了一条新密码时用我：先 dry_run 看 warnings，用户确认后再 dry_run=false。
    真写时会打 `origin=agent_written` 的来源标记（放在 meta 层，不污染 fields）。
    """
    raw = arguments.get("record")
    if not isinstance(raw, dict):
        raise InvalidArguments(_wrap("vault_add", "record 必须是键值对象"))
    raw_dry = arguments.get("dry_run", True)
    dry_run = True if raw_dry is None else bool(raw_dry)

    # 先 reload：判重必须基于盘上最新状态，否则会用过期快照放过一条重复记录
    store = VaultStore(session.settings, session.require_vault())
    store.refresh()
    vault = store.vault
    record = Record.from_dict(dict(raw))
    warnings = service.validate_records(vault, [record])[0]
    rows = service.warnings_to_dicts(warnings)

    payload: dict = {
        "dry_run": dry_run,
        "created": False,
        "id": record.id,
        "revision": int(vault.revision),
        "count": len(vault.records),
        "warnings": rows,
    }
    if dry_run:
        payload["hint"] = "这是试运行，库里什么都没变。用户确认后再传 dry_run=false 调一次。"
        return payload

    blocking = sorted({warning.code for warning in warnings if warning.level in ("error", "conflict")})
    if blocking:
        # 有 error/conflict 就别写：宁可让 Agent 回去改草稿，也不要往库里塞脏数据
        raise InvalidRecord(
            "没有写库：这条记录还有 " + "、".join(blocking) + " 这类问题，先修正或改用待整理流程。"
        )

    record.meta["origin"] = "agent_written"
    record.meta["written_by"] = "agent"
    record.meta["written_at"] = now_iso()

    store = VaultStore(session.settings, vault)
    result = store.commit([Operation.add(record)])
    session.adopt(store.vault)

    audit.append(
        session.settings,
        action="add",
        actor="agent",
        record_id=record.id,
        count=1,
        ok=result.ok,
    )
    return {
        "dry_run": False,
        "created": True,
        "id": record.id,
        "revision": result.revision,
        "count": len(store.vault.records),
        "warnings": rows,
    }


def tool_vault_update(session: McpSession, arguments: dict) -> dict | ToolOutcome:
    """改一条记录。`expected_updated` 必填（乐观锁）：过期就 `record_conflict`，不覆盖。"""
    record_id = str(arguments.get("id") or "").strip()
    raw_changes = arguments.get("changes")
    expected = str(arguments.get("expected_updated") or "").strip()

    if not isinstance(raw_changes, dict) or not raw_changes:
        raise InvalidArguments(_wrap("vault_update", "changes 必须是非空键值对象"))
    if len(raw_changes) > MAX_CHANGES:
        raise InvalidArguments(_wrap("vault_update", f"一次最多改 {MAX_CHANGES} 个字段，请分批"))
    if not expected:
        raise InvalidArguments(
            _wrap("vault_update", "缺少 expected_updated：先用 vault_get 拿到这条的 updated 再提交")
        )

    changes: dict[str, Any] = {}
    for key, value in raw_changes.items():
        name = str(key)
        if name in FORBIDDEN_CHANGE_KEYS:
            raise InvalidArguments(_wrap("vault_update", f"不允许改写系统字段 {name}"))
        if name == "fields":
            if not isinstance(value, dict):
                raise InvalidArguments(_wrap("vault_update", "changes.fields 必须是键值对象"))
            changes[name] = {str(k): str(v) for k, v in value.items()}
            continue
        if isinstance(value, (dict, list)):
            raise InvalidArguments(
                _wrap("vault_update", f"changes.{name} 只能是字符串/数字/布尔/null")
            )
        changes[name] = None if value is None else str(value)

    # 先 reload 再判「记录是否存在」：盘上被别的窗口改过时，
    # 用过期的内存快照会把「刚被别人新增的记录」误报成 record_not_found。
    store = VaultStore(session.settings, session.require_vault())
    store.refresh()
    if store.vault.find_by_id(record_id) is None:
        raise RecordNotFound(record_id)

    result = store.commit([Operation.update(record_id, changes, expected_updated=expected)])
    session.adopt(store.vault)

    if result.conflicts:
        conflict = result.conflicts[0].to_dict()
        kind = str(conflict.get("kind") or "stale")
        audit.append(
            session.settings,
            action="update",
            actor="agent",
            record_id=record_id,
            count=len(changes),
            ok=False,
        )
        message = (
            "这条记录已被另一个窗口删除，本次没有写入。"
            if kind == "deleted"
            else "这条记录刚被另一个窗口改过，本次没有写入（盘上内容没被覆盖）。"
        )
        return ToolOutcome(
            {
                "code": "record_conflict",
                "message": message,
                "hint": "先重新 vault_get 拿最新的 updated 与内容，再决定要不要覆盖。",
                "conflict": conflict,
            },
            True,
        )

    for key in changes:
        audit.append(
            session.settings,
            action="update",
            actor="agent",
            record_id=record_id,
            field_name=key,
            count=1,
            ok=True,
        )
    return {
        "updated": True,
        "id": record_id,
        "revision": result.revision,
        "count": len(store.vault.records),
    }


# --------------------------------------------------------------------- 辅助
def _pending_staging(session: McpSession) -> int:
    """未完成的待整理批次数。状态工具绝不能因为暂存区异常而失败。"""
    try:
        return len(session.staging().list_batches())
    except Exception:  # noqa: BLE001 - 状态探针：任何异常都退化为 0
        return 0


def _inbox_pending(session: McpSession) -> int:
    """inbox 目录里还没被整理的文件数（只数文件，不读内容）。"""
    inbox = session.settings.inbox_path
    if not inbox.is_dir():
        return 0
    try:
        return sum(1 for path in inbox.iterdir() if path.is_file() and path.suffix.lower() != ".lock")
    except OSError:
        return 0


def _snapshot_age_days(settings: Settings) -> int | None:
    """最近一份快照的天数（没有快照返回 None）。"""
    snap_dir = settings.snapshot_dir
    if not snap_dir.is_dir():
        return None
    newest: float | None = None
    try:
        for path in snap_dir.glob("data-*.enc"):
            try:
                stamp = path.stat().st_mtime
            except OSError:
                continue
            newest = stamp if newest is None else max(newest, stamp)
    except OSError:
        return None
    if newest is None:
        return None
    return max(0, int((time.time() - newest) // 86400))


# --------------------------------------------------------------------- schema
_ID_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "description": "记录 id（10 位小写十六进制）。与 query 二选一；两个都给时以 id 为准。",
}
_QUERY_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "description": "关键词，可用前缀限定字段：tag:购物 / user:zhangsan / title:淘宝。",
}
_ANY_ID_OR_QUERY = [{"required": ["id"]}, {"required": ["query"]}]
_LOCATE_PROPERTIES = {"id": dict(_ID_PROPERTY), "query": dict(_QUERY_PROPERTY)}

STATUS_SCHEMA: dict = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

SEARCH_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "query": dict(_QUERY_PROPERTY),
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": SEARCH_LIMIT_MAX,
            "default": SEARCH_LIMIT_DEFAULT,
            "description": f"最多返回多少条（默认 {SEARCH_LIMIT_DEFAULT}，上限 {SEARCH_LIMIT_MAX}）。",
        },
    },
    "required": ["query"],
    "additionalProperties": False,
}

GET_SCHEMA: dict = {
    "type": "object",
    "properties": dict(_LOCATE_PROPERTIES),
    "anyOf": [dict(branch) for branch in _ANY_ID_OR_QUERY],
    "additionalProperties": False,
}

COPY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        **_LOCATE_PROPERTIES,
        "field": {
            "type": "string",
            "minLength": 1,
            "default": "password",
            "description": "要复制的字段：password / username / url / totp，或自定义字段名（原样匹配）。",
        },
    },
    "anyOf": [dict(branch) for branch in _ANY_ID_OR_QUERY],
    "additionalProperties": False,
}

TOTP_SCHEMA: dict = {
    "type": "object",
    "properties": dict(_LOCATE_PROPERTIES),
    "anyOf": [dict(branch) for branch in _ANY_ID_OR_QUERY],
    "additionalProperties": False,
}

# ------------------------------------------------------------------ T07 schema
_BATCH_ID_PROPERTY = {
    "type": "string",
    "minLength": 1,
    "description": "待整理批次 id（形如 sb_1a2b3c4d5e6f，从 vault_staging_list 拿）。",
}

STAGING_LIST_SCHEMA: dict = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

STAGING_CLAIM_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "batch_id": dict(_BATCH_ID_PROPERTY),
        "lease_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_LEASE_SECONDS,
            "default": DEFAULT_LEASE_SECONDS,
            "description": (
                f"租约多少秒（默认 {DEFAULT_LEASE_SECONDS}，上限 {MAX_LEASE_SECONDS}）。"
                "到点自动失效，批次回到可认领状态。"
            ),
        },
    },
    "required": ["batch_id"],
    "additionalProperties": False,
}

STAGING_SUBMIT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "batch_id": dict(_BATCH_ID_PROPERTY),
        "records": {
            "type": "array",
            "description": (
                "归纳出的草稿数组，每条是一个键值对象（title/username/password/url/notes/"
                "totp/tags，其余键原样进自定义字段）。只写草稿，不落库。"
            ),
        },
        "summary": {
            "type": "string",
            "maxLength": 200,
            "description": "给用户看的一句话说明（这批是什么、有没有需要留意的地方）。",
        },
    },
    "required": ["batch_id", "records"],
    "additionalProperties": False,
}

ADD_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "record": {
            "type": "object",
            "description": (
                "新记录：{title, username, password, url, notes, totp, tags, 以及任意自定义字段}。"
                "title 必须有，否则会返回 invalid_record。"
            ),
        },
        "dry_run": {
            "type": "boolean",
            "default": True,
            "description": "默认 true：只校验并回 warnings，一个字节都不写库。用户确认后才传 false。",
        },
    },
    "required": ["record"],
    "additionalProperties": False,
}

UPDATE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "minLength": 1,
            "description": "要改的记录 id（10 位小写十六进制）。",
        },
        "changes": {
            "type": "object",
            "description": (
                "要改的字段：{字段名: 新值}。系统字段（id/created/updated/pw_changed/meta）"
                "不允许改写；tags 用逗号分隔字符串；fields 传整个自定义字段对象。"
            ),
        },
        "expected_updated": {
            "type": "string",
            "minLength": 1,
            "description": (
                "必填。你上一次 vault_get 看到的 updated 时间戳。与盘上不一致就返回 "
                "record_conflict，绝不覆盖别人的改动。"
            ),
        },
    },
    "required": ["id", "changes", "expected_updated"],
    "additionalProperties": False,
}


# --------------------------------------------------------------------- 注册表
@dataclass(frozen=True)
class ToolSpec:
    """一个 MCP 工具的完整定义。`description` 写「什么时候用我」，不是「我做了什么」。"""

    name: str
    title: str
    description: str
    input_schema: dict
    # 绝大多数 handler 直接返回 payload dict；`vault_update` 遇到冲突时要自己
    # 决定 `isError`，所以也允许返回现成的 `ToolOutcome`。
    handler: Callable[[McpSession, dict], "dict | ToolOutcome"]

    def to_mcp(self) -> dict:
        """转成 `tools/list` 里的单个元素。键名与 MCP 规范一致（camelCase）。"""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="vault_status",
        title="密码库状态",
        description=(
            "用户问「库里有几条」「现在锁着吗」「有需要整理的吗」，或你准备做任何其他操作、"
            "想先确认库可用时用我。我永远不会失败，锁着也能回答。"
        ),
        input_schema=STATUS_SCHEMA,
        handler=tool_vault_status,
    ),
    ToolSpec(
        name="vault_search",
        title="按关键词找记录",
        description=(
            "用户提到某个站点/账号但没说清是哪一条时先用我，拿到 id 后再用 vault_copy 或 "
            "vault_get。我只返回定位信息与「有没有密码/动态码」，不返回任何密码值。"
        ),
        input_schema=SEARCH_SCHEMA,
        handler=tool_vault_search,
    ),
    ToolSpec(
        name="vault_get",
        title="看一条记录的详情",
        description=(
            "用户想「看」某一条的账号、网址、备注或有哪些自定义字段时用我。"
            "密码与敏感字段我只会给名字和掩码，永远不会给值 —— 要看值请用 vault_copy。"
        ),
        input_schema=GET_SCHEMA,
        handler=tool_vault_get,
    ),
    ToolSpec(
        name="vault_copy",
        title="把字段复制到剪贴板",
        description=(
            "用户要『用』密码/账号/网址/动态码（要粘贴到别处、要登录某个网站）时用我。"
            "我直接把值写进用户剪贴板并在 30 秒后自动清空，返回的只是回执，不含明文；"
            "复制完成即任务完成，不要再去取它的值。回执里没有 auto_clear_in 就说明"
            "这次自动清空没装上，要提醒用户用完手动覆盖剪贴板。"
        ),
        input_schema=COPY_SCHEMA,
        handler=tool_vault_copy,
    ),
    ToolSpec(
        name="vault_totp",
        title="取当前动态码",
        description=(
            "用户要登录某个开了两步验证的站点、需要「现在这个验证码」时用我。"
            "返回 6 位码与剩余有效秒数；码每 30 秒变一次，过期就让用户再问一次。"
        ),
        input_schema=TOTP_SCHEMA,
        handler=tool_vault_totp,
    ),
    ToolSpec(
        name="vault_staging_list",
        title="看待整理的批次",
        description=(
            "用户说「有文件要整理」「inbox 里放了东西」「还有几批没弄」时先用我。"
            "我只回批次元数据（id/来源文件/状态/条目数/等了多久），不含正文与草稿，"
            "拿到 id 后再用 vault_staging_claim 认领。"
        ),
        input_schema=STAGING_LIST_SCHEMA,
        handler=tool_vault_staging_list,
    ),
    ToolSpec(
        name="vault_staging_claim",
        title="认领一个待整理批次",
        description=(
            "准备把某个批次的原文归纳成记录时用我。我会把批次标记为「整理中」并给你"
            "源文件原文与本地已解析出的草稿参考；同一批次被认领后再次认领会返回 "
            "staging_busy。归纳完用 vault_staging_submit 交回，入库必须由人确认。"
        ),
        input_schema=STAGING_CLAIM_SCHEMA,
        handler=tool_vault_staging_claim,
    ),
    ToolSpec(
        name="vault_staging_submit",
        title="交回整理好的草稿",
        description=(
            "认领并归纳完之后用我：把 records[] 交回批次，批次进入「待确认」等用户在"
            "界面上核对。我只写草稿、**不落库**；批次处于人工编辑中时会被拒绝"
            "（staging_busy），这是正常的，让用户先处理。"
        ),
        input_schema=STAGING_SUBMIT_SCHEMA,
        handler=tool_vault_staging_submit,
    ),
    ToolSpec(
        name="vault_add",
        title="新增一条记录",
        description=(
            "用户口述了一条要存下来的新密码时用我。默认 dry_run=true 只做校验、"
            "不写库，先把它当成「草案」给用户确认；用户明确同意后才传 dry_run=false。"
            "批量整理不要用我，走 vault_staging_*。"
        ),
        input_schema=ADD_SCHEMA,
        handler=tool_vault_add,
    ),
    ToolSpec(
        name="vault_update",
        title="改一条记录",
        description=(
            "用户要改某条记录的字段（换密码、补网址、加备注）时用我。必须带 "
            "expected_updated（先前 vault_get 看到的 updated），过期就返回 "
            "record_conflict 且不会覆盖；拿到冲突后先重新读一遍再问用户要哪个。"
        ),
        input_schema=UPDATE_SCHEMA,
        handler=tool_vault_update,
    ),
)

TOOLS_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in TOOLS}


def list_tools() -> list[dict]:
    """`tools/list` 的 result.tools。"""
    return [spec.to_mcp() for spec in TOOLS]


def tool_names() -> list[str]:
    """已注册的工具名（供日志与测试用）。"""
    return [spec.name for spec in TOOLS]


# --------------------------------------------------------------------- 参数校验
_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}


def _type_ok(value: Any, expected: str) -> bool:
    """JSON Schema 的 `type` 判定。

    注意 `bool` 是 `int` 的子类：`{"limit": true}` 必须被判成类型错误，
    否则 `int(True)` 会静默变成 1。
    """
    if expected in ("integer", "number") and isinstance(value, bool):
        return False
    allowed = _JSON_TYPES.get(expected)
    if allowed is None:
        return True
    return isinstance(value, allowed)


def validate_arguments(schema: dict, arguments: dict, *, tool_name: str = "") -> None:
    """按 `inputSchema` 校验入参，不合法抛 `InvalidArguments`（→ -32602）。

    只实现本项目 schema 真正用到的子集：`type` / `properties` / `required` /
    `additionalProperties` / `enum` / `minLength` / `maxLength` / `minimum` /
    `maximum` / `anyOf(required)`。保持小而准，比塞一个半吊子 JSON Schema 库好。
    """
    if not isinstance(arguments, dict):
        raise InvalidArguments(_wrap(tool_name, "arguments 必须是 JSON 对象"))

    properties = schema.get("properties") or {}
    for key in schema.get("required") or ():
        if key not in arguments:
            raise InvalidArguments(_wrap(tool_name, f"缺少必填参数：{key}"))

    if schema.get("additionalProperties") is False:
        unknown = sorted(key for key in arguments if key not in properties)
        if unknown:
            raise InvalidArguments(_wrap(tool_name, f"不认识的参数：{', '.join(unknown)}"))

    for key, value in arguments.items():
        spec = properties.get(key)
        if not isinstance(spec, dict):
            continue
        expected = spec.get("type")
        if isinstance(expected, str) and not _type_ok(value, expected):
            raise InvalidArguments(
                _wrap(tool_name, f"参数 {key} 必须是 {expected}，收到 {type(value).__name__}")
            )
        if "enum" in spec and value not in (spec.get("enum") or []):
            raise InvalidArguments(_wrap(tool_name, f"参数 {key} 的取值不在允许范围内"))
        if isinstance(value, str):
            if "minLength" in spec and len(value) < int(spec["minLength"]):
                raise InvalidArguments(_wrap(tool_name, f"参数 {key} 不能为空"))
            if "maxLength" in spec and len(value) > int(spec["maxLength"]):
                raise InvalidArguments(_wrap(tool_name, f"参数 {key} 太长"))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in spec and value < spec["minimum"]:
                raise InvalidArguments(_wrap(tool_name, f"参数 {key} 不能小于 {spec['minimum']}"))
            if "maximum" in spec and value > spec["maximum"]:
                raise InvalidArguments(_wrap(tool_name, f"参数 {key} 不能大于 {spec['maximum']}"))

    branches = schema.get("anyOf") or []
    if branches:
        satisfied = False
        for branch in branches:
            needed = (branch or {}).get("required") or []
            if needed and all(key in arguments for key in needed):
                satisfied = True
                break
        if not satisfied:
            needed_names = [" / ".join((branch or {}).get("required") or []) for branch in branches]
            raise InvalidArguments(
                _wrap(tool_name, "至少需要 " + " 或 ".join(name for name in needed_names if name))
            )


def _wrap(tool_name: str, detail: str) -> str:
    """错误文案：`Invalid arguments for <tool>: <detail>`（与 DESIGN §7.4 一致）。"""
    if tool_name:
        return f"Invalid arguments for {tool_name}: {detail}"
    return f"Invalid arguments: {detail}"


# --------------------------------------------------------------------- 分发
def call_tool(session: McpSession, name: str, arguments: dict) -> ToolOutcome:
    """`tools/call` 的唯一入口。

    返回值总是「可以进 result」的东西：
      - 成功 → `ToolOutcome(payload, False)`
      - 业务错误 → `ToolOutcome(public_error(...), True)`
    工具名未知 / 参数不合法 → 抛 `ToolError`（由 mcp_server 映射成 -32602）。
    """
    spec = TOOLS_BY_NAME.get(name)
    if spec is None:
        raise UnknownTool(f"Unknown tool: {name}")

    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise InvalidArguments(_wrap(name, "arguments 必须是 JSON 对象"))

    validate_arguments(spec.input_schema, arguments, tool_name=name)

    session.begin_call()
    try:
        payload = spec.handler(session, arguments)
    except AmbiguousRecords as exc:
        # 先于 VaultError 捕获：它带 candidates
        return ToolOutcome(public_error(exc, candidates=exc.candidates), True)
    except VaultError as exc:
        return ToolOutcome(public_error(exc), True)
    if isinstance(payload, ToolOutcome):
        # handler 自己判定了 isError（例如 record_conflict：不是异常但要标红）
        return payload
    return ToolOutcome(payload, False)


__all__ = [
    "ADD_SCHEMA",
    "AGENT_HOLDER",
    "COPY_KEYS",
    "CANDIDATE_LIMIT",
    "DEFAULT_LEASE_SECONDS",
    "DRAFT_KEYS",
    "ENV_MASTER_PASSWORD",
    "FORBIDDEN_CHANGE_KEYS",
    "LOCKED_HINT",
    "LOCKED_MESSAGE",
    "MAX_CHANGES",
    "MAX_LEASE_SECONDS",
    "McpSession",
    "SEARCH_LIMIT_DEFAULT",
    "SEARCH_LIMIT_MAX",
    "STAGING_LIST_LIMIT",
    "SUMMARY_KEYS",
    "TOOLS",
    "TOOLS_BY_NAME",
    "UPDATE_SCHEMA",
    "AmbiguousRecords",
    "InvalidArguments",
    "ToolError",
    "ToolOutcome",
    "ToolSpec",
    "UnknownTool",
    "call_tool",
    "list_tools",
    "tool_names",
    "tool_vault_add",
    "tool_vault_copy",
    "tool_vault_get",
    "tool_vault_search",
    "tool_vault_staging_claim",
    "tool_vault_staging_list",
    "tool_vault_staging_submit",
    "tool_vault_status",
    "tool_vault_totp",
    "tool_vault_update",
    "unlock_chain",
    "validate_arguments",
]
