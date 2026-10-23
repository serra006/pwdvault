"""唯一脱敏出口。

任何要跨进程（MCP / HTTP）返回的记录数据**都必须**经过本模块。
把「怎么脱敏」集中到这里，是为了让「有没有泄露」成为一个可以审计的代码事实，
而不是散落在各 handler 里的自觉。
"""

from __future__ import annotations

from typing import Any, Iterable, Literal

from .errors import VaultError
from .models import MASK, Record, is_sensitive_key, mask_value

Profile = Literal["agent", "ui", "web"]

Origin = Literal["local", "agent"]

# 对外只暴露两种来源，与 DESIGN §3.x 的 `Origin = Literal["local","agent"]` 对齐。
ORIGIN_LOCAL = "local"
ORIGIN_AGENT = "agent"

# `Record.meta` 是内部标记层，历史上出现过 `origin` 与 `written_by` 两种写法，
# 值域也不统一（`agent` / `agent_written`）。这里做成**归一化白名单**：
# 只有明确的 agent 标记才映射成 "agent"，其余（含未来新增/被伪造的任意字符串）
# 一律降级成 "local" —— 宁可少显示一个徽标，也不让写方决定 UI 上出现什么字。
_AGENT_ORIGIN_VALUES = frozenset({"agent", "agent_written"})
_AGENT_WRITERS = frozenset({"agent"})


def normalize_profile(profile: str) -> str:
    """`web` 与 `ui` 是同一档（浏览器可以显式 reveal）；其余一律当 agent 处理。"""
    return "ui" if str(profile).lower() in ("ui", "web") else "agent"


def record_origin(record: Record) -> str:
    """记录的来源：`"agent"`（Agent 写过）或 `"local"`（人工/导入）。

    值域固定两个，前端只需判 `origin == "agent"`。这是**读 `record.meta` 的唯一
    合法位置**：其它模块（web/mcp）想显示来源徽标，一律读脱敏结果的 `origin` 键，
    不要自己去翻 `record.meta`，否则「哪些内部标记会出现在对外结构里」这件事又散开了。

    归一化规则（fail closed）：
      - `meta.origin` ∈ {`agent`, `agent_written`} → `"agent"`
      - 否则 `meta.written_by == "agent"` → `"agent"`
      - 其余一切（缺失、`web`、`cli`、未来新造的任意字符串）→ `"local"`

    **新增写入方必须在这里登记**（往 `_AGENT_ORIGIN_VALUES` / `_AGENT_WRITERS` 里加）。
    不登记就会被静默降级成 `"local"`：将来若加了 `"mcp_auto"` 之类的新标记却忘了
    登记，界面上会把机器写的记录显示成「人写的」，用户就此误判「这条是谁建的」。
    降级而不是猜测，是因为 `meta` 可以被 payload 合并（见 `Record.apply_changes`），
    让写方决定 UI 上出现什么字是不安全的。
    """
    meta = record.meta or {}
    raw = str(meta.get("origin") or "").strip().lower()
    if raw in _AGENT_ORIGIN_VALUES:
        return ORIGIN_AGENT
    if str(meta.get("written_by") or "").strip().lower() in _AGENT_WRITERS:
        return ORIGIN_AGENT
    return ORIGIN_LOCAL


def redact_record(
    record: Record,
    *,
    profile: Profile = "agent",
    reveal_fields: Iterable[str] = (),
) -> dict:
    """把一条记录变成安全的对外结构（键名固定，前端与 Agent 契约不漂移）。

    返回：
        {id, title, username, url, tags, notes, created, updated, pw_changed,
         origin, has_password, has_totp, password, totp, fields,
         secret_field_names}

    `origin` 是 `"local"` / `"agent"` 两值之一（见 `record_origin()`）：它是
    「由 Agent 写入」徽标的**唯一数据来源**，不让调用方自己去翻 `record.meta`。

    `profile="agent"` 时 `reveal_fields` 被**强制忽略**：这里直接把 reveal 集合
    置空，而不是在下面加条件判断 —— 即使调用方传错参数也不可能泄密。
    """
    prof = normalize_profile(profile)
    reveal: frozenset[str] = frozenset() if prof == "agent" else frozenset(str(f) for f in (reveal_fields or ()))

    out: dict = {
        "id": record.id,
        "title": record.title,
        "username": record.username,
        "url": record.url,
        "tags": list(record.tags),
        "notes": record.notes,
        "created": record.created,
        "updated": record.updated,
        "pw_changed": record.pw_changed,
        "origin": record_origin(record),
        "has_password": bool(record.password),
        "has_totp": bool(record.totp),
    }

    if "password" in reveal:
        out["password"] = record.password
    else:
        out["password"] = mask_value(record.password)

    if "totp" in reveal:
        out["totp"] = record.totp
    else:
        out["totp"] = mask_value(record.totp)

    fields: dict[str, str] = {}
    secret_names: list[str] = []
    for name, value in record.fields.items():
        if is_sensitive_key(name):
            secret_names.append(name)
            fields[name] = value if name in reveal else mask_value(value)
        else:
            fields[name] = value

    out["fields"] = fields
    out["secret_field_names"] = secret_names
    return out


def redact_records(
    records: Iterable[Record],
    *,
    profile: Profile = "agent",
    reveal_fields: Iterable[str] = (),
) -> list[dict]:
    return [
        redact_record(record, profile=profile, reveal_fields=reveal_fields)
        for record in (records or [])
    ]


def public_error(exc: VaultError, *, candidates: list[dict] | None = None) -> dict:
    """把异常翻译成对外结构：{code, message, hint?, candidates?}。

    不传 traceback、不传内部对象、不传 str(exc) 之外的任何东西。
    """
    payload: dict = {"code": exc.code, "message": exc.message}
    if exc.hint:
        payload["hint"] = exc.hint
    if candidates:
        payload["candidates"] = candidates
    return payload


def assert_no_secret(payload: Any, *probes: str) -> None:
    """测试用哨兵断言：递归遍历 payload，命中任一探针即 AssertionError。

    探针是形如 `ZZ-PvProbe-Pw-...-DO-NOT-LEAK` 的字符串，正常数据里绝不会出现，
    所以命中即代表某个字段的明文漏进了对外结构。
    """
    needles = [str(p) for p in probes if p]
    if not needles:
        return

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
            return
        if isinstance(node, (list, tuple, set)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
            return
        if isinstance(node, bytes):
            node = node.decode("utf-8", errors="replace")
        text = node if isinstance(node, str) else repr(node)
        for needle in needles:
            if needle in text:
                raise AssertionError(f"哨兵值泄露在 {path or '<root>'}")

    walk(payload, "")


__all__ = [
    "MASK",
    "ORIGIN_AGENT",
    "ORIGIN_LOCAL",
    "Origin",
    "Profile",
    "assert_no_secret",
    "normalize_profile",
    "public_error",
    "record_origin",
    "redact_record",
    "redact_records",
]
