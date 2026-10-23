"""Web 业务 API（T09）：记录 CRUD / 暂存区 / inbox 上传 / 体检 / MCP 接入配置。

这一层只做三件事：**解析请求 → 调业务层 → 把结果脱敏后序列化**。
它自己不碰文件、不碰加密原语、不碰状态机规则（规则全在 `locks.py` / `staging.py` /
`service.py`）。三条硬纪律：

1. **所有记录数据都经 `redact.py` 出门**。本文件里**禁止**出现
   `record.to_dict()`、`record.password` 直接进入响应 dict，
   连拼字符串都不行（`str(record)` 会把明文带出来）。
2. **所有写操作都走 `VaultStore.commit([Operation...])`**，绝不 `vault.save()`；
   改单条记录必须带 `expected_updated` 走乐观锁，冲突就 409 且盘上一个字节都没动。
   暂存区入库走 `StagingStore.commit`（它内部同样只经 `VaultStore.commit`）。
3. **未解锁一律 401 + `code="locked"`**。`staging` 解草稿需要 DEK，锁着时底层抛
   `Locked`；`_guard_locked()` 是唯一的翻译点，避免每个 handler 各写一遍
   （也避免落到 `STATUS_BY_CODE` 的 409 上，那份表是给 MCP 共用的语义）。

关于事件推送：写记录成功后 `AppState._on_store_revision` 已经会
`bus.publish("revision", {..., "source": "ui"})`。这里**不重复发**同一个事件——
两处各发一次会让 SSE 订阅者每写一次收到两条 revision（前端会多刷一遍列表）。
暂存区状态变化不经过 VaultStore，所以由本文件 `_publish_staging()` 补发 `"staging"`。

关于 `?reveal=`：HTTP 是无状态的，所以「显示 15 秒后自动回掩」由前端计时，
后端只负责**一次性返回明文并写审计**（`action="reveal"`，只记字段名，绝不记值）。
"""

from __future__ import annotations

import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable

from .. import audit, service
from ..config import log_event
from ..errors import InvalidRecord, VaultError
from ..inbox import INBOX_SUFFIXES
from ..locks import Operation
from ..models import Record, split_tags
from ..redact import redact_record
from ..staging import can_transition, label_of
from ..vault import atomic_write
from .server import HttpError, Request, Response, WebServer

#: 列表默认/最大条数。前端有搜索框，200 条足够一屏滚动；500 是保护上限。
DEFAULT_LIST_LIMIT = 200
MAX_LIST_LIMIT = 500

#: 暂存区列表最多返回多少个批次（含已完结的，撤销入口要用）。
STAGING_LIST_LIMIT = 100

#: 明文显示后的提示文案（与前端 15 秒计时一致）。
REVEAL_WARNING = "此值已显示，15 秒后建议刷新页面"

#: 编辑者标识头（前端每个标签页一个唯一 id）。
EDITOR_HEADER = "X-PV-Editor-Id"

#: 记录的三个固定时间戳键，不允许客户端通过 PATCH 写。
_PROTECTED_CHANGE_KEYS = frozenset({"id", "created", "updated", "pw_changed", "meta"})

_CORE_FIELDS: tuple[str, ...] = ("title", "username", "password", "url", "notes", "totp")

#: 云同步目录特征（用于健康检查的 `looks_synced`，只做提示不做判断）。
_SYNC_MARKERS: tuple[str, ...] = (
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud",
    "nutstore",
    "坚果云",
    "baidunetdisk",
    "百度网盘",
    "weiyun",
    "微云",
    "syncthing",
)


# ---------------------------------------------------------------- 小工具
def _store(req: Request):
    """取已解锁的 VaultStore；锁着时抛 `Locked` → `_guard_locked` 翻成 401。"""
    return req.state.require_unlocked()


def _publish_staging(req: Request, batch: Any) -> None:
    """暂存区状态变化 → SSE。任何异常都不能影响已经完成的写入。"""
    try:
        req.state.bus.publish(
            "staging",
            {
                "batch_id": str(getattr(batch, "batch_id", "") or ""),
                "status": str(getattr(batch, "status", "") or ""),
                "item_count": int(getattr(batch, "item_count", 0) or 0),
                "origin": str(getattr(batch, "origin", "local") or "local"),
                "updated": str(getattr(batch, "updated", "") or ""),
                "source": "ui",
            },
        )
    except Exception:  # noqa: BLE001 - 广播失败不影响业务结果
        log_event("staging_publish_failed", scope="pv web", level="WARN")


def _record_summary(record: Record) -> dict:
    """列表项形态。只从 `redact_record` 的输出里挑字段，不碰 `record.*` 明文。

    `origin` 直接用脱敏结果里的值（`"local"` / `"agent"`），**不在这里翻
    `record.meta`**：`redact.record_origin()` 是读 meta 的唯一合法位置，
    否则「哪些内部标记会出现在对外结构里」这件事又会散到第二个地方。
    """
    data = redact_record(record, profile="web")
    return {
        "id": data["id"],
        "title": data["title"],
        "username": data["username"],
        "url": data["url"],
        "tags": list(data["tags"]),
        "has_password": bool(data["has_password"]),
        "has_totp": bool(data["has_totp"]),
        "secret_field_names": list(data["secret_field_names"]),
        "updated": data["updated"],
        "origin": data["origin"],
    }


def _record_detail(record: Record) -> dict:
    """详情形态：summary + 备注/时间/自定义字段（敏感值一律掩码）。

    `password` / `totp` 也给出**掩码**值（`••••`），这样前端不用自己造掩码；
    真值只能通过 `GET /api/records/{id}?reveal=<field>` 单取（会写审计）。
    """
    data = redact_record(record, profile="web")
    out = _record_summary(record)
    out.update(
        {
            "notes": data["notes"],
            "created": data["created"],
            "pw_changed": data["pw_changed"],
            "fields": dict(data["fields"]),
            "password": data["password"],
            "totp": data["totp"],
            "password_hidden": True,
        }
    )
    return out


def _merged_record(payload: dict, base: Record | None = None) -> Record:
    """把一份 payload 合并成 `Record`（POST 新建 / PATCH 暂存草稿共用）。

    与 `Record.from_dict` 的差别：**不做标题推断**（草稿允许空标题，否则暂存区
    手工新建的空白草稿会被直接拒掉），也**不吞 totp**（用户明确填在 totp 里就是
    totp，即使格式不标准也原样保存，由条目警告提醒，而不是悄悄改放进自定义字段）。
    """
    if base is not None:
        values: dict[str, Any] = {
            "title": base.title,
            "username": base.username,
            "password": base.password,
            "url": base.url,
            "notes": base.notes,
            "totp": base.totp,
            "tags": list(base.tags),
            "fields": dict(base.fields),
            "id": base.id,
            "created": base.created,
            "updated": base.updated,
            "pw_changed": base.pw_changed,
        }
        values["meta"] = dict(base.meta)
    else:
        values = {
            "title": "",
            "username": "",
            "password": "",
            "url": "",
            "notes": "",
            "totp": "",
            "tags": [],
            "fields": {},
        }

    for key in _CORE_FIELDS:
        if key not in payload:
            continue
        value = payload[key]
        if value is None:
            continue
        text = str(value)
        # 密码保留原样（首尾空格可能是有意的）；其余主字段去掉两端空白
        values[key] = text if key == "password" else text.strip()

    if "tags" in payload:
        values["tags"] = split_tags(payload["tags"])

    extra_fields: dict[str, str] = dict(values.get("fields") or {})
    nested = payload.get("fields")
    if isinstance(nested, dict):
        for name, value in nested.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            text = str(value)
            if text.strip():
                extra_fields[str(name)] = text
    for key, value in payload.items():
        if key in _CORE_FIELDS or key in ("tags", "fields") or key in _PROTECTED_CHANGE_KEYS:
            continue
        if value is None or isinstance(value, (dict, list)):
            continue
        text = str(value).strip()
        if text:
            extra_fields[str(key)] = text
    values["fields"] = extra_fields

    return Record(**values)


def _normalize_changes(changes: dict) -> dict:
    """把前端传来的 changes 归一成 `Record.apply_changes` 能吃的样子。

    `apply_changes` 把 `tags` 当**字符串**按逗号切分，所以前端传数组时必须先
    `",".join(...)`；否则 `str(["工作"])` 会变成 `"['工作']"` 这样一条标签。
    非标量（dict/list）除了 `fields` 一律丢弃 —— 静默把 `{...}` 塞进字段值没有意义。
    """
    out: dict[str, Any] = {}
    for key, value in (changes or {}).items():
        name = str(key)
        if name in _PROTECTED_CHANGE_KEYS:
            continue
        if name == "tags":
            out["tags"] = ",".join(split_tags(value))
            continue
        if name == "fields":
            if isinstance(value, dict):
                out["fields"] = {
                    str(sub_key): str(sub_value)
                    for sub_key, sub_value in value.items()
                    if sub_value is not None and not isinstance(sub_value, (dict, list))
                }
            continue
        if value is None or isinstance(value, (dict, list)):
            continue
        out[name] = str(value)
    return out


def _field_value(record: Record, field: str) -> str | None:
    """取单个字段的明文。字段不存在返回 None（与「存在但为空」区分）。"""
    name = str(field or "").strip()
    if not name:
        return None
    if name in _CORE_FIELDS:
        return str(getattr(record, name) or "")
    if name in ("user", "account"):
        return record.username
    if name in record.fields:
        return str(record.fields.get(name) or "")
    # 自定义字段名大小写不一致时，做一次大小写不敏感的回退匹配
    for key, value in record.fields.items():
        if str(key).casefold() == name.casefold():
            return str(value or "")
    return None


def _reveal_payload(field: str, value: str, *, extra: dict | None = None) -> dict:
    payload: dict[str, Any] = {
        "revealed": field,
        "value": value,
        "warning": REVEAL_WARNING,
    }
    if extra:
        payload.update(extra)
    return payload


def _audit_reveal(req: Request, record_id: str, field: str) -> None:
    """审计只记「谁看了哪条记录的哪个字段」，**绝不记值**。"""
    audit.append(
        req.state.settings,
        action="reveal",
        actor="web",
        record_id=record_id,
        field_name=field,
        count=1,
    )


def _conflict_response(conflict: Any) -> Response:
    """记录级冲突 → 409，结构固定为 `{code, message, hint, conflict}`。"""
    kind = str(getattr(conflict, "kind", "stale") or "stale")
    message = "这条记录已被另一个窗口删除。" if kind == "deleted" else "这条记录刚被另一个窗口改过。"
    return Response.json(
        {
            "code": "record_conflict",
            "message": message,
            "hint": "选择「保留我的」或「采用新的」，不会静默覆盖。",
            "conflict": conflict.to_dict(),
        },
        status=409,
    )


# ---------------------------------------------------------------- 记录：列表/详情
def handle_records_list(req: Request) -> Response:
    """`GET /api/records?q=&tag=&limit=&offset=` → `{count, total, records[]}`。"""
    store = _store(req)
    vault = store.vault

    query = req.query_str("q").strip()
    tag = req.query_str("tag").strip()
    limit = min(MAX_LIST_LIMIT, max(1, req.query_int("limit", DEFAULT_LIST_LIMIT)))
    offset = max(0, req.query_int("offset", 0))

    if query:
        # 搜索命中按相关度排序（service.search 已经排好），不再按时间打乱
        matched = list(service.search(vault, query))
    else:
        matched = sorted(vault.records, key=lambda item: str(item.updated or ""), reverse=True)

    if tag:
        key = tag.casefold()
        matched = [record for record in matched if any(t.casefold() == key for t in record.tags)]

    total = len(matched)
    page = matched[offset : offset + limit]
    records = [_record_summary(record) for record in page]
    return Response.json(
        {
            "count": len(records),
            "total": total,
            "records": records,
            "limit": limit,
            "offset": offset,
        }
    )


def handle_record_detail(req: Request) -> Response:
    """`GET /api/records/{id}` → 详情（敏感值掩码）；`?reveal=<field>` → 单值明文 + 审计。"""
    store = _store(req)
    record_id = req.param("id")
    record = store.vault.find_by_id(record_id)
    if record is None:
        raise HttpError(
            404,
            "record_not_found",
            "找不到这条记录。",
            hint="刷新列表看看它是否已被另一个窗口删除。",
        )

    field = req.query_str("reveal").strip()
    if not field:
        return Response.json(_record_detail(record))

    value = _field_value(record, field)
    if value is None:
        raise HttpError(
            404,
            "field_not_found",
            "这条记录没有这个字段。",
            hint="刷新详情后再试。",
        )
    _audit_reveal(req, record.id, field)
    return Response.json(_reveal_payload(field, value, extra={"id": record.id}))


# ---------------------------------------------------------------- 记录：写
def handle_record_create(req: Request) -> Response:
    """`POST /api/records` → `{id, revision}`。所有写入走 `VaultStore.commit`。"""
    store = _store(req)
    payload = req.json_body()
    title = str(payload.get("title") or "").strip()
    if not title:
        raise InvalidRecord("标题不能为空")

    record = _merged_record(payload)
    record.title = title
    record.meta["origin"] = "web_ui"
    record.meta["written_by"] = "web"

    result = store.commit([Operation.add(record)])
    if result.conflicts:  # add 不会产生冲突，这里只是防御
        return _conflict_response(result.conflicts[0])

    audit.append(
        req.state.settings,
        action="add",
        actor="web",
        record_id=record.id,
        count=1,
    )
    log_event("api_add", scope="pv web", revision=result.revision, count=1)
    # 200 而不是 201：契约没规定状态码，前端按 2xx 判断，这里选最不容易被
    # 严格 `status === 200` 判断误伤的那个。
    return Response.json({"id": record.id, "revision": result.revision})


def handle_record_patch(req: Request) -> Response:
    """`PATCH /api/records/{id}` → `{updated, id, revision}`；冲突 409 且不落盘。"""
    store = _store(req)
    record_id = req.param("id")
    payload = req.json_body()

    changes = payload.get("changes")
    if not isinstance(changes, dict) or not changes:
        raise HttpError(
            400,
            "invalid_request",
            "changes 必须是一个非空对象。",
            hint="只传要改的字段，例如 {\"changes\": {\"password\": \"新的\"}}。",
        )
    expected = payload.get("expected_updated")
    if not isinstance(expected, str) or not expected.strip():
        raise HttpError(
            400,
            "missing_expected_updated",
            "缺少 expected_updated，无法判断有没有覆盖别人的修改。",
            hint="把详情里的 updated 原样带回来即可。",
        )

    record = store.vault.find_by_id(record_id)
    if record is None:
        raise HttpError(
            404,
            "record_not_found",
            "找不到这条记录。",
            hint="刷新列表看看它是否已被另一个窗口删除。",
        )

    safe_changes = _normalize_changes(changes)
    if not safe_changes:
        raise HttpError(400, "invalid_request", "没有任何可修改的字段。")

    result = store.commit(
        [Operation.update(record_id, safe_changes, expected_updated=expected.strip())]
    )
    if result.conflicts:
        return _conflict_response(result.conflicts[0])

    audit.append(
        req.state.settings,
        action="update",
        actor="web",
        record_id=record_id,
        field_name=",".join(sorted(safe_changes.keys())),
        count=1,
    )
    log_event("api_update", scope="pv web", revision=result.revision, count=result.updated)
    return Response.json({"updated": True, "id": record_id, "revision": result.revision})


def handle_record_delete(req: Request) -> Response:
    """`DELETE /api/records/{id}` body `{confirm_title}` → `{deleted, revision}`。

    标题不匹配一律 400，**记录仍原样在库里** —— 删除是不可逆操作，
    宁可让前端多问一次，也不接受「只凭 id 就删」。
    """
    store = _store(req)
    record_id = req.param("id")
    payload = req.json_body()

    confirm = payload.get("confirm_title")
    if not isinstance(confirm, str) or not confirm.strip():
        raise HttpError(
            400,
            "confirm_mismatch",
            "删除需要确认标题。",
            hint="把这条记录的标题原样放进 confirm_title 再试一次。",
        )

    record = store.vault.find_by_id(record_id)
    if record is None:
        raise HttpError(
            404,
            "record_not_found",
            "找不到这条记录。",
            hint="刷新列表看看它是否已被另一个窗口删除。",
        )
    if record.title.strip() != confirm.strip():
        raise HttpError(
            400,
            "confirm_mismatch",
            "标题不匹配，删除已取消。",
            hint="确认标题与记录标题完全一致（含空格）后再试。",
        )

    result = store.commit([Operation.delete(record_id)])
    # 审计白名单（copy/add/update/reveal/commit）里没有 delete，用 commit 记一次
    audit.append(
        req.state.settings,
        action="commit",
        actor="web",
        record_id=record_id,
        field_name="delete",
        count=1,
    )
    log_event("api_delete", scope="pv web", revision=result.revision, count=result.deleted)
    return Response.json({"deleted": True, "revision": result.revision})


def handle_record_copy(req: Request) -> Response:
    """`POST /api/records/{id}/copy` → **原样透传** `service.copy_field` 的回执。

    `spawn=False` 是硬要求：Web 是长驻进程，进程内 daemon 定时器比分离子进程可靠
    （子进程方式依赖 argv[0] 认 `_clipwatch`，`python -m` 入口下会静默失效）。
    """
    store = _store(req)
    record_id = req.param("id")
    payload = req.json_body()
    field = str(payload.get("field") or "password").strip() or "password"

    record = store.vault.find_by_id(record_id)
    if record is None:
        raise HttpError(
            404,
            "record_not_found",
            "找不到这条记录。",
            hint="刷新列表看看它是否已被另一个窗口删除。",
        )

    receipt = service.copy_field(
        record,
        field=field,
        seconds=int(getattr(req.state.settings, "clipboard_seconds", 30)),
        spawn=False,
    )
    audit.append(
        req.state.settings,
        action="copy",
        actor="web",
        record_id=record.id,
        field_name=field,
        count=1,
    )
    return Response.json(receipt)


def handle_tags(req: Request) -> Response:
    """`GET /api/tags` → `{tags:[{name, count}]}`（按条数降序，同数按名字）。"""
    store = _store(req)
    counter: dict[str, int] = {}
    for record in store.vault.records:
        for tag in record.tags:
            name = str(tag)
            counter[name] = counter.get(name, 0) + 1
    rows = [{"name": name, "count": count} for name, count in counter.items()]
    rows.sort(key=lambda row: (-row["count"], row["name"].casefold()))
    return Response.json({"tags": rows, "count": len(rows)})


# ---------------------------------------------------------------- 暂存区
def _ensure_reviewable(req: Request, batch_id: str) -> Any:
    """把「本地已解析」「无法识别」的批次推到 `review`，让用户能编辑与提交。

    为什么需要：inbox 建出来的批次是 `drafted`（本地解析）或 `failed`（认不出），
    而 `save_items` / `begin_edit` / `commit` 只接受 `review|reviewing`。
    状态机允许 `drafted→review`、`failed→review`，所以这里是一次合法转换，
    不是绕过规则。已经在 `review/reviewing` 就直接返回。
    """
    staging = req.state.staging
    batch = staging.get(batch_id)
    if batch.status in ("review", "reviewing"):
        return batch
    if can_transition(batch.status, "review"):
        moved = staging.transition(batch_id, "review", reason="web_open")
        _publish_staging(req, moved)
        return moved
    raise HttpError(
        409,
        "staging_busy",
        f"批次现在「{label_of(batch.status)}」，不能开始确认。",
        hint="刷新待整理列表看看它是否已经被处理。",
    )


def _editor_id(req: Request, payload: dict | None = None, *, required: bool = False) -> str:
    """`editor_id` 优先取 `X-PV-Editor-Id` 头，缺失时回落 body，再缺就退化成 `"web"`。

    为什么缺失不报错：`staging.py` 的编辑锁语义是「同一个 holder 可以重入」，
    前端只要按契约带上头就是「每标签页唯一」。缺头时退化成单一身份，多标签页的
    互相抢占检测会变弱（谁都能接管），但**不会**让用户点不动按钮 —— 后者是明确的
    功能故障，前者只是保护降级，且在 UI 里可以看到状态变化。
    """
    value = str(req.headers.get(EDITOR_HEADER.lower(), "") or "").strip()
    if not value and isinstance(payload, dict):
        value = str(payload.get("editor_id") or "").strip()
    if not value:
        return "web"
    return value


def _staging_row(batch: Any) -> dict:
    """批次列表行（与 MCP 侧 `vault_staging_list` 的字段保持一致）。"""
    public = batch.to_public(include_items=False)
    return {
        "id": str(batch.batch_id),
        "source_file": str(batch.file_name),
        "status": str(batch.status),
        "status_label": label_of(str(batch.status)),
        "item_count": int(public.get("item_count") or 0),
        "origin": str(batch.origin),
        "age_seconds": int(public.get("age_seconds") or 0),
        "created": str(batch.created or ""),
        "updated": str(batch.updated or ""),
    }


def handle_staging_list(req: Request) -> Response:
    """`GET /api/staging` → `{count, batches:[...]}`（含已入库的，撤销入口要用）。"""
    staging = req.state.staging
    batches = staging.list_batches(include_finished=True)
    rows = [_staging_row(batch) for batch in batches[:STAGING_LIST_LIMIT]]
    payload: dict[str, Any] = {"count": len(rows), "batches": rows}
    if not rows:
        payload["hint"] = "现在没有待整理的批次。把 TXT 拖进来或放进 inbox 目录即可。"
    return Response.json(payload)


def _staging_item_row(index: int, item: Any, *, reveal: frozenset[str] = frozenset()) -> dict:
    """条目对外形态：草稿走 `redact_record`，**密码默认掩码**。"""
    data = redact_record(item.draft, profile="web", reveal_fields=reveal)
    draft = {
        "title": data["title"],
        "username": data["username"],
        "password": data["password"],
        "url": data["url"],
        "notes": data["notes"],
        "totp": data["totp"],
        "tags": list(data["tags"]),
        "fields": dict(data["fields"]),
    }
    return {
        "index": int(index),
        "item_id": str(item.item_id),
        "draft": draft,
        "origin": str(item.origin),
        "accepted": bool(item.accepted),
        "edited": bool(item.edited),
        "has_error": bool(item.has_error),
        "warnings": [warning.to_dict() for warning in item.warnings],
        "conflict": dict(item.conflict) if item.conflict else None,
        "secret_field_names": list(data["secret_field_names"]),
    }


def handle_staging_detail(req: Request) -> Response:
    """`GET /api/staging/{id}` → `{batch, items[]}`；`?reveal=<field>&index=N` 单取一条。"""
    staging = req.state.staging
    batch_id = req.param("id")
    batch = staging.get(batch_id)

    reveal = req.query_str("reveal").strip()
    raw_index = req.query_str("index").strip()
    if reveal and raw_index:
        try:
            index = int(raw_index)
        except ValueError as exc:
            raise HttpError(400, "invalid_index", "index 必须是整数。") from exc
        if index < 0 or index >= len(batch.items):
            raise HttpError(404, "item_not_found", "这个批次里没有这一条。")
        item = batch.items[index]
        value = _field_value(item.draft, reveal)
        if value is None:
            raise HttpError(404, "field_not_found", "这条草稿没有这个字段。")
        _audit_reveal(req, item.draft.id or batch.batch_id, reveal)
        return Response.json(
            _reveal_payload(reveal, value, extra={"batch_id": batch.batch_id, "index": index})
        )

    reveal_set = frozenset({reveal}) if reveal else frozenset()
    items = [
        _staging_item_row(index, item, reveal=reveal_set)
        for index, item in enumerate(batch.items)
    ]
    payload_batch = {
        "id": str(batch.batch_id),
        "status": str(batch.status),
        "status_label": label_of(str(batch.status)),
        "origin": str(batch.origin),
        "item_count": int(batch.item_count or len(batch.items)),
        "notes": str(batch.notes or ""),
        "age_seconds": int(batch.to_public(include_items=False).get("age_seconds") or 0),
        "created": str(batch.created or ""),
        "updated": str(batch.updated or ""),
        "source_file": str(batch.file_name),
        "source": dict(batch.source or {}),
        "editor": dict(batch.editor) if batch.editor else None,
        "commit": dict(batch.commit) if batch.commit else None,
    }
    return Response.json({"batch": payload_batch, "items": items, "count": len(items)})


def handle_staging_edit(req: Request) -> Response:
    """`POST /api/staging/{id}/edit` body `{editor_id, action:"begin"|"end"}`。"""
    staging = req.state.staging
    batch_id = req.param("id")
    payload = req.json_body()
    editor = _editor_id(req, payload)
    action = str(payload.get("action") or "begin").strip().lower()

    if action == "begin":
        batch = _ensure_reviewable(req, batch_id)
        previous = str((batch.editor or {}).get("holder") or "")
        batch = staging.begin_edit(batch_id, holder=editor)
        taken_over = bool(previous) and previous != editor
        _publish_staging(req, batch)
        return Response.json(
            {
                "taken_over": taken_over,
                "batch_id": batch.batch_id,
                "status": batch.status,
                "editor": editor,
            }
        )

    if action == "end":
        batch = staging.end_edit(batch_id)
        _publish_staging(req, batch)
        return Response.json(
            {
                "taken_over": False,
                "batch_id": batch.batch_id,
                "status": batch.status,
                "editor": "",
            }
        )

    raise HttpError(
        400,
        "invalid_action",
        "action 只能是 begin 或 end。",
    )


def handle_staging_items(req: Request) -> Response:
    """`PATCH /api/staging/{id}/items` body `{items:[{index, draft, accepted}], editor_id}`。"""
    staging = req.state.staging
    batch_id = req.param("id")
    payload = req.json_body()

    entries = payload.get("items")
    if not isinstance(entries, list) or not entries:
        raise HttpError(
            400,
            "invalid_request",
            "items 必须是一个非空的数组。",
            hint="每条只传 index 与要改的 draft / accepted。",
        )
    editor = _editor_id(req, payload)

    _ensure_reviewable(req, batch_id)
    batch = staging.get(batch_id)
    items = list(batch.items)

    for entry in entries:
        if not isinstance(entry, dict):
            raise HttpError(400, "invalid_request", "items 的每一项必须是对象。")
        try:
            index = int(entry.get("index"))
        except (TypeError, ValueError) as exc:
            raise HttpError(400, "invalid_index", "index 必须是整数。") from exc
        if index < 0 or index >= len(items):
            raise HttpError(404, "item_not_found", f"没有第 {index} 条草稿。")
        item = items[index]
        draft_payload = entry.get("draft")
        if isinstance(draft_payload, dict):
            item.draft = _merged_record(draft_payload, base=item.draft)
            item.edited = True
        if "accepted" in entry:
            item.accepted = bool(entry["accepted"])

    saved = staging.save_items(batch_id, items, editor=editor)
    _publish_staging(req, saved)
    accepted_count = sum(1 for item in saved.items if item.accepted and not item.has_error)
    return Response.json(
        {
            "batch_id": saved.batch_id,
            "item_count": len(saved.items),
            "accepted_count": accepted_count,
            "status": saved.status,
        }
    )


def _committed_ids(
    staging: Any,
    batch_id: str,
    *,
    before_ids: set[str],
    accept_ids: set[str] | None,
    mode: str,
    vault: Any,
) -> list[str]:
    """提交后按「这一条最终落到哪个 id」收集。overwrite 命中已有记录时用已有 id。"""
    try:
        batch = staging.get(batch_id)
    except Exception:  # noqa: BLE001 - 拿不到批次不影响提交本身的结果
        return []
    index = {
        (str(record.title).casefold().strip(), str(record.username).casefold().strip()): record
        for record in vault.records
    }
    ids: list[str] = []
    for item in batch.items:
        if accept_ids is not None and item.item_id not in accept_ids:
            continue
        if not item.accepted or item.has_error:
            continue
        key = (
            str(item.draft.title).casefold().strip(),
            str(item.draft.username).casefold().strip(),
        )
        resolution = str((item.conflict or {}).get("resolution") or mode)
        record_id = str(item.draft.id or "")
        if record_id in before_ids and resolution == "skip":
            continue
        if resolution == "overwrite":
            existing = index.get(key)
            if existing is not None:
                record_id = existing.id
        if record_id:
            ids.append(record_id)
    return ids


def handle_staging_commit(req: Request) -> Response:
    """`POST /api/staging/{id}/commit` body `{editor_id}` → `{committed, ids, revision}`。"""
    store = _store(req)
    staging = req.state.staging
    batch_id = req.param("id")
    payload = req.json_body()
    _editor_id(req, payload)

    raw_accept = payload.get("accept_item_ids")
    accept_ids: set[str] | None = None
    if isinstance(raw_accept, list):
        accept_ids = {str(value) for value in raw_accept}
    mode = str(payload.get("mode") or "skip").strip().lower()
    if mode not in ("skip", "overwrite", "append"):
        raise HttpError(400, "invalid_mode", "mode 只能是 skip / overwrite / append。")

    # 只有「还没进确认阶段」的批次需要推一把（drafted / failed）。
    # committed / rolled_back / discarded 保持原状态往下走 —— 重复提交的幂等性
    # 由 `StagingStore.commit` 自己保证（它会回 already_committed），这里先拦掉就
    # 会把「安全的重复点击」变成 409。
    current = req.state.staging.get(batch_id)
    if current.status in ("detected", "drafted", "failed"):
        _ensure_reviewable(req, batch_id)
    before_ids = {record.id for record in store.vault.records}

    outcome = staging.commit(
        batch_id,
        store=store,
        accept_item_ids=accept_ids,
        mode=mode,  # type: ignore[arg-type]
    )

    conflicts = outcome.get("conflicts") or []
    if conflicts:
        return Response.json(
            {
                "code": "record_conflict",
                "message": "有记录刚被别的窗口改过，这批没有写入。",
                "hint": "选「跳过 / 覆盖 / 新建副本」后再提交一次。",
                "batch_id": batch_id,
                "status": str(outcome.get("status") or "review"),
                "committed": 0,
                "ids": [],
                "conflicts": conflicts,
            },
            status=409,
        )

    committed = int(outcome.get("added") or 0) + int(outcome.get("updated") or 0)
    ids = (
        _committed_ids(
            staging,
            batch_id,
            before_ids=before_ids,
            accept_ids=accept_ids,
            mode=mode,
            vault=store.vault,
        )
        if committed
        else []
    )

    try:
        batch_row = staging.get(batch_id)
    except Exception:  # noqa: BLE001
        batch_row = None
    if batch_row is not None:
        _publish_staging(req, batch_row)

    log_event("api_staging_commit", scope="pv web", revision=outcome.get("revision"), count=committed)
    payload_out: dict[str, Any] = {
        "committed": committed,
        "ids": ids,
        "revision": outcome.get("revision"),
        "status": str(outcome.get("status") or "committed"),
        "skipped": int(outcome.get("skipped") or 0),
        "batch_id": batch_id,
    }
    if outcome.get("already_committed"):
        payload_out["already_committed"] = True
    if outcome.get("rollback_hint"):
        payload_out["hint"] = str(outcome["rollback_hint"])
    return Response.json(payload_out)


def handle_staging_discard(req: Request) -> Response:
    """`POST /api/staging/{id}/discard` → `{discarded:true}`（并写墓碑，同一文件不再建批）。"""
    staging = req.state.staging
    batch_id = req.param("id")
    req.json_body()  # 契约里 discard 没有入参；这里把坏 JSON 拦成 400，空体照常处理
    staging.discard(batch_id)
    try:
        batch = staging.get(batch_id)
    except Exception:  # noqa: BLE001
        batch = None
    if batch is not None:
        _publish_staging(req, batch)
    log_event("api_staging_discard", scope="pv web", id=batch_id)
    return Response.json({"discarded": True, "batch_id": batch_id})


def handle_staging_rollback(req: Request) -> Response:
    """`POST /api/staging/{id}/rollback` → `{rolled_back:n}`（add 型删除 / overwrite 型还原）。"""
    store = _store(req)
    staging = req.state.staging
    batch_id = req.param("id")
    req.json_body()
    outcome = staging.rollback(batch_id, store=store)
    rolled_back = int(outcome.get("deleted") or 0) + int(outcome.get("restored") or 0)
    try:
        batch = staging.get(batch_id)
    except Exception:  # noqa: BLE001
        batch = None
    if batch is not None:
        _publish_staging(req, batch)
    log_event("api_staging_rollback", scope="pv web", count=rolled_back)
    return Response.json(
        {
            "rolled_back": rolled_back,
            "deleted": int(outcome.get("deleted") or 0),
            "restored": int(outcome.get("restored") or 0),
            "revision": outcome.get("revision"),
            "batch_id": batch_id,
        }
    )


# ---------------------------------------------------------------- inbox 上传
def safe_filename(raw: str) -> str:
    """把上传文件名压成安全的名字：**绝不允许 `../`**，但保留中文。

    步骤：URL 解码（调用方做）→ `\\` 归一成 `/` → `basename` 去掉路径 →
    去控制字符与 Windows 非法字符 → 去首尾点号（挡 `.` / `..` / `...`）→
    `..` 折叠成 `.` → 无后缀补 `.txt`（否则 inbox 监听线程不认这个文件）。
    """
    text = str(raw or "").replace("\\", "/").strip()
    base = os.path.basename(text)
    kept = "".join(
        ch for ch in base if ch.isprintable() and ch not in '<>:"|?*\x00'
    )
    kept = kept.strip().strip(".")
    while ".." in kept:
        kept = kept.replace("..", ".")
    kept = kept.strip().strip(".")
    if not kept:
        kept = "upload.txt"
    if len(kept) > 120:
        stem, dot, suffix = kept.rpartition(".")
        kept = (stem[:100] + "." + suffix) if dot and len(suffix) <= 16 else kept[:120]
    if Path(kept).suffix.lower() not in INBOX_SUFFIXES:
        kept = kept + ".txt"
    return kept


def _unique_target(inbox: Path, name: str) -> Path:
    """同名文件不覆盖：`a.txt` → `a-1.txt` → `a-2.txt` …"""
    target = inbox / name
    if not target.exists():
        return target
    stem = Path(name).stem
    suffix = Path(name).suffix
    for counter in range(1, 1000):
        candidate = inbox / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
    raise HttpError(409, "inbox_busy", "inbox 里同名文件太多了，先清理一下。")


def handle_inbox_upload(req: Request) -> Response:
    """`POST /api/inbox/upload`：`application/octet-stream` + `X-Filename`（urlencode）。

    只落盘、**同步解析一律不做** —— 解析与建批次是监听线程的事（`inbox.py`），
    在这里解析会把一个 2 秒的轮询变成一次可能几秒的阻塞请求，还会让「建批次」
    有两份实现。落盘用 `vault.atomic_write`，避免监听线程读到半个文件。
    """
    req.state.require_unlocked()
    settings = req.state.settings

    raw_name = str(req.headers.get("x-filename") or "")
    name = safe_filename(urllib.parse.unquote(raw_name))
    data = req.body
    if not data:
        raise HttpError(400, "empty_upload", "上传内容是空的。")

    limit = int(getattr(settings, "inbox_max_file_bytes", 2 * 1024 * 1024))
    if len(data) > limit:
        raise HttpError(
            413,
            "file_too_large",
            f"这个文件太大了（{len(data)} 字节）。",
            hint=f"单个文件最大 {limit // 1024} KB，请先拆分。",
        )

    inbox = settings.inbox_path
    inbox.mkdir(parents=True, exist_ok=True)
    target = _unique_target(inbox, name)
    atomic_write(target, data)
    log_event("api_inbox_upload", scope="pv web", count=len(data))
    return Response.json(
        {
            "pending": True,
            "file": target.name,
            "size": len(data),
            "hint": "文件已放进 inbox，监听线程会在 2 秒内把它变成待整理批次。",
        }
    )


# ---------------------------------------------------------------- 体检
def _looks_synced(vault_path: Path) -> bool:
    """路径里有没有网盘同步目录的特征（只做提示，不做判断）。"""
    text = str(vault_path).replace("\\", "/").casefold()
    return any(marker in text for marker in _SYNC_MARKERS)


def _snapshot_info(settings: Any) -> dict:
    directory = settings.snapshot_dir
    last_days: int | None = None
    try:
        snaps = sorted(directory.glob("data-*.enc"))
        if snaps:
            newest = max(snaps, key=lambda path: path.stat().st_mtime)
            last_days = int(max(0.0, (time.time() - newest.stat().st_mtime) // 86400))
    except OSError:
        last_days = None
    return {
        "last_days": last_days,
        "dir": str(directory),
        "looks_synced": _looks_synced(settings.vault_path),
    }


def handle_health(req: Request) -> Response:
    """`GET /api/health` → 四类问题 + 快照状态。

    `reused_groups` **只给标题，绝不给密码**：复用检测的中间结果是密码的
    sha256 分桶，那个桶号对离线爆破毫无意义但也毫无用处，干脆连桶号都不出门。
    """
    store = _store(req)
    report = service.health(store.vault)

    weak = [
        {
            "id": str(row.get("id") or ""),
            "title": str(row.get("title") or ""),
            "entropy": float(row.get("entropy") or 0.0),
            "level": str(row.get("level") or ""),
        }
        for row in (report.get("weak_passwords") or [])
    ]
    reused_groups = [
        {"titles": [str(title) for title in titles], "count": len(titles)}
        for titles in (report.get("reused_passwords") or [])
        if titles
    ]
    stale = [
        {
            "id": str(row.get("id") or ""),
            "title": str(row.get("title") or ""),
            "days": int(row.get("days") or 0),
        }
        for row in (report.get("stale_passwords") or [])
    ]
    no_password = [
        {"id": str(row.get("id") or ""), "title": str(row.get("title") or "")}
        for row in (report.get("without_password") or [])
    ]
    return Response.json(
        {
            "weak": weak,
            "reused_groups": reused_groups,
            "stale": stale,
            "no_password": no_password,
            "snapshot": _snapshot_info(req.state.settings),
            "total": int(report.get("total") or 0),
            "with_totp": int(report.get("with_totp") or 0),
        }
    )


# ---------------------------------------------------------------- MCP 一键接入
#: 降级路径用的模块名：只有定位不到 `pv.py` 时才用 `python -m <它>`（见 `_mcp_command`）。
MCP_MODULE = "pwdvault.mcp_server"

#: `pv.py` 的子命令（T12 已落地）。正常配置就是 `[<pv.py 绝对路径>, "mcp"]`。
MCP_SUBCOMMAND = "mcp"

#: 客户端配置里的服务端键名（两个客户端都用同一个名字，用户好对照）。
MCP_SERVER_KEY = "pwdvault"

#: 给用户抄的路径提示（WorkBuddy 的配置文件位置）。
WORKBUDDY_CONFIG_PATH = "~/.workbuddy/mcp.json"

WORKBUDDY_HINT = (
    f"粘贴到 {WORKBUDDY_CONFIG_PATH} 的 mcpServers 里，然后在连接器管理页右上角"
    "「自定义连接器」点「信任」；不重启客户端不会生效"
)
DEEPSEEK_HARNESS_HINT = "粘贴到 deepseek-harness 的 MCP 配置段（stdio 类型）"

#: 四条固定说明。每一条都对应一个「用户真的会踩」的坑，不要删减。
MCP_BASE_NOTES: tuple[str, ...] = (
    "首次使用前请先在本机启用一次免密（pv local-unlock on）；只在 Web 界面解锁不会让 MCP 进程可读——两边各有各的密钥。",
    "MCP 进程无法交互输入主密码（stdin 被 JSON-RPC 协议占用），库锁着时工具只会返回 locked。",
    "不要把主密码写进 MCP 配置（不要加 PV_MASTER_PASSWORD）：那等于把主密码明文存进客户端配置文件。"
    "需要免密请用 pv local-unlock on（密钥由 Windows DPAPI 保管，落盘的只有密文）。",
    "改完配置文件必须重启客户端：WorkBuddy 的 ~/.workbuddy/mcp.json 不热重载，"
    "重启后工具数量没变就是没生效。",
)


def _project_root() -> Path | None:
    """项目根目录（`pwdvault/web/api.py` 往上两级）。

    推导不出来返回 None —— 调用方必须把「拿不到」如实写进 notes，
    **不允许**编一个看起来很像的假路径（用户照着粘贴会得到一个启动就崩的配置）。
    """
    try:
        return Path(__file__).resolve().parents[2]
    except (IndexError, OSError, ValueError):  # pragma: no cover - 打包成 zip 等极端情况
        return None


def _python_executable() -> str | None:
    """当前解释器的绝对路径。不是真文件（如空串/嵌入模式）就返回 None。"""
    raw = str(sys.executable or "").strip()
    if not raw:
        return None
    try:
        path = Path(raw).resolve()
        if not path.is_file():
            return None
    except OSError:  # pragma: no cover - 权限异常
        return None
    return str(path)


def _vault_path_text(settings: Any) -> str | None:
    """当前配置里 vault 的真实绝对路径（不判断是否存在，存在与否另写 note）。"""
    try:
        return str(Path(settings.vault_path).expanduser().resolve())
    except (OSError, RuntimeError, TypeError, ValueError):  # pragma: no cover - 防御性
        return None


def _mcp_tool_names() -> tuple[list[str], str]:
    """从 `mcp_tools.TOOLS` 现读工具名。

    绝不在这里手抄一份列表：那一定会随 T07/T12 的工具增减而过期，而过期的清单
    比没有清单更糟 —— 用户会照着文档去调一个不存在的工具。

    返回 `(名字列表, 失败说明)`；失败说明为空表示读到了。
    """
    try:
        from ..mcp_tools import TOOLS  # noqa: PLC0415 - 延迟导入：web 层不必在启动时依赖 L4
    except Exception:  # noqa: BLE001 - 工具清单读不到不该让整个接口 500
        return [], "没能读到 MCP 工具清单（pwdvault.mcp_tools 导入失败），下面的 tools 列表可能为空。"
    return [str(spec.name) for spec in TOOLS], ""


def _mcp_command(entry: str | None) -> tuple[list[str], list[str]]:
    """MCP 进程的启动参数。返回 `(args, notes)`。

    首选 `[<pv.py 绝对路径>, "mcp"]`，而不是 `["-m", "pwdvault.mcp_server"]`：

    * `pv.py` 启动时会把**自身所在目录**插进 `sys.path`，所以这么跑**不需要
      `PYTHONPATH`** —— 少一个环境变量就少一个「用户手抄漏了」的故障点；
    * 与命令行里的 `pv mcp` 完全一致，用户看文档和看 JSON 是同一件事；
    * 不受客户端工作目录影响（客户端拉起子进程时的 cwd 不可控）。

    只有定位不到 `pv.py`（打包成 zip、源码被裁剪等极端情况）才降级回
    `["-m", MCP_MODULE]` + `PYTHONPATH`：那种情况下宁可多一个环境变量，
    也不能给出一份启动不起来的配置。
    """
    if entry:
        return [entry, MCP_SUBCOMMAND], [
            "启动用的是 python + pv.py 的绝对路径（等价于命令行的 pv mcp），不依赖 PYTHONPATH；"
            "如果移动了 pv.py 或整个项目目录，要回来重新复制一次配置。"
        ]
    return ["-m", MCP_MODULE], [
        "没能定位到 pv.py，已降级为 python -m pwdvault.mcp_server："
        "这种形式依赖 env 里的 PYTHONPATH 才能找到 pwdvault 包，不要删。"
    ]


def _mcp_server_entry(
    args: list[str],
    python: str | None,
    vault: str | None,
    pythonpath: str | None = None,
) -> dict:
    """一个客户端配置项（`command` / `args` / `env`）。

    `env` 里只有路径级信息：
      * `PV_VAULT`：让 MCP 进程连到这一个库（不是默认 ~/pwdvault）；
      * `PYTHONPATH`：**仅降级路径**（`-m` 形式）才出现，正常配置里没有这一项。
    **永远不放** `PV_MASTER_PASSWORD` —— 那等于把主密码明文写进客户端配置。
    """
    env: dict[str, str] = {}
    if vault:
        env["PV_VAULT"] = vault
    if pythonpath:
        env["PYTHONPATH"] = str(pythonpath)
    entry: dict[str, Any] = {"command": python, "args": list(args)}
    if env:
        entry["env"] = env
    return entry


def handle_mcp_config(req: Request) -> Response:
    """`GET /api/mcp-config` → 可直接粘贴给 MCP 客户端的配置（含工具清单与注意事项）。

    **不需要解锁**：整份响应只有路径、工具名和说明文字，不含任何记录数据，
    所以锁着也能给（用户往往是「先配客户端、再想起来解锁」）。
    仍然走 session token 校验 —— 它暴露了本机的绝对路径，不该让同机其它网页读到。
    """
    settings = req.state.settings
    python = _python_executable()
    root = _project_root()
    vault = _vault_path_text(settings)

    entry_path = (root / "pv.py") if root is not None else None
    entry: str | None = None
    if entry_path is not None:
        try:
            if entry_path.is_file():
                entry = str(entry_path.resolve())
        except OSError:  # pragma: no cover - 权限异常
            entry = None

    tools, tools_note = _mcp_tool_names()
    args, command_notes = _mcp_command(entry)
    # 正常路径（args = [pv.py, "mcp"]）不需要 PYTHONPATH；只有 entry 定位失败、
    # 降级成 `-m pwdvault.mcp_server` 时才把项目根塞进 env，否则那份配置启动不起来。
    pythonpath = str(root) if (entry is None and root is not None) else None
    # 两个客户端各拿**独立的一份**（同一个 dict 对象被两处引用时，将来谁改一处
    # 都会静默影响另一处；这里多构造一次是免费的）。
    workbuddy_entry = _mcp_server_entry(args, python, vault, pythonpath)
    harness_entry = _mcp_server_entry(args, python, vault, pythonpath)

    notes: list[str] = list(MCP_BASE_NOTES)
    notes.extend(command_notes)
    if python is None:
        notes.append("没能确定当前 Python 解释器的绝对路径：请把 config 里的 command 改成你机器上的 python.exe。")
    if entry is None:
        notes.append("没能定位到 pv.py 的绝对路径：请把 config 里 args 的第一项手工改成本机 pv.py 的真实路径（并删掉 PYTHONPATH）。")
    if vault is None:
        notes.append("没能确定密码库文件路径：请在 config 的 env 里自己填 PV_VAULT。")
    else:
        try:
            exists = Path(vault).exists()
        except OSError:  # pragma: no cover
            exists = False
        if not exists:
            notes.append(f"密码库文件还不存在（{vault}）：先运行 pv init 建库，再让客户端连。")
    if tools_note:
        notes.append(tools_note)

    return Response.json(
        {
            "python": python,
            "entry": entry,
            "vault": vault,
            "tools": tools,
            "workbuddy": {
                "hint": WORKBUDDY_HINT,
                "config": {MCP_SERVER_KEY: workbuddy_entry},
            },
            "deepseek_harness": {
                "hint": DEEPSEEK_HARNESS_HINT,
                "config": {"mcpServers": {MCP_SERVER_KEY: harness_entry}},
            },
            "notes": notes,
        }
    )


# ---------------------------------------------------------------- 注册
def _guard_locked(handler: Callable[[Request], Response]) -> Callable[[Request], Response]:
    """唯一的 `Locked` → 401 翻译点（其它 `VaultError` 交给 dispatcher 按表翻译）。"""

    def wrapped(req: Request) -> Response:
        try:
            return handler(req)
        except HttpError:
            raise
        except VaultError as exc:
            if exc.code == "locked":
                raise HttpError(
                    401,
                    "locked",
                    str(exc.message or "密码库现在是锁着的。"),
                    hint="先解锁",
                ) from exc
            raise

    wrapped.__name__ = getattr(handler, "__name__", "handler")
    wrapped.__doc__ = getattr(handler, "__doc__", None)
    return wrapped


#: (方法, 路径, handler)。路径里的 `{name}` 由 `Router.compile` 编译成命名分组。
ROUTES: tuple[tuple[str, str, Callable[[Request], Response]], ...] = (
    ("GET", "/api/records", handle_records_list),
    ("POST", "/api/records", handle_record_create),
    ("GET", "/api/records/{id}", handle_record_detail),
    ("PATCH", "/api/records/{id}", handle_record_patch),
    ("DELETE", "/api/records/{id}", handle_record_delete),
    ("POST", "/api/records/{id}/copy", handle_record_copy),
    ("GET", "/api/tags", handle_tags),
    ("GET", "/api/staging", handle_staging_list),
    ("GET", "/api/staging/{id}", handle_staging_detail),
    ("POST", "/api/staging/{id}/edit", handle_staging_edit),
    ("PATCH", "/api/staging/{id}/items", handle_staging_items),
    ("POST", "/api/staging/{id}/commit", handle_staging_commit),
    ("POST", "/api/staging/{id}/discard", handle_staging_discard),
    ("POST", "/api/staging/{id}/rollback", handle_staging_rollback),
    ("POST", "/api/inbox/upload", handle_inbox_upload),
    ("GET", "/api/health", handle_health),
    ("GET", "/api/mcp-config", handle_mcp_config),
)


def register_api_routes(server: WebServer) -> None:
    """把业务路由挂到 `WebServer.router` 上（幂等：重复调只会覆盖同一路径的分发器）。

    为什么不是「一条路由一个 handler」直接 `router.add`：T08 的 `Router.add` 是按
    **正则模式**去重的（`/api/records/{id}` 的 GET / PATCH / DELETE 是同一个模式），
    它会把 methods 并起来但**只保留最后一次的 handler**。于是 `GET /api/records/{id}`
    会拿到 DELETE 的 handler —— 这不是理论风险，是本轮实测踩到的（详情页一打开就
    报「删除需要确认标题」）。

    所以这里按**路径分组**，每组注册一个「按 `req.method` 分派」的闭包，同一个闭包
    注册给该路径的所有方法。`Router` 一行都不用改，方法不匹配仍然由它回 405。
    """
    grouped: dict[str, dict[str, Callable[[Request], Response]]] = {}
    for method, path, handler in ROUTES:
        grouped.setdefault(path, {})[method] = _guard_locked(handler)

    for path, by_method in grouped.items():
        dispatch = _method_dispatcher(path, by_method)
        for method in by_method:
            server.router.add(method, path, dispatch)


def _method_dispatcher(
    path: str, by_method: dict[str, Callable[[Request], Response]]
) -> Callable[[Request], Response]:
    """同路径多方法的分发器（`Router` 已经按方法过滤过，这里只是兜底）。"""

    def dispatch(req: Request) -> Response:
        handler = by_method.get(str(req.method).upper())
        if handler is None:
            raise HttpError(405, "method_not_allowed", "这个路径不支持该请求方法。")
        return handler(req)

    dispatch.__name__ = "api" + "".join(ch if ch.isalnum() else "_" for ch in path)
    return dispatch



__all__ = [
    "DEFAULT_LIST_LIMIT",
    "EDITOR_HEADER",
    "MAX_LIST_LIMIT",
    "MCP_BASE_NOTES",
    "MCP_MODULE",
    "MCP_SERVER_KEY",
    "MCP_SUBCOMMAND",
    "REVEAL_WARNING",
    "ROUTES",
    "handle_health",
    "handle_inbox_upload",
    "handle_mcp_config",
    "handle_record_copy",
    "handle_record_create",
    "handle_record_delete",
    "handle_record_detail",
    "handle_record_patch",
    "handle_records_list",
    "handle_staging_commit",
    "handle_staging_detail",
    "handle_staging_discard",
    "handle_staging_edit",
    "handle_staging_items",
    "handle_staging_list",
    "handle_staging_rollback",
    "handle_tags",
    "register_api_routes",
    "safe_filename",
]
