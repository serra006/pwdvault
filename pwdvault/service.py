"""业务层：增删改查、搜索、TOTP、导入合并、体检统计。

这一层不碰文件、不碰加密原语、不碰 requests/argv，只接收一个已解锁的 Vault。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import socket
import struct
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from . import clipboard
from .errors import AmbiguousRecord, InvalidRecord, RecordNotFound
from .models import (
    Record,
    Warning,
    is_sensitive_key,
    looks_like_totp,
    new_id,
    now_iso,
    score_secret,
)
from .vault import Vault

FIELD_PREFIXES = ("title", "user", "url", "tag", "note", "field")

# 条目级校验常量（PRD §6.3）
PHONE_USERNAME_RE = re.compile(r"^1[3-9]\d{9}$")
LONG_VALUE_LIMIT = 128

# importers 旁路采集到的 note code → 条目警告
# 说明：`title_inferred`（标题是从别的字段推断出来的）按架构裁决 R3 落成
# `title_missing` + level=error（该条不可提交），因为 `Record.from_dict` 本身
# 不会产出「无标题」的草稿。
NOTE_WARNING_MAP: dict[str, Warning] = {
    "password_trimmed": Warning(
        code="password_trimmed",
        level="warn",
        message="密码两端有空格，已去除",
        field="password",
    ),
    "title_inferred": Warning(
        code="title_missing",
        level="error",
        message="没有标题，是从其他字段推断出来的，请确认后再提交",
        field="title",
    ),
    "long_value": Warning(
        code="long_password",
        level="warn",
        message="密码超过 128 个字符，可能把整段文本当成了密码",
        field="password",
    ),
}
WARNING_LONG_PASSWORD = NOTE_WARNING_MAP["long_value"]


# --------------------------------------------------------------------- 搜索
def _fields_of(record: Record) -> dict[str, str]:
    data = {
        "title": record.title.casefold(),
        "user": record.username.casefold(),
        "url": record.url.casefold(),
        "note": record.notes.casefold(),
        "tag": " ".join(record.tags).casefold(),
    }
    for key, value in record.fields.items():
        data[f"field:{key.casefold()}"] = value.casefold()
    return data


def _score_one(fields: dict[str, str], token: str, limit_to: str | None) -> int:
    best = 0
    for name, value in fields.items():
        if limit_to:
            if limit_to.startswith("field"):
                if not name.startswith("field") and limit_to != "field":
                    continue
                if token not in value:
                    continue
            elif name != limit_to:
                continue
        if not value or token not in value:
            continue
        if name == "title":
            score = 100 if value == token else (80 if value.startswith(token) else 65)
        elif name == "tag":
            score = 60 if token in value.split() else 40
        elif name == "user":
            score = 50 if value == token else 45
        elif name == "url":
            score = 40
        else:
            score = 25
        best = max(best, score)
    return best


def parse_query(query: str) -> list[tuple[str | None, str]]:
    tokens: list[tuple[str | None, str]] = []
    for raw in query.split():
        if ":" in raw:
            prefix, _, rest = raw.partition(":")
            if prefix.lower() in FIELD_PREFIXES and rest:
                tokens.append((prefix.lower(), rest.casefold()))
                continue
        tokens.append((None, raw.casefold()))
    return tokens


def search(vault: Vault, query: str, *, limit: int | None = None) -> list[Record]:
    tokens = parse_query(query)
    if not tokens:
        return list(vault.records)

    scored: list[tuple[int, Record]] = []
    for record in vault.records:
        fields = _fields_of(record)
        total = 0
        hit_all = True
        for limit_to, token in tokens:
            score = _score_one(fields, token, limit_to)
            if score == 0:
                hit_all = False
                break
            total += score
        if hit_all:
            scored.append((total, record))

    scored.sort(key=lambda pair: (-pair[0], pair[1].title.casefold()))
    records = [record for _, record in scored]
    return records[:limit] if limit else records


def resolve(vault: Vault, ref: str) -> Record:
    """按 id → 精确标题 → 唯一模糊匹配 的顺序定位记录。"""
    by_id = vault.find_by_id(ref)
    if by_id:
        return by_id

    exact = [r for r in vault.records if r.title.casefold() == ref.casefold()]
    if len(exact) == 1:
        return exact[0]

    matches = search(vault, ref)
    if not matches:
        raise RecordNotFound(ref)
    if len(matches) > 1:
        raise AmbiguousRecord(ref, [f"{r.title}({r.id})" for r in matches[:5]])
    return matches[0]


# --------------------------------------------------------------------- 写入
def add(vault: Vault, record: Record) -> Record:
    if not record.title.strip():
        raise InvalidRecord("标题不能为空")
    vault.records.append(record)
    vault.touch()
    return record


def update(vault: Vault, record: Record, changes: dict[str, str]) -> Record:
    """字段变更的唯一实现下沉到 `Record.apply_changes`（rebase 也要用它）。"""
    record.apply_changes(changes)
    vault.touch()
    return record


def delete(vault: Vault, record: Record) -> None:
    vault.records = [r for r in vault.records if r.id != record.id]
    vault.touch()


def add_note(vault: Vault, record: Record, text: str) -> Record:
    record.notes = (record.notes + " " + text).strip() if record.notes else text
    record.updated = now_iso()
    vault.touch()
    return record


# --------------------------------------------------------------------- 校验
def _dedup_key(record: Record) -> tuple[str, str]:
    return (record.title.casefold().strip(), record.username.casefold().strip())


def _validate_one(
    record: Record,
    *,
    seen: set[tuple[str, str]],
    notes_codes: set[str],
) -> list[Warning]:
    """单条记录的确定性校验（PRD §6.3 的 8 类规则）。

    `seen` 是「已占用」的 (title, username) 集合，**会被就地更新**，
    这样批次内部的重复也能检出。
    """
    warnings: list[Warning] = []

    # 1. 缺标题（含「标题是推断出来的」，裁决 R3）
    if "title_inferred" in notes_codes:
        warnings.append(NOTE_WARNING_MAP["title_inferred"])
    elif not str(record.title or "").strip():
        warnings.append(
            Warning(code="title_missing", level="error", message="没有标题，这条不能提交", field="title")
        )

    # 2. 无账号且无密码 → 可能是注释行
    if not str(record.username or "").strip() and not str(record.password or ""):
        warnings.append(
            Warning(
                code="empty_record",
                level="warn",
                message="没有账号也没有密码，可能是一行注释",
                field=None,
            )
        )

    # 3. 密码首尾空格被裁剪（只能由 importers 旁路采集）
    if "password_trimmed" in notes_codes:
        warnings.append(NOTE_WARNING_MAP["password_trimmed"])

    # 4. 账号看起来是手机号
    if PHONE_USERNAME_RE.match(str(record.username or "").strip()):
        warnings.append(
            Warning(
                code="phone_username",
                level="info",
                message="账号看起来是手机号",
                field="username",
            )
        )

    # 5. 密码与账号相同
    if record.password and record.username and record.password == record.username:
        warnings.append(
            Warning(
                code="password_equals_username",
                level="warn",
                message="账号与密码相同",
                field="password",
            )
        )

    # 6. 超长值被当成密码
    if len(str(record.password or "")) > LONG_VALUE_LIMIT or "long_value" in notes_codes:
        warnings.append(WARNING_LONG_PASSWORD)

    # 7. 非 totp 字段里出现 Base32 种子
    for name, value in record.fields.items():
        if is_sensitive_key(name):
            continue
        if looks_like_totp(str(value)):
            warnings.append(
                Warning(
                    code="base32_in_field",
                    level="info",
                    message="这个字段看起来是 TOTP 种子，可以移到动态码字段",
                    field=name,
                )
            )
            break

    # 8. 与现有记录 / 本批次前面的记录重复
    key = _dedup_key(record)
    if key[0] and key in seen:
        warnings.append(
            Warning(
                code="duplicate_record",
                level="conflict",
                message="库里已有标题与账号都相同的记录",
                field=None,
            )
        )
    seen.add(key)

    return warnings


def validate_records(
    records_or_vault,
    records: list[Record] | None = None,
    *,
    seen: set[tuple[str, str]] | None = None,
    notes=None,
) -> list[list[Warning]]:
    """逐条校验，返回与输入等长的警告列表。

    两种调用形态都支持（PRD 与设计文档写法不同，这里都接受）：
      - `validate_records(records)`                       —— 只做记录自身规则
      - `validate_records(vault, records)`                —— 额外查「与库里重复」

    `seen` 可传入已占用的 (title, username) 集合（就地更新）。
    `notes` 是 `importers.parse_any(notes=...)` 采到的 `(index, code)` 序列，
    index 从 1 开始，与本列表顺序对应；这是 8 类规则里 3 类「只能旁路知道」
    的信息来源（密码被裁剪 / 标题靠推断 / 超长值）。
    """
    if records is None:
        items = list(records_or_vault)  # type: ignore[arg-type]
        existing: list[Record] = []
    else:
        items = list(records)
        source = records_or_vault
        existing = list(getattr(source, "records", source) or [])

    taken = seen if seen is not None else set()
    for record in existing:
        taken.add(_dedup_key(record))

    notes_by_index: dict[int, set[str]] = {}
    for entry in notes or ():
        try:
            index, code = entry
        except (TypeError, ValueError):
            continue
        notes_by_index.setdefault(int(index), set()).add(str(code))

    out: list[list[Warning]] = []
    for position, record in enumerate(items, start=1):
        out.append(_validate_one(record, seen=taken, notes_codes=notes_by_index.get(position, set())))
    return out


def warnings_to_dicts(warnings: list[Warning]) -> list[dict]:
    return [warning.to_dict() for warning in warnings]


# --------------------------------------------------------------------- 复制
def _field_value(record: Record, field: str) -> str:
    core = ("title", "username", "password", "url", "notes", "totp")
    if field in core:
        return str(getattr(record, field) or "")
    if field in ("user", "account"):
        return str(record.username or "")
    return str(record.fields.get(field, "") or "")


def copy_field(
    record_or_vault,
    record: Record | None = None,
    field: str = "password",
    *,
    seconds: int = 30,
    spawn: bool = True,
) -> dict:
    """把某个字段复制到本机剪贴板，返回回执（**不含明文**）。

    UI 与 MCP 共用这一个出口。三种写法都接受：
        copy_field(record)
        copy_field(record, "password")              # 第二个位置参数**也是** field
        copy_field(vault, record, "password")

    上面第二种写法曾是个坑：`record` 形参接住 `"password"` 后直接抛
    `invalid_record`（"copy_field 需要一个记录对象"），报错信息完全指不到真正的原因。
    所以显式做一次位置纠偏（见下方 `isinstance(record, str)` 分支）。

    **位置纠偏是历史兼容，不是 bug，请不要"修"掉它**：v1.0 与第三方脚本可能就是这么
    调的，改成硬失败会打断它们，而报错文案对用户毫无意义。第二位置参数按 `field`
    解释（`str` 与 `Record` 类型完全不同，能安全区分，不存在真歧义）；只有「第二个
    位置参数 + 显式 `field=`」同时出现才抛 `invalid_record`，那才是真错位。
    新代码请写 `copy_field(record, field="password", ...)` —— 显式关键字更清晰。

    明文只作为局部变量存在，取到摘要后立刻丢弃，不进入任何容器。

    Args:
        record_or_vault: 记录对象；或第一个位置参数传了 vault（兼容旧写法）。
        record: 记录对象（当 `record_or_vault` 是 vault 时必传）。
        field: password / username / url / totp 或自定义字段名。
        seconds: 自动清空秒数。`<= 0` 表示**不装定时器**，回执里
            `auto_clear=false` / `auto_clear_in=0` —— 不承诺「0 秒后清空」这种
            自相矛盾的倒计时。
        spawn: True（默认，向后兼容）用分离子进程清空，CLI 继续用；
            False 用进程内 daemon 定时器 —— MCP 是长驻进程，进程内更可靠
            （子进程方式依赖 argv[0] 认 `_clipwatch`，`python -m` 入口下会静默失效）。

    回执里的 `auto_clear` 是「定时器到底装上没有」，`auto_clear_in` 只有在真的装上时
    才等于 `seconds`，否则为 0 —— 宁可如实说没装，也不许撒谎说 30 秒后清空。
    """
    if isinstance(record, str) and record:
        # 位置纠偏：copy_field(record, "password") —— 第二个位置参数其实是 field。
        if field == "password":  # 没被显式覆盖过，才把字符串挪到 field
            record, field = None, record
        else:
            raise InvalidRecord("copy_field 第二个位置参数是 field，请写 copy_field(record, field=\"...\")")

    target = record if record is not None else record_or_vault
    if not isinstance(target, Record):
        raise InvalidRecord("copy_field 需要一个记录对象")

    value = _field_value(target, field)
    if not value:
        raise InvalidRecord(f"{target.title} 没有 {field} 可复制")

    seconds = int(seconds)
    if seconds <= 0:
        # 0 秒绝不能落进 `copy_with_autoclear`：它会把 delay 夹到 0.0 然后
        # `threading.Timer(0, ...)` 立刻触发 —— 用户还没粘贴，剪贴板就被清空了。
        # 所以这一档直接走纯复制，回执如实说「没装定时器」。
        clipboard.copy_text(value)
        del value
        return {
            "copied": True,
            "title": target.title,
            "field": field,
            "auto_clear": False,
            "auto_clear_in": 0,
            "auto_clear_mode": "none",
            "host": socket.gethostname(),
            "hint": (
                "这次没有设置自动清空，剪贴板里的内容会一直留到你下次复制别的。"
                "用完请手动复制一个无关内容覆盖它。"
            ),
        }

    outcome = clipboard.copy_with_autoclear(value, seconds, spawn=spawn)
    del value

    armed = bool(outcome.get("auto_clear"))
    receipt = {
        "copied": True,
        "title": target.title,
        "field": field,
        "auto_clear": armed,
        "auto_clear_in": seconds if armed else 0,
        "auto_clear_mode": str(outcome.get("mode") or "none") if armed else "none",
        "host": socket.gethostname(),
    }
    if not armed:
        receipt["hint"] = (
            "这次没能装上自动清空定时器，剪贴板里的内容会一直留到你下次复制别的。"
            "用完请手动复制一个无关内容覆盖它。"
        )
    return receipt


# --------------------------------------------------------------------- 导入
def merge_import(
    vault: Vault,
    incoming: list[Record],
    *,
    mode: str = "skip",
    apply: bool = True,
) -> dict:
    """把导入记录合并进 vault。

    mode: skip 已存在的跳过 / update 已存在则更新 / append 一律新增
    去重键：标题 + 用户名（都做 casefold）
    """
    index: dict[tuple[str, str], Record] = {}
    existing_ids = set()
    for record in vault.records:
        index[(record.title.casefold(), record.username.casefold())] = record
        existing_ids.add(record.id)

    report = {"added": 0, "updated": 0, "skipped": 0, "details": []}

    # 逐条警告：v1.1 只**新增** details[i]["warnings"] 这个键，其余键语义不变
    seen_keys = {_dedup_key(record) for record in vault.records}
    warning_rows = validate_records(incoming, seen=seen_keys) if incoming else []

    for position, record in enumerate(incoming):
        key = (record.title.casefold(), record.username.casefold())
        existing = index.get(key)
        row_warnings = warnings_to_dicts(warning_rows[position]) if position < len(warning_rows) else []
        if existing and mode == "skip":
            report["skipped"] += 1
            report["details"].append(
                {"action": "skip", "title": record.title, "warnings": row_warnings}
            )
            continue
        if existing and mode == "update":
            for field in ("password", "url", "notes", "totp"):
                value = getattr(record, field)
                if value:
                    setattr(existing, field, value)
            existing.tags = list(dict.fromkeys(existing.tags + record.tags))
            existing.fields.update(record.fields)
            existing.updated = now_iso()
            report["updated"] += 1
            report["details"].append(
                {"action": "update", "title": record.title, "id": existing.id, "warnings": row_warnings}
            )
            continue

        if existing and mode == "append":
            record.id = new_id()
        if record.id in existing_ids:
            record.id = new_id()  # 绝不接受与现有记录重复的 id
        if apply:
            vault.records.append(record)
        index[key] = record
        report["added"] += 1
        report["details"].append(
            {"action": "add", "title": record.title, "id": record.id, "warnings": row_warnings}
        )

    if apply and (report["added"] or report["updated"]):
        vault.touch()
    return report


# --------------------------------------------------------------------- TOTP
def extract_totp_secret(raw: str) -> str:
    text = (raw or "").strip()
    if text.lower().startswith("otpauth://"):
        query = parse_qs(urlparse(text).query)
        secret = query.get("secret", [""])[0]
        return secret
    return text


def totp_code(secret: str, *, digits: int = 6, period: int = 30, at: float | None = None) -> tuple[str, int]:
    """按 RFC 6238 生成动态码，返回（验证码, 剩余秒数）。"""
    cleaned = extract_totp_secret(secret)
    cleaned = "".join(ch for ch in cleaned.upper() if ch.isalnum())
    if not cleaned:
        raise InvalidRecord("TOTP 种子为空")
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        key = base64.b32decode(cleaned + pad)
    except Exception as exc:  # noqa: BLE001
        raise InvalidRecord(f"TOTP 种子不是合法 Base32：{exc}") from exc

    now = time.time() if at is None else at
    counter = int(now // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(value % (10**digits)).zfill(digits)
    remain = period - int(now % period)
    return code, remain


# --------------------------------------------------------------------- 体检
def health(vault: Vault) -> dict:
    total = len(vault.records)
    without_password = [r for r in vault.records if not r.password]
    weak = []
    for record in vault.records:
        if not record.password:
            continue
        entropy, level = score_secret(record.password)
        if entropy < 45:
            weak.append({"id": record.id, "title": record.title, "entropy": entropy, "level": level})

    buckets: dict[str, list[str]] = {}
    for record in vault.records:
        if record.password:
            digest = hashlib.sha256(record.password.encode("utf-8")).hexdigest()
            buckets.setdefault(digest, []).append(record.title)
    reused = [titles for titles in buckets.values() if len(titles) > 1]

    tag_counter = Counter(tag for record in vault.records for tag in record.tags)

    def days_since(stamp: str) -> int | None:
        if not stamp:
            return None
        try:
            moment = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - moment).days

    stale = []
    for record in vault.records:
        age = days_since(record.pw_changed or record.created)
        if age is not None and age > 365:
            stale.append({"id": record.id, "title": record.title, "days": age})

    return {
        "total": total,
        "with_totp": sum(1 for r in vault.records if r.totp),
        "without_password": [{"id": r.id, "title": r.title} for r in without_password],
        "weak_passwords": weak,
        "reused_passwords": reused,
        "stale_passwords": sorted(stale, key=lambda item: -item["days"])[:10],
        "tags": tag_counter.most_common(15),
    }
