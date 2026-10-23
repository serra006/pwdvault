"""记录模型与字段归一化。

「尽量自由」是硬要求：除了固定的主字段，任何多余键都会被原样收进 fields 字典，
所以 agent 从明文 TXT 里归纳出来的自定义信息（密保问题、绑定的手机号、
保险箱编号、API Key……）都能被完整保存，不会因为「没有这个字段」而丢失。
"""

from __future__ import annotations

import math
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from .errors import InvalidRecord

# 中英别名 → 标准字段名。顺序敏感：先匹配更具体的。
ALIASES: dict[str, str] = {
    "id": "id",
    "uid": "id",
    "title": "title",
    "name": "title",
    "site": "title",
    "sitename": "title",
    "service": "title",
    "app": "title",
    "platform": "title",
    "website_name": "title",
    "站点": "title",
    "网站": "title",
    "标题": "title",
    "名称": "title",
    "服务": "title",
    "平台": "title",
    "软件": "title",
    "应用": "title",
    "username": "username",
    "user": "username",
    "login": "username",
    "loginname": "username",
    "account": "username",
    "acct": "username",
    "email": "username",
    "mail": "username",
    "phone": "username",
    "mobile": "username",
    "账号": "username",
    "帐号": "username",
    "用户名": "username",
    "账户": "username",
    "帐户": "username",
    "登录名": "username",
    "登录账号": "username",
    "邮箱": "username",
    "手机": "username",
    "手机号": "username",
    "电话": "username",
    "password": "password",
    "pass": "password",
    "passwd": "password",
    "pwd": "password",
    "pw": "password",
    "secret_code": "password",
    "密码": "password",
    "口令": "password",
    "登录密码": "password",
    "url": "url",
    "uri": "url",
    "link": "url",
    "website": "url",
    "site_url": "url",
    "homepage": "url",
    "网址": "url",
    "链接": "url",
    "地址": "url",
    "官网": "url",
    "首页": "url",
    "notes": "notes",
    "note": "notes",
    "remark": "notes",
    "remarks": "notes",
    "comment": "notes",
    "description": "notes",
    "desc": "notes",
    "备注": "notes",
    "说明": "notes",
    "注释": "notes",
    "描述": "notes",
    "记录": "notes",
    "totp": "totp",
    "otp": "totp",
    "otp_secret": "totp",
    "totp_secret": "totp",
    "2fa": "totp",
    "mfa": "totp",
    "authenticator": "totp",
    "动态码": "totp",
    "验证器": "totp",
    "二步验证": "totp",
    "tags": "tags",
    "tag": "tags",
    "label": "tags",
    "labels": "tags",
    "category": "tags",
    "group": "tags",
    "分类": "tags",
    "标签": "tags",
    "分组": "tags",
    "类别": "tags",
}

# 这些键即使不叫 totp，也大概率是动态码种子
TOTP_HINTS = ("totp", "otp", "2fa", "mfa", "authenticator", "otpauth")
BASE32_RE = re.compile(r"^[A-Z2-7\s=]{16,}$")

STANDARD_FIELDS = ("id", "title", "username", "password", "url", "notes", "totp", "tags")

# 元数据键：必须单独识别，否则会被误收进自定义字段
META_KEYS = {
    "created",
    "updated",
    "pwchanged",
    "createdat",
    "updatedat",
    "创建时间",
    "更新时间",
    "修改时间",
}

TAG_KEYS = {
    "tags",
    "tag",
    "label",
    "labels",
    "category",
    "group",
    "分类",
    "标签",
    "分组",
    "类别",
}


def utc_now() -> datetime:
    """当前 UTC 时刻 —— 全模块**唯一**的取时点。

    单独拆出来只有一个目的：把「时间从哪来」和「时间怎么格式化」分开，测试才能
    注入时间而不篡改格式。`tests/test_timestamp_precision.py` 用
    `mock.patch("pwdvault.models.utc_now", …)` 把两次写入钉进同一秒，**格式化仍走
    `now_iso()` 的生产实现** —— 否则用例会绕过被测精度，把缺陷「测成通过」。
    """
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """当前 UTC 时间的 ISO-8601 字符串，**微秒精度 + 显式时区**。

    精度是乐观锁的一部分，不是「顺手多写几位数字」：`locks.VaultStore.commit`
    用 `target.updated != expected_updated` 判定 stale，秒级截断会让「同一秒内的
    读 → 他人写 → 提交」被误判成无冲突，把别人的改动静默覆盖掉（lost update）。
    微秒精度把碰撞窗口从 1 秒压到 1 微秒。

    格式：`2026-10-23T09:00:39.123456+00:00`。

    **不要和 `staging._iso()` 合并。** 那两个时间戳用途不同、精度要求也不同：
    这个值参与乐观锁的**等值比较**（`expected_updated`），秒级截断会让「同一秒内的
    读→他人写→提交」被误判成无冲突（Q-04），所以必须微秒；
    `staging._iso()` 参与的是租约/编辑锁的**剩余时长减法**，毫秒够用且更省字节。
    「看着不整齐」不是合并的理由 —— 合并会动到已落盘的 `Record.updated` 格式。

    与旧数据（秒级 `2026-10-23T09:00:39+00:00`）混用时，**字典序比较依然单调**：
    `+` 是 0x2B、`.` 是 0x2E，所以「秒级写法」恰好排在「同一秒的微秒写法」之前，
    这正是「秒级 = 该秒的起点」应有的顺序。`tests/test_timestamp_precision.py`
    用测试钉死了这个字节序事实。
    """
    return utc_now().isoformat(timespec="microseconds")


def new_id() -> str:
    return secrets.token_hex(5)


def normalize_key(key: str) -> str:
    return re.sub(r"[\s_\-]+", "", str(key)).strip().lower()


def split_tags(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(split_tags(item))
        return out
    text = str(value)
    parts = re.split(r"[,，;；|/\t]+", text)
    seen: list[str] = []
    for part in parts:
        tag = part.strip().lstrip("#").strip()
        if tag and tag not in seen:
            seen.append(tag)
    return seen


def looks_like_totp(value: str) -> bool:
    cleaned = re.sub(r"\s+", "", value)
    if not BASE32_RE.match(cleaned.upper()):
        return False
    return len(cleaned.rstrip("=")) >= 16


# ------------------------------------------------------------ 敏感字段与掩码
# 判定规则见 PRD §7.1。宁枉勿纵：shipping / keyboard / monkey 会误报，可接受。
SENSITIVE_TOKENS: tuple[str, ...] = (
    "secret",
    "key",
    "token",
    "pass",
    "pwd",
    "pin",
    "seed",
    "私钥",
    "密钥",
    "令牌",
    "口令",
    "种子",
)

# 标准非敏感键：必须先判，否则 pw_changed 会被 "pw" 误伤
NON_SENSITIVE_KEYS = frozenset(
    {
        "id",
        "title",
        "username",
        "url",
        "notes",
        "tags",
        "created",
        "updated",
        "pw_changed",
    }
)

MASK = "\u2022\u2022\u2022\u2022"  # 恒为四个字符，长度零泄露
EMPTY_MASK = "（空）"


def is_sensitive_key(name: str) -> bool:
    """字段名是否敏感（PRD §7.1）。

    1. 标准非敏感字段 → False（先判，避免 notes 里的 key 被误伤）
    2. 以 "*" 开头 → True（人工强制标记，v1.0 打开只多显示一个星号）
    3. 小写且去掉全部空白后含任一 SENSITIVE_TOKENS → True
    """
    key = str(name or "").strip()
    if not key:
        return False
    norm = re.sub(r"\s+", "", key).casefold()
    if norm in NON_SENSITIVE_KEYS:
        return False
    if key.startswith("*"):
        return True
    return any(token in norm for token in SENSITIVE_TOKENS)


def mask_value(value) -> str:
    """非空 → MASK；空 → EMPTY_MASK。绝不泄露原值长度。"""
    text = "" if value is None else str(value)
    return EMPTY_MASK if text == "" else MASK


Level = Literal["error", "warn", "info", "conflict"]


@dataclass(frozen=True)
class Warning:
    """条目级确定性警告（PRD §6.3）。

    `message` 是中文人读文案，**只允许出现字段名与规则描述，绝不出现字段值**。
    """

    code: str
    level: Level = "warn"
    message: str = ""
    field: str | None = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "level": self.level,
            "message": self.message,
            "field": self.field,
        }


@dataclass
class Record:
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp: str = ""
    tags: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    id: str = ""
    created: str = ""
    updated: str = ""
    pw_changed: str = ""
    # 系统级标记（来源、写入者……）。**故意与 `fields` 分开**：`fields` 是用户/导入
    # 自由填写的业务字段（会进搜索、会展示），meta 只放「这条记录怎么来的」这类
    # 内部标记，永不参与搜索，也不允许被 import 到的数据覆盖。
    # 空 dict 时 `to_dict()` 不输出该键 —— v1.0 的落盘格式一个字节都没变。
    meta: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = new_id()
        stamp = now_iso()
        if not self.created:
            self.created = stamp
        if not self.updated:
            self.updated = stamp
        if not self.pw_changed and self.password:
            self.pw_changed = self.created
        self.tags = split_tags(self.tags)
        self.fields = {str(k): str(v) for k, v in self.fields.items() if str(v).strip()}
        self.meta = {str(k): str(v) for k, v in (self.meta or {}).items() if str(v).strip()}

    # ---------- 序列化 ----------
    def to_dict(self, *, mask_secrets: bool = False) -> dict:
        """序列化成落盘/传输形态。

        `mask_secrets=True` 时 password / totp / 敏感自定义字段的值换成 MASK，
        其余（含空值省略规则）与默认形态完全一致。默认 False：
        `Vault._serialize_payload` 用的就是默认值，落盘格式一个字节都没变。
        """
        out: dict = {"id": self.id, "title": self.title}
        for key in ("username", "password", "url", "notes", "totp"):
            value = getattr(self, key)
            if value:
                out[key] = mask_value(value) if (mask_secrets and key in ("password", "totp")) else value
        if self.tags:
            out["tags"] = list(self.tags)
        if self.fields:
            if mask_secrets:
                out["fields"] = {
                    name: (mask_value(value) if is_sensitive_key(name) else value)
                    for name, value in self.fields.items()
                }
            else:
                out["fields"] = dict(self.fields)
        if self.meta:
            out["meta"] = dict(self.meta)
        out["created"] = self.created
        out["updated"] = self.updated
        if self.pw_changed:
            out["pw_changed"] = self.pw_changed
        return out

    # ---------- 字段变更 ----------
    def apply_changes(self, changes: dict[str, Any]) -> bool:
        """就地应用字段变更，返回是否改了 password。

        语义 = v1.0 `service.update` 的逐字平移（唯一一份实现，`locks.py` 的
        rebase 与 `service.update` 都走这里，避免两份逻辑漂移）：
          - value is None → 跳过
          - key == "tags" → 逗号切分
          - key == "fields" → dict 时整表替换，其余一律跳过（v1.0 是纯跳过；
            dict 分支是 v1.1 追加的，供暂存区「覆盖提交」与「撤销」还原全量字段）
          - hasattr(self, key) → setattr（password 真变了就刷 pw_changed）
          - 否则 → self.fields[key] = value
        无论是否真的改了值，`updated` 都会刷新（与 v1.0 行为一致）。
        """
        touched_password = False
        for key, value in changes.items():
            if value is None:
                continue
            if key == "tags":
                self.tags = [t.strip() for t in str(value).split(",") if t.strip()]
            elif key == "fields":
                if isinstance(value, dict):
                    self.fields = {str(k): str(v) for k, v in value.items() if str(v).strip()}
                continue
            elif key == "meta":
                # 系统标记只能合并，不能被 payload 整表替换（否则可伪造「web 写的」）
                if isinstance(value, dict):
                    merged = dict(self.meta)
                    merged.update({str(k): str(v) for k, v in value.items() if str(v).strip()})
                    self.meta = merged
                continue
            elif hasattr(self, key):
                if key == "password" and value != self.password:
                    touched_password = True
                setattr(self, key, value)
            else:
                self.fields[key] = value
        self.updated = now_iso()
        if touched_password:
            self.pw_changed = self.updated
        return touched_password

    @classmethod
    def from_dict(cls, raw: dict, *, record_id: str | None = None, keep_id: bool = False) -> "Record":
        if not isinstance(raw, dict):
            raise InvalidRecord("单条记录必须是键值对象")

        data: dict = {}
        extras: dict[str, str] = {}
        meta: dict[str, str] = {}
        record_meta: dict[str, str] = {}

        # fields 子对象要原样摊平回自定义字段，而不是变成 fields.xxx
        nested_fields = raw.get("fields")
        if isinstance(nested_fields, dict):
            for sub_key, sub_value in nested_fields.items():
                if sub_value is not None and not isinstance(sub_value, (dict, list)):
                    extras[str(sub_key)] = str(sub_value)

        for key, value in raw.items():
            if value is None:
                continue
            norm = normalize_key(key)

            if norm == "fields":
                continue
            if norm == "meta":
                # 系统标记：只认标量值，且绝不落进 fields（否则会污染业务字段并进搜索）
                if isinstance(value, dict):
                    record_meta = {
                        str(k): str(v)
                        for k, v in value.items()
                        if v is not None and not isinstance(v, (dict, list))
                    }
                continue
            if norm in META_KEYS:
                meta[norm] = str(value)
                continue
            if norm == "id":
                continue  # 只有 keep_id 才认外部 id
            if norm in TAG_KEYS:
                data["tags"] = split_tags(value)
                continue

            target = ALIASES.get(norm)
            if target in ("title", "username", "password", "url", "notes", "totp"):
                text = str(value).strip()
                if target == "totp" and text and not looks_like_totp(text):
                    extras[str(key)] = text
                    continue
                data[target] = text
                continue

            if isinstance(value, (dict, list)):
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if sub_value is not None and not isinstance(sub_value, (dict, list)):
                            extras[f"{key}.{sub_key}"] = str(sub_value)
                continue

            # 未识别的键：长得像 TOTP 种子就收进 totp，否则原样保留
            text = str(value).strip()
            if not text:
                continue
            if any(hint in norm for hint in TOTP_HINTS) and looks_like_totp(text) and "totp" not in data:
                data["totp"] = text
            else:
                extras[str(key)] = text

        record = cls(**data, fields=extras, meta=record_meta)
        if record_id:
            record.id = record_id
        elif keep_id and isinstance(raw.get("id"), str) and raw["id"].strip():
            record.id = raw["id"].strip()

        for field_name in ("created", "updated", "pw_changed"):
            # 注意：meta 的键是 normalize_key 之后的（"pw_changed" → "pwchanged"），
            # v1.0 这里直接用 field_name 取，导致 pw_changed 永远无法从盘上回读。
            stored = meta.get(normalize_key(field_name))
            if stored:
                setattr(record, field_name, stored)

        if not record.title:
            record.title = record.username or record.url or (record.notes[:24] if record.notes else "")
        if not record.title:
            raise InvalidRecord("缺少标题，且无法从其他字段推断")

        return record

    # ---------- 查询 ----------
    def haystack(self) -> str:
        parts = [
            self.title,
            self.username,
            self.url,
            self.notes,
            " ".join(self.tags),
            " ".join(f"{k} {v}" for k, v in self.fields.items()),
        ]
        return " ".join(parts).casefold()

    def searchable_pairs(self) -> list[tuple[str, str]]:
        pairs = [
            ("title", self.title),
            ("user", self.username),
            ("url", self.url),
            ("notes", self.notes),
            ("tag", " ".join(self.tags)),
        ]
        pairs.extend((f"field:{k}", v) for k, v in self.fields.items())
        return [(name, value.casefold()) for name, value in pairs if value]

    def masked_password(self) -> str:
        if not self.password:
            return "（空）"
        return "•" * min(12, max(6, len(self.password)))

    def __repr__(self) -> str:
        """**永不输出任何敏感值**（O-3）。

        dataclass 生成的默认 `__repr__` 会把 `password` / `totp` / 敏感自定义字段的
        明文全部打出来。当前所有日志路径都没有这么写过（QA 已 grep 验证），但这属于
        「谁写一句 `f"{record}"` 就泄密」的地雷：调试打印、异常 message、
        `logging.info("%s", record)`、pytest 断言失败信息，全都会走到这里。

        所以这里只报「有没有」和「有几个」，不报值：
            Record(id='a1b2c3d4e5', title='淘宝', username='zhangsan',
                   has_password=True, has_totp=False, fields=2)

        `title` / `username` 属于 `NON_SENSITIVE_KEYS`，可以出现（排查问题时没有它们
        等于把日志变成噪音）。自定义字段**只给数量**，连键名都不给 —— 键名本身可能
        包含用户隐私（例如「小明的生日」）。
        """
        return (
            f"Record(id={self.id!r}, title={self.title!r}, username={self.username!r}, "
            f"has_password={bool(self.password)}, has_totp={bool(self.totp)}, "
            f"fields={len(self.fields)})"
        )


def score_secret(secret: str) -> tuple[float, str]:
    """估算口令熵（比特），用于给出可操作的强度提示。"""
    if not secret:
        return 0.0, "空密码"

    words = [w for w in re.split(r"[\s\-_.]+", secret) if w]
    word_entropy = 0.0
    if len(words) >= 3 and sum(len(w) >= 2 for w in words) >= 3:
        word_entropy = len(words) * math.log2(7776)

    charset = 0
    if re.search(r"[a-z]", secret):
        charset += 26
    if re.search(r"[A-Z]", secret):
        charset += 26
    if re.search(r"[0-9]", secret):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", secret):
        charset += 33
    char_entropy = len(secret) * math.log2(max(charset, 2))

    entropy = max(word_entropy, char_entropy)
    if entropy < 40:
        level = "弱"
    elif entropy < 55:
        level = "偏弱"
    elif entropy < 75:
        level = "够用"
    else:
        level = "强"
    return round(entropy, 1), level
