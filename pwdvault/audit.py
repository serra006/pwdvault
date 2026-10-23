"""审计流水（L3）：只记「谁对哪条记录的哪个字段做了什么」，绝不记值。

为什么单独一层
--------------
审计最容易变成第二个泄露面：一句「顺手把改动记下来」就会把密码、TOTP 种子、
备注正文、搜索关键词原文写进一个**不加密**的 JSONL 文件，而这个文件通常还会被
人拷来拷去。所以这里的规矩是硬编码的：

  1. 每行只允许出现 7 个键：`ts` / `actor` / `action` / `record_id` /
     `field_name` / `count` / `ok`。`build_entry()` 是唯一构造入口，
     **没有任何参数可以塞进字段值**。
     注：`export` 事件没有「字段」可言，此时 `field_name` 承载的是**导出格式**
     （`json` / `csv`）。这确实是个语义借用，但**故意不为它加第 8 个键** ——
     白名单每多一个槽位，就多一处可能被误塞明文的地方。
  2. `action` 与 `actor` 是白名单枚举，写错直接 `ValueError`（编程错误要当场炸）。
     经由 `append()` 时默认也当场炸（`RuntimeError`，见下），只有显式设
     `PV_AUDIT_STRICT=0` 才降级成 stderr —— 理由：**未知动作意味着有调用点漏配白名单，
     也就是「某个高危行为根本没进审计」**（`export` 导出明文就曾因此完全无记录）。
     这种缺陷如果只留一行 WARNING，就会被日志噪音淹没；而 WARNING 又恰好总是在
     测试里刷屏，让人以为「无关紧要」。
  3. `record_id` / `field_name` 会在落盘前被清洗成「短标识符」：去掉换行、
     引号、控制字符并截断 —— 即使调用方误把一段正文当字段名传进来，也写不成一行
     恶意 JSON，更不会把整段值写进去。
  4. 写入失败（磁盘满 / 只读 / 权限）**绝不影响主流程**：吞掉异常，只在 stderr
     留一行日志。审计是「有了更好」的东西，不能因为它让用户复制不了密码。
     注意这条**只覆盖 I/O 失败**；枚举写错是编程错误，按第 2 条处理。

分层：本模块属 L3，只依赖标准库 + `config.Settings`，**不得** import
`mcp_tools` / `mcp_server` / `web`（否则 L4/L5 与 L7 会被它拖进 import 环）。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

AUDIT_FILE_NAME = "audit.jsonl"

# 允许的枚举（写错就是编程错误，不是用户错误）
#   copy   —— 把某个字段的值送进剪贴板
#   reveal —— 把某个字段的值明文展示出来
#   add / update / commit —— 写库的三种动作
#   export —— 把**整库明文**导出成文件/标准输出（最高危的一个，必须有记录）
# 只列真实在用的动作；不要为了「将来可能用到」提前加。
ACTIONS: frozenset[str] = frozenset({"copy", "add", "update", "reveal", "commit", "export"})
ACTORS: frozenset[str] = frozenset({"agent", "web", "cli"})

# `append()` 遇到「未知动作/未知主体」时的行为开关：
#   未设置或 "1" → 抛 RuntimeError（开发期/CI 必红，缺陷无处躲）
#   "0"          → 降级成 stderr 一行（仅在明确知道自己不该被审计打断的场景用）
AUDIT_STRICT_ENV = "PV_AUDIT_STRICT"

# 一行 JSON 的长度上限：正常一条不到 200 字符，超过就说明有东西混进来了
MAX_TOKEN_CHARS = 64
MAX_LINE_CHARS = 512
DEFAULT_RECENT = 50
MAX_RECENT = 500

# 唯一允许出现在审计行里的键（顺序即落盘顺序，便于人读）
ENTRY_KEYS: tuple[str, ...] = ("ts", "actor", "action", "record_id", "field_name", "count", "ok")


def audit_path(settings: Any) -> Path:
    """审计文件路径：`<home>/logs/audit.jsonl`。"""
    return Path(settings.logs_dir) / AUDIT_FILE_NAME


def _clean_token(value: Any, *, limit: int = MAX_TOKEN_CHARS) -> str:
    """把任意输入压成「短标识符」：只留可打印字符，去掉引号与反斜杠。

    id 是 10 位十六进制，字段名最多几十个字符；正常输入一个字符都不会被改动。
    """
    text = "" if value is None else str(value)
    kept = [ch for ch in text if ch.isprintable() and ch not in '"\\']
    return "".join(kept)[:limit]


def _stamp(now: datetime | None = None) -> str:
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def build_entry(
    *,
    action: str,
    actor: str = "agent",
    record_id: Any = "",
    field_name: Any = "",
    count: Any = None,
    ok: bool = True,
    now: datetime | None = None,
) -> dict:
    """构造一条审计记录（纯函数，可单测）。

    Raises:
        ValueError: `action` / `actor` 不在白名单里（编程错误，必须当场暴露）。
    """
    if action not in ACTIONS:
        raise ValueError(f"未知的审计动作：{action!r}（只允许 {sorted(ACTIONS)}）")
    if actor not in ACTORS:
        raise ValueError(f"未知的审计主体：{actor!r}（只允许 {sorted(ACTORS)}）")

    entry: dict = {
        "ts": _stamp(now),
        "actor": actor,
        "action": action,
        "record_id": _clean_token(record_id),
        "field_name": _clean_token(field_name),
        "ok": bool(ok),
    }
    if count is not None:
        try:
            entry["count"] = int(count)
        except (TypeError, ValueError):
            entry["count"] = 0
    return entry


def _warn(detail: str) -> None:
    """审计降级日志：只报异常类型/原因，不含任何业务数据。"""
    try:
        print(f"[pv] WARNING 审计写入失败（不影响主流程）：{detail}", file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 - 连 stderr 都写不了就只能放弃
        pass


def is_strict() -> bool:
    """`PV_AUDIT_STRICT=0` → 审计枚举错误降级为 stderr；其余（含未设置）→ 抛异常。"""
    return os.environ.get(AUDIT_STRICT_ENV, "1").strip() != "0"


def append(
    settings: Any,
    *,
    action: str,
    actor: str = "agent",
    record_id: Any = "",
    field_name: Any = "",
    count: Any = None,
    ok: bool = True,
    now: datetime | None = None,
) -> bool:
    """追加一条审计。返回是否**真的写进了文件**。

    两种失败要分开看（这是本函数的全部要点）：
      - **枚举写错**（未知 `action` / `actor`）→ 编程错误。默认抛 `RuntimeError`，
        因为它的真实含义是「某条高危路径漏配了白名单，这个行为根本没被审计」；
        只有 `PV_AUDIT_STRICT=0` 才降级成 stderr。
      - **I/O 失败**（磁盘满 / 只读 / 权限 / 意外异常）→ 只降级到 stderr，
        绝不打断用户操作。审计是「有了更好」的东西。
    """
    try:
        entry = build_entry(
            action=action,
            actor=actor,
            record_id=record_id,
            field_name=field_name,
            count=count,
            ok=ok,
            now=now,
        )
    except ValueError as exc:
        if is_strict():
            raise RuntimeError(f"审计枚举配置错误（这是编程错误，不是用户错误）：{exc}") from exc
        _warn(str(exc))
        return False

    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    if len(line) > MAX_LINE_CHARS:  # pragma: no cover - 白名单键 + 截断后不可能触发
        _warn("单行过长，已丢弃")
        return False

    try:
        path = audit_path(settings)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        _warn(type(exc).__name__)
        return False
    except Exception as exc:  # noqa: BLE001 - 任何意外都不影响主流程
        _warn(type(exc).__name__)
        return False
    return True


def read_recent(settings: Any, limit: int = DEFAULT_RECENT) -> list[dict]:
    """读取最近 `limit` 条审计（供将来的审计页面用）。

    坏行（被截断 / 手工编辑）直接跳过，不抛异常 —— 一个坏行不该让整页打不开。
    返回顺序为「旧 → 新」。
    """
    try:
        count = int(limit)
    except (TypeError, ValueError):
        count = DEFAULT_RECENT
    count = max(0, min(count, MAX_RECENT))
    if count == 0:
        return []

    path = audit_path(settings)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    out: list[dict] = []
    for raw in lines[-count:]:
        text = raw.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        # 出口也过一遍白名单：即使文件被人手工塞了 `password` 字段，也不会流出去
        out.append({key: item[key] for key in ENTRY_KEYS if key in item})
    return out


def iter_entries(settings: Any) -> Iterable[dict]:
    """逐条遍历全部审计（只读工具/测试用）。坏行跳过。"""
    path = audit_path(settings)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                text = raw.strip()
                if not text:
                    continue
                try:
                    item = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    yield {key: item[key] for key in ENTRY_KEYS if key in item}
    except OSError:
        return


__all__ = [
    "ACTIONS",
    "ACTORS",
    "AUDIT_FILE_NAME",
    "DEFAULT_RECENT",
    "ENTRY_KEYS",
    "MAX_LINE_CHARS",
    "MAX_RECENT",
    "MAX_TOKEN_CHARS",
    "append",
    "audit_path",
    "build_entry",
    "iter_entries",
    "read_recent",
]
