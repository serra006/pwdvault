"""多格式导入：JSON / CSV / 纯文本 TXT。

这个模块是为「把一堆明文资料交给 agent，归纳后直接入库」这条工作流准备的。
三种格式的可靠性依次下降：

  JSON  —— 结构化，零歧义，agent 归纳后的首选目标（强烈推荐）
  CSV   —— 表头即字段名，适合从 Excel 另存
  TXT   —— 启发式解析，永远要配 --dry-run 先看结果再落库

TXT 解析永远不可能 100% 准确，所以它只是兜底通道，而不是主路径。
"""

from __future__ import annotations

import csv
import io
import json
import re

from .errors import ImportError_
from .models import ALIASES, Record, new_id, normalize_key, split_tags

LABEL_RE = re.compile(r"([^\s:：=|\t]{1,12})\s*[:：=](?![\/]{1,2})\s*")
URL_TOKEN_RE = re.compile(r"(?:https?://|www\.)[^\s，。、；]+", re.I)
URL_PLACEHOLDER_RE = re.compile(r"\x00(\d+)\x00")
BULLET_RE = re.compile(r"^[\s\-*·•—]+")
SEPARATOR_LINE_RE = re.compile(r"^[\s\-=_*~·—]{3,}$")
URL_LIKE_RE = re.compile(r"^(https?://|www\.)", re.I)

TITLE_ALIASES = {
    k for k, v in ALIASES.items() if v == "title"
}
CORE_ORDER = ("title", "username", "password", "url", "notes", "totp")

# 单个值超过这个长度就当成「可能把整段文本当成了密码」（PRD §6.3 规则 6）
LONG_VALUE_LIMIT = 128


# ------------------------------------------------------------------- 旁路标记
def _is_password_key(key: str) -> bool:
    return ALIASES.get(normalize_key(key)) == "password"


def _collect_notes(item: dict, index: int, notes: list) -> None:
    """在**归一化之前**扫原始键值，把可疑点旁路记成 `(index, code)`。

    这件事必须发生在 `Record.from_dict` 之前：字段一旦被别名改写
    （站点→title、登录名→username），就再也对应不上原始键名了。

    标记绝不写进 `record.fields`：那会随记录一起落进 `data.enc`，
    用户导出时看到一堆脏字段，直接违背「记录结构完全不变」的承诺。
    """
    if not isinstance(item, dict):
        return

    normalized = {normalize_key(key) for key in item}
    if not normalized & TITLE_ALIASES:
        # 没有标题键：这条记录的标题只能靠 username/url/notes 推断出来
        notes.append((index, "title_inferred"))

    for key, value in item.items():
        if value is None or isinstance(value, (dict, list)):
            continue
        text = str(value)
        if text != text.strip() and _is_password_key(key):
            notes.append((index, "password_trimmed"))
        if len(text.strip()) > LONG_VALUE_LIMIT:
            notes.append((index, "long_value"))
            break


# --------------------------------------------------------------------- JSON
def parse_json(text: str, notes: list | None = None) -> list[Record]:
    """JSON 是我们自己的导出格式，保留 id 以便「导出 → 恢复」后引用不变。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportError_(f"JSON 语法错误（第 {exc.lineno} 行）：{exc.msg}") from exc
    return records_from_obj(data, keep_id=True, notes=notes)


def records_from_obj(data, *, keep_id: bool = True, notes: list | None = None) -> list[Record]:
    if isinstance(data, list):
        return _build(data, keep_id=keep_id, notes=notes)

    if isinstance(data, dict):
        for key in ("records", "items", "data", "entries", "list"):
            value = data.get(key)
            if isinstance(value, list):
                return _build(value, keep_id=keep_id, notes=notes)

        # {网站名: {账号: ..., 密码: ...}} 形式 —— 很常见，必须支持
        if data and all(isinstance(v, dict) for v in data.values()):
            norm_keys = {normalize_key(k) for k in data}
            if not norm_keys & set(ALIASES):
                merged = []
                for title, body in data.items():
                    item = dict(body)
                    item.setdefault("title", title)
                    merged.append(item)
                return _build(merged, keep_id=False, notes=notes)

        if normalize_key(next(iter(data))) in ALIASES:
            return _build([data], keep_id=keep_id, notes=notes)

    raise ImportError_("JSON 顶层既不是记录数组，也不是可识别的单条记录")


def _build(items: list, *, keep_id: bool = False, notes: list | None = None) -> list[Record]:
    records: list[Record] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ImportError_(f"第 {index} 条不是键值对象")
        if notes is not None:
            _collect_notes(item, index, notes)
        try:
            records.append(Record.from_dict(item, keep_id=keep_id))
        except Exception as exc:  # noqa: BLE001
            raise ImportError_(f"第 {index} 条无法解析：{exc}") from exc
    if not records:
        raise ImportError_("没有解析出任何记录")

    if keep_id:
        # 外部 JSON 可能带重复 id，出现冲突就整组重新分配，避免后续引用错乱
        seen: set[str] = set()
        for record in records:
            if record.id in seen:
                record.id = new_id()
            seen.add(record.id)
    return records


# ---------------------------------------------------------------------- CSV
def parse_csv(text: str, notes: list | None = None) -> list[Record]:
    text = text.lstrip("\ufeff")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel

    rows = list(csv.reader(io.StringIO(text), dialect))
    rows = [r for r in rows if any(cell.strip() for cell in r)]
    if not rows:
        raise ImportError_("CSV 内容为空")

    header = [cell.strip() for cell in rows[0]]
    known = {normalize_key(h) for h in header} & set(ALIASES)
    if len(known) >= 2:
        items = []
        for row in rows[1:]:
            items.append({h: row[i] if i < len(row) else "" for i, h in enumerate(header) if h})
        return _build(items, notes=notes)

    return _positional(rows, note="CSV 未识别到表头，按列顺序推断", notes=notes)


# ---------------------------------------------------------------------- TXT
COLUMN_SPLIT_RE = re.compile(r"[\t|,，;；]+|\s{2,}")
HEADER_WORDS = {"站点", "网站", "名称", "标题", "title", "site", "name", "服务", "平台"}


def _labels_in(line: str) -> list[tuple[int, int, str, str]]:
    """从一行里抽出所有「键: 值」对，返回 [(start, end, key, value)]。

    用位置切片而不是简单 split，才能正确处理「账号:xxx 密码:yyy」这种一行多条。
    行内 URL 先替换成占位符，否则 https://a.com/x?y=1 里的 ?y=1 会被误判成键值对。
    """
    urls: list[str] = []

    def stash(match: re.Match) -> str:
        urls.append(match.group(0))
        return f"\x00{len(urls) - 1}\x00"

    masked = URL_TOKEN_RE.sub(stash, line)
    matches = list(LABEL_RE.finditer(masked))
    out: list[tuple[int, int, str, str]] = []
    for index, match in enumerate(matches):
        key = match.group(1).strip()
        if not key or key.isdigit():
            continue
        if any(ch in key for ch in "/?&"):
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(masked)
        value = masked[match.end() : end].strip().strip("|,，;；")
        value = URL_PLACEHOLDER_RE.sub(lambda m: urls[int(m.group(1))], value)
        if not value or URL_LIKE_RE.match(key):
            continue
        out.append((match.start(), match.end(), key, value))
    return out


def _split_blocks(lines: list[str]) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if not line or SEPARATOR_LINE_RE.match(line):
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        blocks.append(current)
    return blocks


def _split_columns(line: str) -> list[str]:
    if line.strip().lower() in HEADER_WORDS:
        return []
    return [part.strip() for part in COLUMN_SPLIT_RE.split(line) if part.strip()]


def _cols_to_item(cols: list[str], *, note: str | None = None) -> dict:
    item: dict = {}
    if not cols:
        return item
    if len(cols) == 1:
        item["title"] = cols[0]
    elif len(cols) == 2:
        item["title"] = cols[0]
        item["username"] = cols[1]
    else:
        if URL_LIKE_RE.match(cols[0]):
            item["url"] = cols[0]
            item["title"] = cols[1]
            item["username"] = cols[2]
            rest = cols[3:]
        else:
            item["title"] = cols[0]
            item["username"] = cols[1]
            item["password"] = cols[2]
            rest = cols[3:]
        if rest:
            item["notes"] = " ".join(rest)
    if note:
        item["导入备注"] = note
    return item


def parse_txt(text: str, notes: list | None = None) -> list[Record]:
    raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # 空行必须保留：它是块的分隔符，丢掉就整篇粘成一条了
    lines = [BULLET_RE.sub("", line).strip() for line in raw_lines]

    if not any(lines):
        raise ImportError_("文本内容为空")

    items: list[dict] = []
    for block in _split_blocks(lines):
        items.extend(_parse_block(block))

    if not items:
        raise ImportError_("没有在文本中识别出任何可用记录")
    return _build(items, notes=notes)


def _parse_block(block: list[str]) -> list[dict]:
    labelled: list[tuple[str, str]] = []
    plain: list[str] = []

    for line in block:
        labels = _labels_in(line)
        if labels:
            labelled.extend((key, value) for _, _, key, value in labels)
        else:
            plain.append(line)

    if labelled:
        item: dict = {}
        for key, value in labelled:
            if key in item:
                item[key] = f"{item[key]} {value}".strip()
            else:
                item[key] = value

        has_title = any(normalize_key(k) in TITLE_ALIASES for k in item)
        if plain:
            if not has_title:
                item["title"] = plain[0]
                plain = plain[1:]
            if plain:
                merged = " ".join(plain)
                item["备注"] = f"{item.get('备注', '')} {merged}".strip()
        return [item]

    # 整块没有标签：按列位置推断
    rows = [cols for cols in (_split_columns(line) for line in plain) if cols]
    if not rows:
        return []

    if len(rows) == 1:
        return [_cols_to_item(rows[0])]

    single_column = all(len(row) == 1 for row in rows)
    if single_column and len(rows) <= 3:
        # 例如「淘宝 / zhangsan / abc123」三行，视为一条记录的三段
        return [_cols_to_item([row[0] for row in rows])]

    if single_column:
        return [_cols_to_item(row, note="未检测到标签，按行推断") for row in rows]

    return [_cols_to_item(row) for row in rows]


def _parse_positional_lines(lines: list[str]) -> list[Record]:
    rows = [cols for cols in (_split_columns(line) for line in lines) if cols]
    if not rows:
        raise ImportError_("没有在文本中识别出任何可用记录")
    return _positional(rows, note="未检测到标签，按列顺序推断")


def _positional(rows: list[list[str]], *, note: str, notes: list | None = None) -> list[Record]:
    items: list[dict] = []
    for parts in rows:
        width = len(parts)
        item: dict = {}
        if width == 1:
            item["title"] = parts[0]
        elif width == 2:
            item["title"] = parts[0]
            item["username"] = parts[1]
        else:
            item["title"] = parts[0]
            cursor = 1
            if URL_LIKE_RE.match(parts[0]):
                item["title"] = parts[1]
                item["url"] = parts[0]
                cursor = 2
            if cursor < width:
                item["username"] = parts[cursor]
                cursor += 1
            if cursor < width:
                item["password"] = parts[cursor]
                cursor += 1
            if cursor < width:
                item["notes"] = " ".join(parts[cursor:])
        items.append(item)
    records = _build(items, notes=notes)
    for record in records:
        record.fields.setdefault("导入备注", note)
    return records


# ---------------------------------------------------------------------- 入口
def detect_format(text: str, filename: str = "") -> str:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if suffix in ("json",):
        return "json"
    if suffix in ("csv", "tsv"):
        return "csv"
    if suffix in ("txt", "md", "log", "dat", "ini"):
        return "txt"
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    return "csv" if ("," in text.split("\n")[0] and text.count(",") >= 2) else "txt"


def parse_any(
    text: str,
    *,
    filename: str = "",
    fmt: str | None = None,
    source_name: str | None = None,
    notes: list | None = None,
) -> list[Record]:
    """统一入口。

    `notes` 是**旁路**参数：传一个空列表进来，解析过程中会把
    `(item_index, code)` 追加进去（code ∈ password_trimmed / title_inferred / long_value），
    最终只进 `StagingItem.warnings`，**绝不进 record.fields**。
    `notes=None` 且 `source_name=None` 时行为与 v1.0 完全一致。
    """
    chosen = fmt or detect_format(text, filename)
    if chosen == "json":
        records = parse_json(text, notes=notes)
    elif chosen == "csv":
        records = parse_csv(text, notes=notes)
    else:
        records = parse_txt(text, notes=notes)

    if source_name:
        # PRD §11：复用既有的「导入备注」字段记来源文件名（不加新字段）
        for record in records:
            record.fields.setdefault("导入备注", str(source_name))
    return records


def records_to_json(records: list[Record]) -> str:
    return json.dumps(
        {"schema": 1, "records": [r.to_dict() for r in records]},
        ensure_ascii=False,
        indent=2,
    )


def records_to_csv(records: list[Record]) -> str:
    extra_keys: list[str] = []
    for record in records:
        for key in record.fields:
            if key not in extra_keys:
                extra_keys.append(key)

    columns = list(CORE_ORDER) + ["tags"] + extra_keys
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for record in records:
        row = []
        for column in columns:
            if column in CORE_ORDER:
                row.append(getattr(record, column))
            elif column == "tags":
                row.append(",".join(record.tags))
            else:
                row.append(record.fields.get(column, ""))
        writer.writerow(row)
    return buffer.getvalue()
