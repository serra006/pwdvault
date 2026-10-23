"""导入解析测试：JSON / CSV / TXT 三条通道，重点是自由字段不丢失。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault import importers

# 模拟「agent 整理后的标准产物」
JSON_ARRAY = """
[
  {"站点": "淘宝", "账号": "zhangsan", "密码": "Tb#2024", "标签": "购物,常用",
   "密保问题": "母亲的名字", "绑定手机": "13800138000"},
  {"title": "GitHub", "username": "gh", "password": "Gh@1",
   "totp": "JBSWY3DPEHPK3PXP"}
]
"""

JSON_WRAPPED = '{"records": [{"title": "知乎", "username": "z", "password": "p"}]}'

JSON_TITLE_MAP = """
{
  "淘宝": {"账号": "u1", "密码": "p1"},
  "京东": {"账号": "u2", "密码": "p2", "备注": "备用"}
}
"""

CSV_DATA = """站点,账号,密码,标签,密保问题
淘宝,u1,p1,购物,故乡
京东,u2,p2,购物,出生地
"""

TXT_LABELLED = """淘宝
账号: zhangsan@example.com
密码: Tb#2024xy
网址: https://taobao.com
备注: 主要购物号

京东
账号: lisi
密码: Jd@9988
密保问题: 出生城市
"""

TXT_COLUMNS = """知乎 | zhihu_user | Zh#2021
GitHub	gh_user	Gh@pass123
"""

TXT_THREE_LINES = """淘宝
zhangsan
abc123
"""


class JsonTests(unittest.TestCase):
    def test_array(self):
        records = importers.parse_json(JSON_ARRAY)
        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first.title, "淘宝")
        self.assertEqual(first.username, "zhangsan")
        self.assertEqual(first.tags, ["购物", "常用"])
        self.assertEqual(first.fields["密保问题"], "母亲的名字")

    def test_totp_routed_to_field(self):
        records = importers.parse_json(JSON_ARRAY)
        self.assertEqual(records[1].totp, "JBSWY3DPEHPK3PXP")
        self.assertNotIn("totp", records[1].fields)

    def test_wrapped_in_records_key(self):
        records = importers.parse_json(JSON_WRAPPED)
        self.assertEqual(records[0].title, "知乎")

    def test_title_keyed_map(self):
        records = importers.parse_json(JSON_TITLE_MAP)
        self.assertEqual([r.title for r in records], ["淘宝", "京东"])
        # 「备注」是标准字段别名，会进 notes 而不是自由字段
        self.assertEqual(records[1].notes, "备用")
        self.assertEqual(records[0].password, "p1")

    def test_meta_fields_not_leaked_into_custom_fields(self):
        records = importers.parse_json(
            '[{"title": "A", "created": "2026-01-01T00:00:00+00:00", '
            '"updated": "2026-01-02T00:00:00+00:00", "pw_changed": "2026-01-03T00:00:00+00:00"}]'
        )
        self.assertEqual(records[0].fields, {})
        self.assertEqual(records[0].created, "2026-01-01T00:00:00+00:00")

    def test_bad_json_raises(self):
        with self.assertRaises(Exception):
            importers.parse_json("[{oops")


class CsvTests(unittest.TestCase):
    def test_header_mapping(self):
        records = importers.parse_csv(CSV_DATA)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].title, "淘宝")
        self.assertEqual(records[0].tags, ["购物"])
        self.assertEqual(records[0].fields["密保问题"], "故乡")

    def test_without_header_falls_back_to_position(self):
        text = "淘宝,u1,p1\n京东,u2,p2\n"
        records = importers.parse_csv(text)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].title, "淘宝")


class TxtTests(unittest.TestCase):
    def test_labelled_blocks(self):
        records = importers.parse_txt(TXT_LABELLED)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].title, "淘宝")
        self.assertEqual(records[0].username, "zhangsan@example.com")
        self.assertEqual(records[0].password, "Tb#2024xy")
        self.assertEqual(records[0].url, "https://taobao.com")
        self.assertEqual(records[1].fields["密保问题"], "出生城市")

    def test_column_separated(self):
        records = importers.parse_txt(TXT_COLUMNS)
        self.assertEqual([r.title for r in records], ["知乎", "GitHub"])
        self.assertEqual(records[0].username, "zhihu_user")
        self.assertEqual(records[0].password, "Zh#2021")
        self.assertEqual(records[1].password, "Gh@pass123")

    def test_three_plain_lines_make_one_record(self):
        records = importers.parse_txt(TXT_THREE_LINES)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, "淘宝")
        self.assertEqual(records[0].username, "zhangsan")
        self.assertEqual(records[0].password, "abc123")

    def test_url_not_split_as_label(self):
        records = importers.parse_txt("淘宝\n网址: https://a.com/x?y=1\n")
        self.assertEqual(records[0].url, "https://a.com/x?y=1")

    def test_inline_multiple_labels(self):
        records = importers.parse_txt("淘宝 账号:solo 密码:pw123\n")
        self.assertEqual(records[0].username, "solo")
        self.assertEqual(records[0].password, "pw123")


class DetectTests(unittest.TestCase):
    def test_by_suffix(self):
        self.assertEqual(importers.detect_format("{}", "a.json"), "json")
        self.assertEqual(importers.detect_format("a,b", "a.csv"), "csv")
        self.assertEqual(importers.detect_format("x", "a.txt"), "txt")

    def test_by_content(self):
        self.assertEqual(importers.detect_format('{"a":1}'), "json")
        self.assertEqual(importers.detect_format("[1]"), "json")

    def test_export_json_roundtrip(self):
        records = importers.parse_json(JSON_ARRAY)
        text = importers.records_to_json(records)
        again = importers.parse_json(text)
        self.assertEqual([r.title for r in again], ["淘宝", "GitHub"])
        self.assertEqual([r.id for r in again], [r.id for r in records])

    def test_export_csv_contains_custom_columns(self):
        records = importers.parse_json(JSON_ARRAY)
        text = importers.records_to_csv(records)
        self.assertIn("密保问题", text.splitlines()[0])


if __name__ == "__main__":
    unittest.main()
