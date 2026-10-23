"""模型层测试：`apply_changes` 与 v1.0 `service.update` 的等价性、掩码序列化。

等价性是硬要求：`service.update` 已经改为委托 `Record.apply_changes`，而
`locks.py` 的 rebase 也直接用同一个方法。所以这里把 v1.0 的原实现逐字抄一份
作为基准，逐字段比对结果。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault.models import MASK, Record, now_iso

CORE = dict(
    title="淘宝",
    username="zhangsan",
    password="old-pass",
    url="https://taobao.com",
    notes="主要购物号",
    totp="JBSWY3DPEHPK3PXP",
    tags=["购物"],
    fields={"密保问题": "故乡"},
)


def legacy_update(record: Record, changes: dict) -> bool:
    """v1.0 `service.update` 的逐字副本（基准实现，不许改）。"""
    touched_password = False
    for key, value in changes.items():
        if value is None:
            continue
        if key == "tags":
            record.tags = [t.strip() for t in str(value).split(",") if t.strip()]
        elif key == "fields":
            continue
        elif hasattr(record, key):
            if key == "password" and value != record.password:
                touched_password = True
            setattr(record, key, value)
        else:
            record.fields[key] = value
    record.updated = now_iso()
    if touched_password:
        record.pw_changed = record.updated
    return touched_password


def _content(record: Record) -> dict:
    """只留「内容」，把全部时间戳剔除。

    **不要用时间戳之间的相等关系去推断语义**（例如「`pw_changed == updated` 就说明
    密码被改过」）：这个等式在时钟没有走动时**也会成立**，于是结论随机器负载抖动 ——
    这条用例曾经因此间歇性失败（秒级精度时代被 `timespec="seconds"` 的截断意外掩盖，
    改成微秒精度后暴露出来）。时间戳的正确关系改用下面 `_assert_pw_changed` 在
    **同一条记录内部**断言，与时钟分辨率无关。
    """
    data = record.to_dict()
    for key in ("id", "created", "updated", "pw_changed"):
        data.pop(key, None)
    return data


def _assert_pw_changed(case, record: Record, *, touched: bool) -> None:
    """`pw_changed` 的语义：改密码 → 跟随本次 `updated`；没改 → 保持 `created`。

    两条断言都在**同一条记录内部**比较，不跨记录、不依赖两次 `now_iso()` 是否相等。
    """
    if touched:
        case.assertEqual(record.pw_changed, record.updated, "改了密码，pw_changed 必须等于本次 updated")
        case.assertNotEqual(record.pw_changed, "", "改了密码却没写 pw_changed")
    else:
        case.assertEqual(record.pw_changed, record.created, "没改密码，pw_changed 必须保持 created")


class ApplyChangesEquivalenceTests(unittest.TestCase):
    CASES = (
        {"password": "a-brand-new-one"},
        {"username": "lisi", "url": "https://jd.com"},
        {"tags": "购物, 常用 ,,常用"},
        {"注册邮箱": "x@y.com"},
        {"title": None, "notes": "只改备注"},
        {"password": "old-pass"},  # 值没变：pw_changed 不该刷新
        {"totp": ""},
        {"notes": "n1", "自定义1": "v1", "自定义2": "v2"},
    )

    def test_equivalent_to_legacy_update(self):
        for changes in self.CASES:
            with self.subTest(changes=changes):
                fresh = Record(**{**CORE, "tags": list(CORE["tags"]), "fields": dict(CORE["fields"])})
                legacy = Record(**{**CORE, "tags": list(CORE["tags"]), "fields": dict(CORE["fields"])})
                legacy_touched = legacy_update(legacy, dict(changes))
                touched = fresh.apply_changes(dict(changes))
                # 内容等价（时间戳不参与比较，见 `_content` 的注释）
                self.assertEqual(_content(fresh), _content(legacy))
                self.assertEqual(touched, legacy_touched)
                # 时间戳的语义在两个实现里各自正确（同记录内部关系，与时钟无关）
                _assert_pw_changed(self, fresh, touched=touched)
                _assert_pw_changed(self, legacy, touched=legacy_touched)

    def test_returns_true_only_when_password_changed(self):
        record = Record(**{**CORE, "fields": dict(CORE["fields"])})
        self.assertTrue(record.apply_changes({"password": "new"}))
        self.assertFalse(record.apply_changes({"password": "new"}))
        self.assertFalse(record.apply_changes({"title": "别的"}))

    def test_password_change_refreshes_pw_changed(self):
        record = Record(**{**CORE, "fields": dict(CORE["fields"])})
        before = record.pw_changed
        record.apply_changes({"password": "new"})
        self.assertEqual(record.pw_changed, record.updated)
        self.assertGreaterEqual(record.pw_changed, before)

    def test_updated_always_refreshed(self):
        record = Record(**{**CORE, "fields": dict(CORE["fields"])})
        record.updated = "2020-01-01T00:00:00+00:00"
        record.apply_changes({"title": "新标题"})
        self.assertNotEqual(record.updated, "2020-01-01T00:00:00+00:00")

    def test_fields_dict_replaces_whole_table(self):
        """v1.1 追加分支：dict 形态的 fields 整表替换（暂存区覆盖/撤销用）。"""
        record = Record(**{**CORE, "fields": dict(CORE["fields"])})
        record.apply_changes({"fields": {"只剩这个": "x", "空的": ""}})
        self.assertEqual(record.fields, {"只剩这个": "x"})


class ToDictMaskingTests(unittest.TestCase):
    def test_default_dict_unchanged(self):
        """落盘路径用的默认形态：不得出现掩码字符。"""
        record = Record(**{**CORE, "fields": {"api_key": "sk-live"}})
        data = record.to_dict()
        self.assertEqual(data["password"], "old-pass")
        self.assertEqual(data["fields"]["api_key"], "sk-live")
        self.assertNotIn(MASK, str(data))

    def test_masked_dict(self):
        record = Record(**{**CORE, "fields": {"api_key": "sk-live", "密保问题": "故乡"}})
        data = record.to_dict(mask_secrets=True)
        self.assertEqual(data["password"], MASK)
        self.assertEqual(data["totp"], MASK)
        self.assertEqual(data["fields"]["api_key"], MASK)
        self.assertEqual(data["fields"]["密保问题"], "故乡")
        self.assertEqual(data["username"], "zhangsan")


class SensitiveMaskTests(unittest.TestCase):
    def test_mask_present_in_record_serialization_only_when_asked(self):
        record = Record(title="x", password="")
        masked = record.to_dict(mask_secrets=True)
        self.assertNotIn("password", masked)


if __name__ == "__main__":
    unittest.main()
