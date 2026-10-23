"""业务层测试：搜索、合并去重、TOTP 标准向量、体检。"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault import service
from pwdvault.config import Settings
from pwdvault.errors import InvalidRecord
from pwdvault.models import Record, score_secret
from pwdvault.vault import Vault

FAST_KDF = {"algo": "argon2id", "time_cost": 1, "memory_cost": 8192, "parallelism": 1}
PASSWORD = "测试 词组 用来 加密 数据 的"


def make_vault(testcase) -> Vault:
    tmp = tempfile.TemporaryDirectory()
    testcase.addCleanup(tmp.cleanup)
    settings = Settings(vault_path=Path(tmp.name) / "data.enc", snapshot_keep=0, kdf=dict(FAST_KDF))
    vault, _ = Vault.create(settings, PASSWORD)
    return vault


class TotpTests(unittest.TestCase):
    """RFC 6238 附录 B 的官方测试向量（SHA-1，8 位）。"""

    SECRET = base64.b32encode(b"12345678901234567890").decode()

    def test_rfc6238_vectors(self):
        cases = {
            59: "94287082",
            1111111109: "07081804",
            1111111111: "14050471",
            1234567890: "89005924",
            2000000000: "69279037",
            20000000000: "65353130",
        }
        for at, expected in cases.items():
            code, _ = service.totp_code(self.SECRET, digits=8, at=at)
            self.assertEqual(code, expected, f"T={at} 的验证码应为 {expected}")

    def test_six_digits_default(self):
        code, remain = service.totp_code(self.SECRET, at=59)
        self.assertEqual(len(code), 6)
        self.assertTrue(1 <= remain <= 30)

    def test_otpauth_uri_supported(self):
        uri = f"otpauth://totp/Demo:me?secret={self.SECRET}&issuer=Demo"
        self.assertEqual(service.extract_totp_secret(uri), self.SECRET)
        self.assertEqual(service.totp_code(uri, digits=8, at=59)[0], "94287082")

    def test_invalid_secret(self):
        from pwdvault.errors import InvalidRecord

        with self.assertRaises(InvalidRecord):
            service.totp_code("!!!not-base32!!!")


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.vault = make_vault(self)
        for item in (
            {"title": "淘宝", "username": "zhangsan", "tags": "购物", "网址": "https://taobao.com"},
            {"title": "京东", "username": "lisi", "tags": "购物,常用"},
            {"title": "GitHub", "username": "zhangsan", "tags": "开发", "ssh": "~/.ssh/id_rsa"},
        ):
            self.vault.records.append(Record.from_dict(item))

    def test_fuzzy_title(self):
        self.assertEqual([r.title for r in service.search(self.vault, "淘宝")], ["淘宝"])

    def test_shared_username_matches_multiple(self):
        titles = {r.title for r in service.search(self.vault, "zhangsan")}
        self.assertEqual(titles, {"淘宝", "GitHub"})

    def test_field_prefix(self):
        self.assertEqual([r.title for r in service.search(self.vault, "tag:开发")], ["GitHub"])

    def test_custom_field_searchable(self):
        self.assertEqual([r.title for r in service.search(self.vault, "id_rsa")], ["GitHub"])

    def test_title_ranks_above_other_fields(self):
        """标题命中要排在只在自定义字段里命中之前。"""
        self.vault.records.append(Record.from_dict({"title": "购物清单", "备注": "无"}))
        results = service.search(self.vault, "购物")
        self.assertEqual(results[0].title, "购物清单")

    def test_no_match(self):
        self.assertEqual(service.search(self.vault, "不存在的站点"), [])

    def test_resolve_ambiguous(self):
        from pwdvault.errors import AmbiguousRecord

        with self.assertRaises(AmbiguousRecord):
            service.resolve(self.vault, "zhangsan")

    def test_resolve_by_id(self):
        target = self.vault.records[1]
        self.assertEqual(service.resolve(self.vault, target.id).title, "京东")


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.vault = make_vault(self)
        self.vault.records.append(Record.from_dict({"title": "淘宝", "username": "u1", "password": "old"}))

    def test_skip_mode(self):
        report = service.merge_import(
            self.vault, [Record.from_dict({"title": "淘宝", "username": "u1", "password": "new"})], mode="skip"
        )
        self.assertEqual(report["skipped"], 1)
        self.assertEqual(self.vault.records[0].password, "old")

    def test_update_mode(self):
        report = service.merge_import(
            self.vault, [Record.from_dict({"title": "淘宝", "username": "u1", "password": "new"})], mode="update"
        )
        self.assertEqual(report["updated"], 1)
        self.assertEqual(self.vault.records[0].password, "new")

    def test_append_mode_assigns_new_id(self):
        incoming = Record.from_dict({"title": "淘宝", "username": "u1", "password": "dup"})
        original_id = self.vault.records[0].id
        report = service.merge_import(self.vault, [incoming], mode="append")
        self.assertEqual(report["added"], 1)
        self.assertNotEqual(self.vault.records[1].id, original_id)

    def test_case_insensitive_dedup(self):
        service.merge_import(
            self.vault, [Record.from_dict({"title": "淘宝", "username": "U1"})], mode="skip"
        )
        self.assertEqual(len(self.vault.records), 1)


class HealthTests(unittest.TestCase):
    def test_detects_weak_and_reused(self):
        vault = make_vault(self)
        for item in (
            {"title": "A", "password": "123456"},
            {"title": "B", "password": "同一个强密码 ABC#2024xyz"},
            {"title": "C", "password": "同一个强密码 ABC#2024xyz"},
        ):
            vault.records.append(Record.from_dict(item))
        report = service.health(vault)
        self.assertEqual(report["total"], 3)
        self.assertTrue(any(item["title"] == "A" for item in report["weak_passwords"]))
        self.assertEqual(len(report["reused_passwords"]), 1)


class ScoreTests(unittest.TestCase):
    def test_digits_are_weak(self):
        entropy, level = score_secret("123456")
        self.assertLess(entropy, 40)

    def test_passphrase_is_strong(self):
        entropy, _ = score_secret("橘子 铁路 钢琴 沙漠 灯塔 钥匙")
        self.assertGreater(entropy, 70)


class UpdateTests(unittest.TestCase):
    def test_password_change_updates_timestamp(self):
        vault = make_vault(self)
        record = Record.from_dict({"title": "A", "password": "old"})
        vault.records.append(record)
        before = record.pw_changed
        service.update(vault, record, {"password": "newlonger123"})
        self.assertNotEqual(record.pw_changed, "")
        self.assertEqual(record.password, "newlonger123")
        self.assertGreaterEqual(record.pw_changed, before)

    def test_unknown_key_goes_to_fields(self):
        vault = make_vault(self)
        record = Record.from_dict({"title": "A"})
        service.update(vault, record, {"注册邮箱": "x@y.com"})
        self.assertEqual(record.fields["注册邮箱"], "x@y.com")


class CopyFieldTests(unittest.TestCase):
    """`copy_field` 的两个坑：位置参数形状、`seconds<=0` 的诚实回执。

    剪贴板一律打桩：这层测试只关心「回执说了什么」，不碰真剪贴板。
    """

    def setUp(self):
        self.record = Record.from_dict({"title": "淘宝", "username": "zhangsan", "password": "P@ssw0rd-x"})
        self.copied: list[str] = []
        self.cleared: list[tuple[str, float]] = []
        self._orig_copy = service.clipboard.copy_text
        self._orig_auto = service.clipboard.copy_with_autoclear

        def fake_copy(text):
            self.copied.append(text)

        def fake_auto(text, seconds, *, spawn=True, on_fired=None):
            self.copied.append(text)
            self.cleared.append(("armed", float(seconds)))
            return {"auto_clear": True, "seconds": float(seconds), "mode": "process", "spawn": spawn}

        service.clipboard.copy_text = fake_copy
        service.clipboard.copy_with_autoclear = fake_auto
        self.addCleanup(setattr, service.clipboard, "copy_text", self._orig_copy)
        self.addCleanup(setattr, service.clipboard, "copy_with_autoclear", self._orig_auto)

    def test_second_positional_is_field_not_record(self):
        """`copy_field(rec, "password")` 曾经把 "password" 当成 record 然后报错。"""
        receipt = service.copy_field(self.record, "password", spawn=False, seconds=30)
        self.assertEqual(receipt["field"], "password")
        self.assertEqual(self.copied, ["P@ssw0rd-x"])

    def test_three_positional_vault_form_still_works(self):
        vault = make_vault(self)
        receipt = service.copy_field(vault, self.record, "username", spawn=False, seconds=30)
        self.assertEqual(receipt["field"], "username")

    def test_conflicting_positional_raises_clearly(self):
        with self.assertRaises(InvalidRecord):
            service.copy_field(self.record, "username", "totp", spawn=False)

    def test_seconds_zero_does_not_arm_an_instant_timer(self):
        """`seconds=0` 绝不能落进 copy_with_autoclear —— 它会在 0 秒时立刻清空剪贴板。"""
        receipt = service.copy_field(self.record, field="password", spawn=False, seconds=0)
        self.assertFalse(receipt["auto_clear"])
        self.assertEqual(receipt["auto_clear_in"], 0)
        self.assertEqual(receipt["auto_clear_mode"], "none")
        self.assertIn("hint", receipt)
        self.assertEqual(self.cleared, [], "0 秒时不许装定时器")
        self.assertEqual(self.copied, ["P@ssw0rd-x"])

    def test_negative_seconds_treated_like_zero(self):
        receipt = service.copy_field(self.record, field="password", spawn=False, seconds=-5)
        self.assertFalse(receipt["auto_clear"])
        self.assertEqual(self.cleared, [])

    def test_positive_seconds_arms_timer(self):
        receipt = service.copy_field(self.record, field="password", spawn=False, seconds=20)
        self.assertTrue(receipt["auto_clear"])
        self.assertEqual(receipt["auto_clear_in"], 20)
        self.assertNotIn("hint", receipt)

    def test_receipt_never_contains_plaintext(self):
        receipt = service.copy_field(self.record, field="password", spawn=False, seconds=20)
        self.assertNotIn("P@ssw0rd-x", json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
