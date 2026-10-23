"""存储层测试：创建、打开、快照、改密码、损坏恢复。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault.config import Settings
from pwdvault.errors import AuthenticationFailed, CorruptVault, VaultExists
from pwdvault.models import Record
from pwdvault.vault import Vault

FAST_KDF = {"algo": "argon2id", "time_cost": 1, "memory_cost": 8192, "parallelism": 1}
PASSWORD = "测试 用 的 主 密码 词组"
NEW_PASSWORD = "另一个 完全 不同 的 词组 here"


class VaultLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = Settings(
            vault_path=Path(self.tmp.name) / "data.enc",
            snapshot_keep=3,
            kdf=dict(FAST_KDF),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _create(self):
        return Vault.create(self.settings, PASSWORD)

    def test_create_writes_file_with_all_wraps(self):
        vault, recovery = self._create()
        self.assertTrue(self.settings.vault_path.exists())
        raw = json.loads(self.settings.vault_path.read_text(encoding="utf-8"))
        self.assertEqual(raw["format"], "pwdvault")
        self.assertIn("password", raw["wraps"])
        self.assertIn("recovery", raw["wraps"])
        self.assertRegex(recovery, r"^[A-Z2-7]{4}(-[A-Z2-7]{4})+$")
        self.assertEqual(len(vault.records), 0)

    def test_create_refuses_existing(self):
        self._create()
        with self.assertRaises(VaultExists):
            self._create()

    def test_open_with_password(self):
        self._create()
        vault = Vault.open(self.settings, password=PASSWORD)
        self.assertEqual(vault.unlocked_by, "password")

    def test_open_with_wrong_password(self):
        self._create()
        with self.assertRaises(AuthenticationFailed):
            Vault.open(self.settings, password="错误的密码")

    def test_open_with_recovery_code(self):
        _, recovery = self._create()
        vault = Vault.open(self.settings, recovery_code=recovery)
        self.assertEqual(vault.unlocked_by, "recovery")

    def test_records_survive_roundtrip(self):
        vault, _ = self._create()
        record = Record.from_dict({"title": "淘宝", "username": "u1", "password": "p1",
                                   "tags": "购物,常用", "密保问题": "故乡"})
        vault.records.append(record)
        vault.save()

        again = Vault.open(self.settings, password=PASSWORD)
        self.assertEqual(len(again.records), 1)
        self.assertEqual(again.records[0].title, "淘宝")
        self.assertEqual(again.records[0].tags, ["购物", "常用"])
        self.assertEqual(again.records[0].fields["密保问题"], "故乡")
        # id 必须稳定，否则每次解锁后引用都会失效
        self.assertEqual(again.records[0].id, record.id)

    def test_revision_increments(self):
        vault, _ = self._create()
        self.assertEqual(vault.revision, 0)
        vault.save()
        self.assertEqual(vault.revision, 1)
        vault.save()
        self.assertEqual(vault.revision, 2)

    def test_snapshots_created_and_rotated(self):
        vault, _ = self._create()
        for index in range(6):
            vault.records.append(Record.from_dict({"title": f"站点{index}"}))
            vault.save()
        snaps = list(self.settings.snapshot_dir.glob("data-*.enc"))
        self.assertEqual(len(snaps), 3, "应只保留 snapshot_keep 份")

    def test_no_tmp_file_left_behind(self):
        vault, _ = self._create()
        vault.save()
        leftovers = list(self.settings.vault_path.parent.glob("*.tmp"))
        self.assertEqual(leftovers, [])

    def test_change_password_keeps_data_and_recovery(self):
        vault, recovery = self._create()
        vault.records.append(Record.from_dict({"title": "邮箱", "password": "secret"}))
        vault.save()

        reopened = Vault.open(self.settings, password=PASSWORD)
        reopened.rewrap_password(NEW_PASSWORD)
        reopened.save()

        with self.assertRaises(AuthenticationFailed):
            Vault.open(self.settings, password=PASSWORD)
        self.assertEqual(len(Vault.open(self.settings, password=NEW_PASSWORD).records), 1)
        # 恢复码用独立 salt，换主密码后必须依然有效
        self.assertEqual(len(Vault.open(self.settings, recovery_code=recovery).records), 1)

    def test_reset_recovery_invalidates_old(self):
        vault, old_code = self._create()
        new_code = vault.reset_recovery()
        vault.save()
        self.assertNotEqual(old_code, new_code)
        self.assertIsNotNone(Vault.open(self.settings, recovery_code=new_code))
        with self.assertRaises(AuthenticationFailed):
            Vault.open(self.settings, recovery_code=old_code)

    def test_corrupt_file_detected(self):
        self._create()
        self.settings.vault_path.write_text("{ 这不是 json", encoding="utf-8")
        with self.assertRaises(CorruptVault):
            Vault.open(self.settings, password=PASSWORD)

    def test_truncated_file_detected(self):
        self._create()
        raw = self.settings.vault_path.read_text(encoding="utf-8")
        self.settings.vault_path.write_text(raw[: len(raw) // 2], encoding="utf-8")
        with self.assertRaises(CorruptVault):
            Vault.open(self.settings, password=PASSWORD)

    def test_payload_tampering_detected(self):
        self._create()
        raw = json.loads(self.settings.vault_path.read_text(encoding="utf-8"))
        ct = raw["payload"]["ct"]
        raw["payload"]["ct"] = ("A" if ct[0] != "A" else "B") + ct[1:]
        self.settings.vault_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(AuthenticationFailed):
            Vault.open(self.settings, password=PASSWORD)

    def test_wrap_swap_attack_detected(self):
        """把 recovery 的包裹挪到 password 位置，AAD 绑定应当拒绝。"""
        self._create()
        raw = json.loads(self.settings.vault_path.read_text(encoding="utf-8"))
        raw["wraps"]["password"] = dict(raw["wraps"]["recovery"])
        raw["wraps"]["password"].pop("salt", None)
        self.settings.vault_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(AuthenticationFailed):
            Vault.open(self.settings, password=PASSWORD)

    def test_snapshot_restore_path(self):
        """快照能解开，且内容就是保存前的状态。"""
        vault, _ = self._create()
        vault.records.append(Record.from_dict({"title": "第一条"}))
        vault.save()  # 此时产生一份「只有 0 条」的快照
        vault.records.append(Record.from_dict({"title": "第二条"}))
        vault.save()

        snaps = sorted(self.settings.snapshot_dir.glob("data-*.enc"))
        first = snaps[0]
        restored_settings = Settings(vault_path=first, snapshot_keep=0, kdf=dict(FAST_KDF))
        restored = Vault.open(restored_settings, password=PASSWORD)
        self.assertEqual(len(restored.records), 1)
        self.assertEqual(restored.records[0].title, "第一条")


if __name__ == "__main__":
    unittest.main()
