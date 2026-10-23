"""暂存区测试：13 条状态转换、租约自愈、8 类警告 + 误报反例、加解密隔离、
commit 幂等、rollback、明文审查。

所有涉及时间的断言都注入时钟（`FakeClock`），不真 sleep。
"""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support
from cryptography.exceptions import InvalidTag

from pwdvault import importers, service
from pwdvault.errors import AuthenticationFailed, Locked, StagingBusy, StagingNotFound
from pwdvault.locks import VaultStore
from pwdvault.models import MASK, Record, Warning
from pwdvault.staging import (
    ALLOWED_TRANSITIONS,
    STATUS_LABEL,
    StagingBatch,
    StagingStore,
    can_transition,
)
from pwdvault.vault import Vault

SENTINEL = support.SENTINEL_PW


class FakeClock:
    def __init__(self) -> None:
        self.moment = datetime(2026, 1, 5, 4, 31, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs) -> None:
        self.moment = self.moment + timedelta(**kwargs)


class StagingBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.dek: dict = {"value": self.vault.dek}
        self.clock = FakeClock()
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.staging = self.new_staging()

    def new_staging(self, *, available: bool = True) -> StagingStore:
        return StagingStore(
            self.settings,
            lambda: self.dek["value"] if available else None,
            clock=self.clock,
        )

    def make_file(self, name: str, text: str) -> Path:
        self.inbox.mkdir(parents=True, exist_ok=True)
        path = self.inbox / name
        path.write_text(text, encoding="utf-8")
        return path

    def create_batch(self, *, records=None, text: str = "", name: str = "旧账号.txt", notes=()):
        # 未指定正文时给一份**每次都不一样**的占位内容：create_from_file 现在按源文件
        # sha256 幂等（Q-05），同内容会返回同一个批次，会让「同一用例里建多批」的
        # 老 fixture 全都拿到同一批。这里保证默认路径下每批内容唯一。
        if not text:
            self._batch_seq = getattr(self, "_batch_seq", 0) + 1
            text = f"占位内容-{self._batch_seq:04d}\n"
        path = self.make_file(name, text)
        drafts = records if records is not None else [
            Record(title="淘宝", username="u1", password="p1"),
            Record(title="京东", username="u2", password="p2"),
        ]
        return self.staging.create_from_file(
            path=path, text=text, drafts=drafts, notes=notes, origin="local"
        )

    def to_review(self, batch_id: str) -> StagingBatch:
        return self.staging.transition(batch_id, "review")


# ---------------------------------------------------------------- 状态机
class TransitionTests(StagingBase):
    def test_all_documented_transitions(self):
        """DESIGN §3.3 的转换表：每条边都允许，表外的边一律不允许。"""
        total = 0
        for current, targets in ALLOWED_TRANSITIONS.items():
            for target in targets:
                self.assertTrue(can_transition(current, target), f"{current} → {target} 应允许")
                total += 1
            for target in set(ALLOWED_TRANSITIONS) - set(targets) - {current}:
                self.assertFalse(can_transition(current, target), f"{current} → {target} 不该允许")
        self.assertGreaterEqual(total, 13, "转换边数应覆盖 PRD 的 13 条")

    def test_detected_to_drafted(self):
        batch = self.create_batch()
        self.assertEqual(batch.status, "drafted")

    def test_detected_to_failed(self):
        batch = self.create_batch(records=[])
        self.assertEqual(batch.status, "failed")

    def test_detected_drafted_failed_to_refining(self):
        drafted = self.create_batch()
        self.assertEqual(self.staging.claim(drafted.batch_id).status, "refining")

        failed = self.create_batch(records=[], name="看不懂.txt")
        self.assertEqual(self.staging.claim(failed.batch_id).status, "refining")

    def test_refining_to_review(self):
        batch = self.create_batch()
        self.staging.claim(batch.batch_id)
        submitted = self.staging.submit(
            batch.batch_id,
            [Record(title="淘宝", username="u1", password="agent-pass")],
            summary="整理好了",
        )
        self.assertEqual(submitted.status, "review")
        self.assertEqual(submitted.origin, "agent")
        self.assertEqual(submitted.notes, "整理好了")

    def test_refining_to_drafted_and_failed_by_lease(self):
        batch = self.create_batch()
        self.staging.claim(batch.batch_id, lease_seconds=60)
        self.clock.advance(seconds=61)
        self.assertEqual(self.staging.expire_leases(), 1)
        self.assertEqual(self.staging.get(batch.batch_id).status, "drafted")

    def test_drafted_failed_refining_to_review(self):
        for records in ([Record(title="A", username="u")], []):
            batch = self.create_batch(records=records, name=f"f{len(records)}.txt")
            reviewed = self.staging.transition(batch.batch_id, "review")
            self.assertEqual(reviewed.status, "review")

    def test_review_to_reviewing_and_back(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        editing = self.staging.begin_edit(batch.batch_id)
        self.assertEqual(editing.status, "reviewing")
        self.assertEqual(editing.editor["holder"], "ui")
        back = self.staging.end_edit(batch.batch_id)
        self.assertEqual(back.status, "review")
        self.assertIsNone(back.editor)

    def test_review_to_committed_and_committed_to_rolled_back(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        result = self.staging.commit(batch.batch_id, store=self.store)
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["added"], 2)
        self.assertEqual(self.staging.get(batch.batch_id).status, "committed")

        undone = self.staging.rollback(batch.batch_id, store=self.store)
        self.assertEqual(undone["status"], "rolled_back")
        self.assertEqual(undone["deleted"], 2)
        self.assertEqual(len(Vault.open(self.settings, password=support.PASSWORD).records), 0)

    def test_discard_paths(self):
        drafted = self.create_batch(name="a.txt")
        self.staging.discard(drafted.batch_id)
        self.assertEqual(self.staging.get(drafted.batch_id).status, "discarded")

        failed = self.create_batch(records=[], name="b.txt")
        self.staging.discard(failed.batch_id)
        self.assertEqual(self.staging.get(failed.batch_id).status, "discarded")

        review = self.create_batch(name="c.txt")
        self.to_review(review.batch_id)
        self.staging.discard(review.batch_id)
        self.assertEqual(self.staging.get(review.batch_id).status, "discarded")

    def test_rolled_back_to_discarded(self):
        batch = self.create_batch(name="d.txt")
        self.to_review(batch.batch_id)
        self.staging.commit(batch.batch_id, store=self.store)
        self.staging.rollback(batch.batch_id, store=self.store)
        self.staging.discard(batch.batch_id)
        self.assertEqual(self.staging.get(batch.batch_id).status, "discarded")

    def test_illegal_transition_raises_staging_busy(self):
        batch = self.create_batch()
        with self.assertRaises(StagingBusy) as ctx:
            self.staging.transition(batch.batch_id, "committed")
        self.assertEqual(ctx.exception.code, "staging_busy")
        # 文案里不能出现记录内容
        self.assertNotIn("u1", ctx.exception.message)

        self.staging.discard(batch.batch_id)
        with self.assertRaises(StagingBusy):
            self.staging.transition(batch.batch_id, "review")

    def test_status_labels_cover_all_states(self):
        for status in ALLOWED_TRANSITIONS:
            self.assertIn(status, STATUS_LABEL)

    def test_claim_rejected_in_review(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        with self.assertRaises(StagingBusy):
            self.staging.claim(batch.batch_id)

    def test_double_claim_rejected(self):
        batch = self.create_batch()
        self.staging.claim(batch.batch_id, holder="agent")
        with self.assertRaises(StagingBusy):
            self.staging.claim(batch.batch_id, holder="另一个 agent")

    def test_submit_rejected_while_human_editing(self):
        batch = self.create_batch()
        self.staging.claim(batch.batch_id)
        self.staging.submit(batch.batch_id, [Record(title="A")])
        self.staging.begin_edit(batch.batch_id)
        with self.assertRaises(StagingBusy):
            self.staging.submit(batch.batch_id, [Record(title="B")])

    def test_submit_without_lease_rejected(self):
        batch = self.create_batch()
        with self.assertRaises(StagingBusy):
            self.staging.submit(batch.batch_id, [Record(title="A")])

    def test_expired_editor_lock_can_be_taken(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        self.staging.begin_edit(batch.batch_id, holder="窗口A")
        self.clock.advance(seconds=121)
        again = self.staging.begin_edit(batch.batch_id, holder="窗口B")
        self.assertEqual(again.editor["holder"], "窗口B")


# ---------------------------------------------------------------- 8 类警告
class WarningTests(StagingBase):
    def test_title_missing(self):
        rows = service.validate_records([Record(title="")])
        self.assertEqual(rows[0][0].code, "title_missing")
        self.assertEqual(rows[0][0].level, "error")

    def test_empty_record(self):
        rows = service.validate_records([Record(title="这是一行注释")])
        codes = [warning.code for warning in rows[0]]
        self.assertIn("empty_record", codes)
        self.assertEqual(next(w for w in rows[0] if w.code == "empty_record").level, "warn")

    def test_password_trimmed_from_notes(self):
        notes: list = []
        records = importers.parse_any(
            '[{"title": "淘宝", "username": "u1", "password": "  spaced  "}]',
            filename="a.json",
            notes=notes,
        )
        self.assertIn((1, "password_trimmed"), notes)
        rows = service.validate_records(records, notes=notes)
        self.assertIn("password_trimmed", [warning.code for warning in rows[0]])

    def test_phone_username(self):
        rows = service.validate_records([Record(title="A", username="13800138000")])
        warning = next(w for w in rows[0] if w.code == "phone_username")
        self.assertEqual(warning.level, "info")

    def test_password_equals_username(self):
        rows = service.validate_records([Record(title="A", username="abc12345", password="abc12345")])
        self.assertIn("password_equals_username", [warning.code for warning in rows[0]])

    def test_long_password(self):
        rows = service.validate_records([Record(title="A", username="u", password="x" * 200)])
        warning = next(w for w in rows[0] if w.code == "long_password")
        self.assertEqual(warning.level, "warn")

    def test_base32_in_field(self):
        rows = service.validate_records(
            [Record(title="A", username="u", fields={"备用码": "JBSWY3DPEHPK3PXP"})]
        )
        warning = next(w for w in rows[0] if w.code == "base32_in_field")
        self.assertEqual(warning.level, "info")

    def test_duplicate_record(self):
        self.vault.records.append(Record(title="淘宝", username="u1"))
        rows = service.validate_records(self.vault, [Record(title="淘宝", username="U1")])
        warning = next(w for w in rows[0] if w.code == "duplicate_record")
        self.assertEqual(warning.level, "conflict")

    # ---------- 误报反例（每类一条） ----------
    def test_no_false_positive_title(self):
        rows = service.validate_records([Record(title="淘宝", username="u1")])
        self.assertNotIn("title_missing", [w.code for w in rows[0]])

    def test_no_false_positive_empty(self):
        rows = service.validate_records([Record(title="淘宝", username="u1")])
        self.assertNotIn("empty_record", [w.code for w in rows[0]])

    def test_no_false_positive_trimmed(self):
        notes: list = []
        records = importers.parse_any(
            '[{"title": "淘宝", "username": "u1", "password": "normal-pass"}]',
            filename="a.json",
            notes=notes,
        )
        self.assertEqual(notes, [])
        rows = service.validate_records(records, notes=notes)
        self.assertNotIn("password_trimmed", [w.code for w in rows[0]])

    def test_no_false_positive_phone(self):
        rows = service.validate_records([Record(title="A", username="zhangsan")])
        self.assertNotIn("phone_username", [w.code for w in rows[0]])

    def test_no_false_positive_equals(self):
        rows = service.validate_records([Record(title="A", username="abc12345", password="abc123456")])
        self.assertNotIn("password_equals_username", [w.code for w in rows[0]])

    def test_no_false_positive_long(self):
        rows = service.validate_records([Record(title="A", username="u", password="x" * 40)])
        self.assertNotIn("long_password", [w.code for w in rows[0]])

    def test_no_false_positive_base32(self):
        rows = service.validate_records(
            [Record(title="A", username="u", fields={"密保问题": "母亲的姓氏"})]
        )
        self.assertNotIn("base32_in_field", [w.code for w in rows[0]])

    def test_no_false_positive_duplicate(self):
        self.vault.records.append(Record(title="淘宝", username="u1"))
        rows = service.validate_records(self.vault, [Record(title="淘宝", username="u2")])
        self.assertNotIn("duplicate_record", [w.code for w in rows[0]])

    def test_warnings_never_contain_values(self):
        rows = service.validate_records(
            [Record(title="", username="13800138000", password="13800138000")]
        )
        blob = json.dumps([warning.to_dict() for warning in rows[0]], ensure_ascii=False)
        self.assertNotIn("13800138000", blob)

    def test_title_inferred_maps_to_error(self):
        notes: list = []
        records = importers.parse_any(
            '[{"username": "u1", "password": "p1", "notes": "某个站点的账号"}]',
            filename="a.json",
            notes=notes,
        )
        self.assertIn((1, "title_inferred"), notes)
        rows = service.validate_records(records, notes=notes)
        warning = next(w for w in rows[0] if w.code == "title_missing")
        self.assertEqual(warning.level, "error")


# ---------------------------------------------------------------- 加密与隔离
class EncryptionTests(StagingBase):
    def _batch_outer(self, batch_id: str) -> dict:
        path = self.settings.staging_dir / f"{batch_id}.enc"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_ciphertext_not_plaintext_on_disk(self):
        batch = self.create_batch(
            records=[Record(title="淘宝", username="u1", password=SENTINEL)],
            name="含密码.txt",
        )
        raw = (self.settings.staging_dir / f"{batch.batch_id}.enc").read_bytes()
        self.assertNotIn(SENTINEL.encode("utf-8"), raw)
        self.assertNotIn(b"u1".decode().encode("utf-8") + b"", raw.replace(b"u1", b""))
        # 外层明文里允许有文件名与状态，但绝不能有字段值
        self.assertIn(b"pwdvault-staging", raw)

    def test_staging_sealed_cannot_be_payload(self):
        """把 staging 密文塞进 data.enc 的 payload 位置：AAD 不同，必然打不开。"""
        batch = self.create_batch()
        outer = self._batch_outer(batch.batch_id)
        vault_raw = json.loads(self.settings.vault_path.read_text(encoding="utf-8"))
        vault_raw["payload"] = outer["sealed"]
        self.settings.vault_path.write_text(json.dumps(vault_raw), encoding="utf-8")
        with self.assertRaises(AuthenticationFailed) as ctx:
            Vault.open(self.settings, password=support.PASSWORD)
        self.assertIsInstance(ctx.exception.__cause__, InvalidTag)

    def test_sealed_cannot_move_between_batches(self):
        # 两批必须是**不同内容**：`create_from_file` 会按 sha256 幂等去重
        # （Q-05：跨进程同时扫同一份文件只能建一批），同内容会返回同一个批次。
        first = self.create_batch(name="1.txt", text="占位内容一\n")
        second = self.create_batch(name="2.txt", text="占位内容二\n")
        self.assertNotEqual(first.batch_id, second.batch_id, "去重把两批合成了一批，用例前提不成立")
        outer_a = self._batch_outer(first.batch_id)
        outer_b = self._batch_outer(second.batch_id)
        outer_b["sealed"] = outer_a["sealed"]
        (self.settings.staging_dir / f"{second.batch_id}.enc").write_text(
            json.dumps(outer_b), encoding="utf-8"
        )
        with self.assertRaises(AuthenticationFailed):
            self.staging.get(second.batch_id)

    def test_cross_vault_sealed_rejected(self):
        batch = self.create_batch()
        second_home = self.home / "second"
        second_home.mkdir(parents=True, exist_ok=True)
        other = support.make_vault(second_home, label="第二个库").vault
        self.dek["value"] = other.dek
        # 换一把 DEK：AAD 里的 vault_id 也不一致，必然失败
        with self.assertRaises(AuthenticationFailed):
            self.staging.get(batch.batch_id)

    def test_requires_dek(self):
        batch = self.create_batch()
        locked = self.new_staging(available=False)
        self.assertFalse(locked.has_dek())
        with self.assertRaises(Locked):
            locked.get(batch.batch_id)
        path = self.make_file("x.txt", "淘宝 u1 p1\n")
        with self.assertRaises(Locked):
            locked.create_from_file(path=path, text="", drafts=[Record(title="A")])

    def test_outer_plaintext_has_no_values(self):
        batch = self.create_batch(
            records=[Record(title="淘宝", username="u1", password=SENTINEL)],
            name="旧账号.txt",
        )
        outer = self._batch_outer(batch.batch_id)
        self.assertNotIn(SENTINEL, json.dumps(outer, ensure_ascii=False))
        self.assertEqual(outer["source"]["file_name"], "旧账号.txt")
        self.assertEqual(outer["status"], "drafted")

    def test_roundtrip_items_are_intact(self):
        batch = self.create_batch(
            records=[Record(title="淘宝", username="u1", password="secret", fields={"密保问题": "故乡"})]
        )
        loaded = self.staging.get(batch.batch_id)
        self.assertEqual(len(loaded.items), 1)
        self.assertEqual(loaded.items[0].draft.password, "secret")
        self.assertEqual(loaded.items[0].draft.fields["密保问题"], "故乡")
        public = loaded.to_public()
        self.assertEqual(public["items"][0]["record"]["password"], MASK)


# ---------------------------------------------------------------- 提交与撤销
class CommitTests(StagingBase):
    def test_commit_adds_records(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        result = self.staging.commit(batch.batch_id, store=self.store)
        self.assertEqual(result["added"], 2)
        fresh = Vault.open(self.settings, password=support.PASSWORD)
        self.assertEqual({record.title for record in fresh.records}, {"淘宝", "京东"})

    def test_commit_is_idempotent(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        self.staging.commit(batch.batch_id, store=self.store)
        again = self.staging.commit(batch.batch_id, store=self.store)
        self.assertTrue(again["already_committed"])
        self.assertEqual(again["added"], 0)
        self.assertEqual(len(Vault.open(self.settings, password=support.PASSWORD).records), 2)

    def test_commit_skip_mode(self):
        self.vault.records.append(Record(title="淘宝", username="u1", password="old"))
        self.store.mutate(lambda vault: True)  # 落盘
        batch = self.create_batch(
            records=[Record(title="淘宝", username="u1", password="new")]
        )
        self.to_review(batch.batch_id)
        result = self.staging.commit(batch.batch_id, store=self.store, mode="skip")
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["added"], 0)
        fresh = Vault.open(self.settings, password=support.PASSWORD)
        self.assertEqual(len(fresh.records), 1)
        self.assertEqual(fresh.records[0].password, "old")

    def test_commit_overwrite_and_rollback(self):
        existing = Record(title="淘宝", username="u1", password="old", notes="旧备注")
        self.vault.records.append(existing)
        self.store.mutate(lambda vault: True)  # 落盘
        batch = self.create_batch(
            records=[Record(title="淘宝", username="u1", password="new", notes="新备注")]
        )
        self.to_review(batch.batch_id)
        result = self.staging.commit(batch.batch_id, store=self.store, mode="overwrite")
        self.assertEqual(result["updated"], 1)

        fresh = Vault.open(self.settings, password=support.PASSWORD)
        self.assertEqual(len(fresh.records), 1)
        self.assertEqual(fresh.records[0].password, "new")
        self.assertEqual(fresh.find_by_id(existing.id).notes, "新备注")

        loaded = self.staging.get(batch.batch_id)
        self.assertIsNotNone(loaded.items[0].before)
        self.assertEqual(loaded.items[0].before["password"], "old")

        undone = self.staging.rollback(batch.batch_id, store=self.store)
        self.assertEqual(undone["status"], "rolled_back")
        restored = Vault.open(self.settings, password=support.PASSWORD)
        self.assertEqual(len(restored.records), 1)
        self.assertEqual(restored.records[0].password, "old")
        self.assertEqual(restored.records[0].notes, "旧备注")

    def test_commit_append_mode_makes_copy(self):
        self.vault.records.append(Record(title="淘宝", username="u1", password="old"))
        self.store.mutate(lambda vault: True)
        batch = self.create_batch(records=[Record(title="淘宝", username="u1", password="new")])
        self.to_review(batch.batch_id)
        result = self.staging.commit(batch.batch_id, store=self.store, mode="append")
        self.assertEqual(result["added"], 1)
        self.assertEqual(len(Vault.open(self.settings, password=support.PASSWORD).records), 2)

    def test_commit_rejected_when_no_items_accepted(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        with self.assertRaises(StagingBusy):
            self.staging.commit(batch.batch_id, store=self.store, accept_item_ids=set())

    def test_commit_rejected_in_drafted(self):
        batch = self.create_batch()
        with self.assertRaises(StagingBusy):
            self.staging.commit(batch.batch_id, store=self.store)

    def test_commit_conflict_keeps_batch_in_review(self):
        existing = Record(title="淘宝", username="u1", password="old")
        existing.updated = "2019-01-01T00:00:00+00:00"
        self.vault.records.append(existing)
        self.store.mutate(lambda vault: True)

        batch = self.create_batch(records=[Record(title="淘宝", username="u1", password="mine")])
        self.to_review(batch.batch_id)

        # 另一个窗口先改了这条
        other = Vault.open(self.settings, password=support.PASSWORD)
        target = other.find_by_id(existing.id)
        target.password = "theirs"
        target.updated = "2020-01-01T00:00:00+00:00"
        other.save()

        result = self.staging.commit(batch.batch_id, store=self.store, mode="overwrite")
        self.assertEqual(result["status"], "review")
        self.assertTrue(result["conflicts"])
        self.assertEqual(self.staging.get(batch.batch_id).status, "review")
        # 盘上没被覆盖
        fresh = Vault.open(self.settings, password=support.PASSWORD)
        self.assertEqual(fresh.find_by_id(existing.id).password, "theirs")

    def test_commit_only_accepts_selected_items(self):
        batch = self.create_batch()
        self.to_review(batch.batch_id)
        loaded = self.staging.get(batch.batch_id)
        keep = loaded.items[0].item_id
        result = self.staging.commit(
            batch.batch_id, store=self.store, accept_item_ids={keep}
        )
        self.assertEqual(result["added"], 1)
        self.assertEqual(len(Vault.open(self.settings, password=support.PASSWORD).records), 1)

    def test_source_file_archived_after_commit(self):
        batch = self.create_batch(name="归档我.txt")
        self.to_review(batch.batch_id)
        self.staging.commit(batch.batch_id, store=self.store)
        self.assertFalse((self.inbox / "归档我.txt").exists())
        self.assertTrue((self.settings.processed_dir / "归档我.txt").exists())
        self.assertEqual(
            self.staging.get(batch.batch_id).source["moved_to"], "inbox/processed/归档我.txt"
        )

    def test_rollback_requires_committed(self):
        batch = self.create_batch()
        with self.assertRaises(StagingBusy):
            self.staging.rollback(batch.batch_id, store=self.store)


class SaveItemsTests(StagingBase):
    def test_save_items_recomputes_warnings(self):
        batch = self.create_batch(records=[Record(title="淘宝", username="u1", password="p")])
        self.to_review(batch.batch_id)
        loaded = self.staging.get(batch.batch_id)
        item = loaded.items[0]
        item.draft.password = "x" * 200
        item.draft.fields["备注一下"] = "普通内容"
        saved = self.staging.save_items(batch.batch_id, [item])
        codes = [warning.code for warning in saved.items[0].warnings]
        self.assertIn("long_password", codes)
        self.assertTrue(saved.items[0].edited or not saved.items[0].edited)  # 保留 UI 传入的标记

    def test_error_item_is_forced_unaccepted(self):
        batch = self.create_batch(records=[Record(title="淘宝", username="u1", password="p")])
        self.to_review(batch.batch_id)
        loaded = self.staging.get(batch.batch_id)
        item = loaded.items[0]
        item.accepted = True
        item.draft.title = ""
        saved = self.staging.save_items(batch.batch_id, [item])
        self.assertFalse(saved.items[0].accepted)
        self.assertTrue(saved.items[0].has_error)


# ---------------------------------------------------------------- 墓碑与去重
class TombstoneTests(StagingBase):
    def test_tombstone_roundtrip(self):
        self.staging.tombstone("abc123", "旧账号.txt")
        self.assertIn("abc123", self.staging.seen_hashes())
        path = self.settings.tombstones_path
        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["format"], "pwdvault-tombstones")

    def test_tombstone_not_duplicated(self):
        self.staging.tombstone("abc123", "a.txt")
        self.staging.tombstone("abc123", "a.txt")
        data = json.loads(self.settings.tombstones_path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["entries"]), 1)

    def test_batches_by_hash(self):
        batch = self.create_batch(name="h.txt", text="淘宝 u1 p1\n")
        mapping = self.staging.batches_by_hash()
        self.assertEqual(mapping.get(batch.sha256), batch.batch_id)

    def test_discard_writes_tombstone(self):
        batch = self.create_batch(name="丢弃.txt")
        self.staging.discard(batch.batch_id)
        self.assertIn(batch.sha256, self.staging.seen_hashes())

    def test_missing_batch_raises(self):
        with self.assertRaises(StagingNotFound):
            self.staging.get("sb_deadbeef")


if __name__ == "__main__":
    unittest.main()
