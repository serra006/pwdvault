"""暂存区判重缓存 / 明文总结扫描 / 编辑锁可配 三块的回归测试。

覆盖三件事，每件都对应一条「改坏就会静默出错」的路径：

1. **`_digest_index()` 的缓存失效**（Q-05 的落地风险）：批次文件被清理之后，
   同一个文件再进 inbox 必须能重新建批。缓存里如果留下「幽灵批次」，
   用户会看到「东西放进去了但什么都没发生」，而且没有任何报错。
2. **Agent 一句话总结的敏感内容扫描**（O-2）：`notes` 是明文落在 `sb_*.enc`
   外层 JSON 里的，命中敏感内容必须整条替换；同时保留反向对照 —— 正常总结
   不许被误伤（误伤等于把功能关掉）。
3. **编辑锁 / 暂存区锁的超时可配**（O-4）：`[staging] editor_lock_seconds`
   写进 config.toml 之后必须真的生效，而不是永远吃模块常量。

顺带把 O-3（`Record.__repr__` 不带明文）钉一条，因为它和 O-2 是同一类地雷。

所有涉及时间的断言都注入时钟，不真 sleep。
"""

from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import staging as staging_module
from pwdvault.config import load_settings
from pwdvault.locks import VaultStore
from pwdvault.models import Record
from pwdvault.staging import NOTES_REDACTED_TEXT, StagingStore

SENTINEL_PW = "ZZ-PvProbe-Pw-staging-cache-DO-NOT-LEAK"
SENTINEL_TOTP = "JBSWY3DPEHPK3PXPZZ"
SENTINEL_FIELD = "ZZ-PvProbe-Field-staging-cache-DO-NOT-LEAK"


class FakeClock:
    """可注入时钟：所有与时间有关的断言都靠它，绝不真 sleep。"""

    def __init__(self) -> None:
        self.moment = datetime(2026, 1, 5, 4, 31, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs) -> None:
        self.moment = self.moment + timedelta(**kwargs)


class StagingCacheBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.clock = FakeClock()
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.staging = StagingStore(self.settings, lambda: self.vault.dek, clock=self.clock)

    # ------------------------------------------------------------ 夹具
    def write_source(self, name: str, text: str) -> Path:
        self.inbox.mkdir(parents=True, exist_ok=True)
        path = self.inbox / name
        path.write_text(text, encoding="utf-8")
        return path

    def create_batch(self, *, name: str = "源文件.txt", text: str = "", drafts=None):
        body = text or f"内容-{name}\n"
        path = self.write_source(name, body)
        records = drafts if drafts is not None else [Record(title="淘宝", username="u1", password="p1")]
        return self.staging.create_from_file(path=path, text=body, drafts=records, origin="local")

    def outer_of(self, batch_id: str) -> dict:
        path = self.settings.staging_dir / f"{batch_id}.enc"
        return json.loads(path.read_text(encoding="utf-8"))


# =====================================================================  1. 缓存失效
class DigestCacheInvalidationTests(StagingCacheBase):
    def test_inbox_still_quiet_after_discard_because_tombstone_not_cache(self):
        """丢弃之后，**inbox 扫描**必须保持安静 —— 而且拦住它的得是墓碑，不是缓存。

        两条界线要分清：

        1. **inbox 扫描**（本用例守的）：DESIGN §4.4 与 T04 验收 ③ 把丢弃定义成
           「用户说过这一份不要了，别再来烦我」。源文件通常还留在 `inbox/` 里，而扫描
           是 2 秒一轮，所以墓碑必须**按 sha256 无条件跳过**，不能看时刻放行 ——
           一旦放行，丢掉的那份会立刻再建一批，这个功能就毁了。
        2. **直接调 `create_from_file`**（Web 端重新上传）：它不走墓碑，会新建一批。
           这是有意的：上传是用户明确的动作，静默地把他丢掉的东西原样递回来
           （`deduped=True` + `status="discarded"`）会让调用方以为「已经处理过」，
           等于把这次操作吞掉。

        真正要防的是**缓存替墓碑背锅**：缓存里那条残留若继续拦人，会没有任何日志。
        所以用**全新实例**（冷缓存）复现一遍，断言两个实例结论一致。
        """
        batch = self.create_batch(name="丢弃后重放.txt", text="淘宝 u1 p1\n")
        digest = self.outer_of(batch.batch_id)["source"]["sha256"]
        self.assertIn(digest, self.staging._digest_index(), "建批后缓存里应有这一条")

        self.staging.discard(batch.batch_id)
        self.assertIn(digest, self.staging.seen_hashes(), "丢弃必须写墓碑（这是挡住重放的东西）")

        cold = StagingStore(self.settings, lambda: self.vault.dek, clock=self.clock)
        again = cold.create_from_file(
            path=self.inbox / "丢弃后重放.txt",
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", password="p1")],
            origin="local",
        )
        # 上传路径：丢弃过的一批不算「已存在」，应当开一批新的（见上第 2 条）。
        self.assertFalse(again.deduped, "不能把丢弃过的批次当成「已存在」递回去")
        self.assertNotEqual(again.batch_id, batch.batch_id, "必须是一个全新批次")

        # 而 inbox 扫描路径仍然被墓碑挡住 —— 这才是 T04 验收 ③ 要求的。
        from pwdvault.inbox import InboxWatcher

        for store in (self.staging, cold):
            watcher = InboxWatcher(self.settings, staging=store, interval=999)
            self.assertEqual(
                watcher.scan_once(),
                [],
                "丢进墓碑的内容，inbox 扫描必须保持安静（DESIGN §4.4 / T04 验收 ③）",
            )

    def test_purged_batch_file_leaves_no_ghost_in_digest_index(self):
        """批次文件被清理后，同一份内容必须能重新建批（缓存不能留幽灵）。"""
        source = self.write_source("清理后重放.txt", "淘宝 u1 p1\n")
        batch = self.staging.create_from_file(
            path=source,
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", password="p1")],
            origin="local",
        )
        digest = self.outer_of(batch.batch_id)["source"]["sha256"]
        self.assertIn(digest, self.staging._digest_index())

        self.staging.transition(batch.batch_id, "review")
        self.staging.commit(batch.batch_id, store=self.store)
        self.assertEqual(self.staging.get(batch.batch_id).status, "committed")

        # keep_days=0 的判据是 `updated < now`：先把时钟推过批次最后更新时间
        self.clock.advance(minutes=1)
        removed = self.staging.purge_expired_batches(keep_days=0)
        self.assertGreaterEqual(removed, 1, "keep_days=0 时已完结批次必须被清掉")
        self.assertFalse(
            (self.settings.staging_dir / f"{batch.batch_id}.enc").exists(),
            "批次文件应已删除",
        )
        self.assertNotIn(
            digest,
            self.staging._digest_index(),
            "文件删了，缓存里那条 `文件名 → sha256` 必须一起没，否则同一内容会被判成「已有批次」",
        )

        fresh = self.staging.create_from_file(
            path=source,
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", password="p1")],
            origin="local",
        )
        self.assertNotEqual(fresh.batch_id, batch.batch_id, "清理之后必须能建出**新**批次")
        self.assertFalse(fresh.deduped)

    def test_dedupe_index_argument_is_the_only_dedupe_hint(self):
        """`dedupe_index` 快路径命中直接返回既有批次；未命中仍以锁内真实目录为准。"""
        batch = self.create_batch(name="快路径.txt", text="淘宝 u1 p1\n")
        digest = self.outer_of(batch.batch_id)["source"]["sha256"]

        # 快路径命中：传入一个手工构造的索引，必须原样返回该批次
        other = self.create_batch(name="另一份.txt", text="京东 u2 p2\n")
        hit = self.staging.create_from_file(
            path=self.inbox / "快路径.txt",
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", password="p1")],
            origin="local",
            dedupe_index={digest: other.batch_id},
        )
        self.assertEqual(hit.batch_id, other.batch_id, "快路径给的 batch_id 必须被采信")

        # 快路径落空 + 锁内命中：必须回落到真实目录，而不是相信空索引
        missed = self.staging.create_from_file(
            path=self.inbox / "快路径.txt",
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", password="p1")],
            origin="local",
            dedupe_index={},
        )
        self.assertEqual(missed.batch_id, batch.batch_id, "快路径落空后必须由锁内复查兜住")
        self.assertTrue(missed.deduped)

    def test_created_batch_is_registered_back_into_dedupe_index(self):
        """建完一批要把自己登记回调用方的 `dedupe_index`，否则同一轮扫描会重建。"""
        index: dict[str, str] = {}
        first = self.create_batch(name="登记.txt", text="淘宝 u1 p1\n")
        digest = self.outer_of(first.batch_id)["source"]["sha256"]
        self.assertNotIn(digest, index)

        created = self.staging.create_from_file(
            path=self.inbox / "登记2.txt",
            text="京东 u2 p2\n",
            drafts=[Record(title="京东", username="u2", password="p2")],
            origin="local",
            dedupe_index=index,
        )
        new_digest = self.outer_of(created.batch_id)["source"]["sha256"]
        self.assertEqual(index.get(new_digest), created.batch_id, "新建的批次必须写回 dedupe_index")


# =====================================================================  2. O-2 明文总结
class NotesScrubbingTests(StagingCacheBase):
    def to_refining(self, batch_id: str) -> None:
        self.staging.claim(batch_id, holder="agent")

    def test_summary_with_field_value_is_replaced_whole(self):
        """总结里出现本次草稿的密码 → 整条替换，外层 JSON 里绝不能有明文。"""
        batch = self.create_batch(
            name="总结含密码.txt",
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", password=SENTINEL_PW)],
        )
        self.to_refining(batch.batch_id)
        self.staging.submit(
            batch.batch_id,
            [Record(title="淘宝", username="u1", password=SENTINEL_PW)],
            holder="agent",
            summary=f"已整理 1 条，其中淘宝密码是 {SENTINEL_PW}",
        )

        outer = self.outer_of(batch.batch_id)
        self.assertEqual(outer["notes"], NOTES_REDACTED_TEXT, "命中敏感内容必须整条替换")
        self.assertTrue(outer["notes_redacted"], "替换必须留痕，否则用户以为总结被吞了")
        blob = json.dumps(outer, ensure_ascii=False)
        self.assertNotIn(SENTINEL_PW, blob, "外层明文里出现了密码")

    def test_summary_quoting_a_dropped_totp_is_also_replaced(self):
        """探针不只看「本次交回的记录」，也要看「上一轮草稿」里的值。

        Agent 最典型的泄漏是它读了源文件、把里面的 TOTP 复述进总结，但交回时
        没有把这个字段带上 —— 只拿本次 records 当探针会漏掉这种。
        """
        batch = self.create_batch(
            name="总结含TOTP.txt",
            text="淘宝 u1 p1\n",
            drafts=[Record(title="淘宝", username="u1", totp=SENTINEL_TOTP)],
        )
        self.to_refining(batch.batch_id)
        self.staging.submit(
            batch.batch_id,
            [Record(title="淘宝", username="u1")],
            holder="agent",
            summary=f"这条记录带动态口令 {SENTINEL_TOTP}，请核对",
        )
        outer = self.outer_of(batch.batch_id)
        self.assertEqual(outer["notes"], NOTES_REDACTED_TEXT)
        self.assertNotIn(SENTINEL_TOTP, json.dumps(outer, ensure_ascii=False))

    def test_summary_with_otpauth_uri_is_replaced(self):
        """形状检查：`otpauth://` 链接不在任何草稿字段里，只能靠形状抓。"""
        batch = self.create_batch(name="otpauth.txt", text="淘宝 u1 p1\n")
        self.to_refining(batch.batch_id)
        self.staging.submit(
            batch.batch_id,
            [Record(title="淘宝", username="u1")],
            holder="agent",
            summary="扫码用 otpauth://totp/Taobao?secret=ABCDEF 就行",
        )
        outer = self.outer_of(batch.batch_id)
        self.assertEqual(outer["notes"], NOTES_REDACTED_TEXT)
        self.assertTrue(outer["notes_redacted"])

    def test_ordinary_summary_is_kept_verbatim(self):
        """反向对照：正常总结一个字都不许改（误伤等于把功能关掉）。"""
        batch = self.create_batch(name="正常总结.txt", text="淘宝 u1 p1\n")
        self.to_refining(batch.batch_id)
        summary = "从购物清单里整理出 1 条淘宝账号，已跳过重复项。"
        self.staging.submit(
            batch.batch_id,
            [Record(title="淘宝", username="u1", password="p1")],
            holder="agent",
            summary=summary,
        )
        outer = self.outer_of(batch.batch_id)
        self.assertEqual(outer["notes"], summary, "正常总结被误伤了")
        self.assertFalse(outer["notes_redacted"])


# =====================================================================  3. O-3 / O-4
class RecordReprTests(unittest.TestCase):
    def test_repr_never_contains_field_values(self):
        """任何一句 `f"{record}"` 进日志都不该带明文（O-3）。"""
        record = Record(
            title="淘宝",
            username="zhangsan",
            password=SENTINEL_PW,
            totp=SENTINEL_TOTP,
            fields={"取件码": SENTINEL_FIELD},
        )
        text = repr(record)
        for probe in (SENTINEL_PW, SENTINEL_TOTP, SENTINEL_FIELD):
            self.assertNotIn(probe, text, f"repr 泄漏了字段值：{probe[:12]}…")
        self.assertIn("淘宝", text, "标题属于非敏感键，排查问题时需要它")
        self.assertIn("has_password=True", text)


class ConfigurableTimeoutsTests(StagingCacheBase):
    def test_config_editor_lock_seconds_really_applies(self):
        """`[staging] editor_lock_seconds = 3` → 3 秒后允许接管，2.9 秒时不允许。"""
        support.write_config(
            self.home,
            self.home / "data.enc",
            extra="[staging]\neditor_lock_seconds = 3",
        )
        import os

        previous_home = os.environ.get("PV_HOME")
        os.environ["PV_HOME"] = str(self.home)
        self.addCleanup(
            lambda: os.environ.pop("PV_HOME", None)
            if previous_home is None
            else os.environ.__setitem__("PV_HOME", previous_home)
        )
        settings = load_settings()
        self.assertEqual(settings.staging_editor_lock_seconds, 3.0, "配置没被读进来")

        store = StagingStore(settings, lambda: self.vault.dek, clock=self.clock)
        self.assertEqual(store._editor_lock_seconds(), 3.0, "配置值没生效，仍然是模块常量")

        batch = self.create_batch(name="可配编辑锁.txt", text="淘宝 u1 p1\n")
        store.transition(batch.batch_id, "review")
        store.begin_edit(batch.batch_id, holder="窗口A")

        self.clock.advance(seconds=2.9)
        with self.assertRaises(Exception, msg="2.9 秒时锁仍有效，不许接管"):
            store.begin_edit(batch.batch_id, holder="窗口B")

        self.clock.advance(seconds=0.3)
        taken = store.begin_edit(batch.batch_id, holder="窗口B")
        self.assertEqual(taken.editor["holder"], "窗口B")
        self.assertTrue(taken.editor.get("taken_over"), "接管过期锁必须留痕")

    def test_unset_config_falls_back_to_module_constant(self):
        """没配 `editor_lock_seconds` 时必须回落到模块常量（默认 120 秒）。"""
        store = StagingStore(self.settings, lambda: self.vault.dek, clock=self.clock)
        self.assertIsNone(self.settings.staging_editor_lock_seconds, "没配就应该是 None")
        self.assertEqual(store._editor_lock_seconds(), float(staging_module.EDITOR_LOCK_SECONDS))
        self.assertEqual(store._lock_timeout(), float(staging_module.STAGING_LOCK_TIMEOUT))

    def test_config_lock_timeout_seconds_really_applies(self):
        """`[staging] lock_timeout_seconds` 也必须真的进 LockManager 的默认超时。"""
        configured = replace(self.settings, staging_lock_timeout_seconds=1.25)
        store = StagingStore(configured, lambda: self.vault.dek, clock=self.clock)
        self.assertEqual(store._lock_timeout(), 1.25)
        self.assertEqual(store.lock.default_timeout, 1.25, "LockManager 的默认超时没跟着变")


if __name__ == "__main__":
    unittest.main()
