"""第二轮：**修复引入的新代码**有没有修出新问题。

为什么工程师自己的测试打不到这三处：

1. `_digest_index()`（H1）是 Q-05 的性能补丁 —— 工程师的 inbox 用例每次都是
   「新建一个 StagingStore / 新建一个 Watcher 再扫」，实例级的 `_outer_index`
   缓存与 `_seen` 集合永远是空的，于是「缓存命中导致该建的批次没建」这类
   跨轮次的状态错误一次也跑不出来。本文件让**同一个** `StagingStore` 与
   **同一个** watcher 连续工作多轮。
2. `_stale_memory`（H2）是 Q-02 的补丁。工程师只测了「恢复成功」那一半，
   `_restore_from_disk()` **失败**那一半（盘暂时读不了）没有任何用例 ——
   而「置了脏标记却清不掉」正是这类标志位最典型的死法：每次写都重读整个库，
   或者脏视图被一直当成真数据喂给读接口。
3. `copy_field(seconds=0)`（H3）是 O-1 的行为修正。`test_service.py` 把
   `copy_with_autoclear` 整个换成了假函数，于是「定时器到底装没装、到点到底
   清不清」从来没被真正观察过。本文件只替换掉剪贴板读写两个最底层的原语，
   让 `copy_with_autoclear` / `threading.Timer` 走真实代码路径。

另外钉住一处「看起来可配置、实际配置不进去」的幽灵字段（Q-09）。
"""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _qa_runner as qa
import _support as support

from pwdvault import clipboard, service, staging as staging_module
from pwdvault.config import load_settings
from pwdvault.errors import CorruptVault, StagingBusy
from pwdvault.inbox import InboxWatcher
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record
from pwdvault.staging import StagingStore

PASSWORD = support.PASSWORD
LEASE_SECONDS = 2


class Round2Base(unittest.TestCase):
    """一个共享的 home / vault / StagingStore，缓存与 `_seen` 都跨用例内部轮次复用。"""

    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(
            self.home,
            self.home / "data.enc",
            lock_timeout=10.0,
            lock_poll=0.01,
            staging_extra=f"lease_seconds = {LEASE_SECONDS}\nlease_max_seconds = 600",
        )
        fixture = support.make_vault(self.home, snapshot_keep=0)
        previous_home = os.environ.get("PV_HOME")
        os.environ["PV_HOME"] = str(self.home)
        self.addCleanup(
            lambda: os.environ.pop("PV_HOME", None)
            if previous_home is None
            else os.environ.__setitem__("PV_HOME", previous_home)
        )
        self.settings = load_settings()
        self.assertEqual(str(self.settings.vault_path), str(self.home / "data.enc"))
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        # **同一个** staging 实例贯穿全用例：`_outer_index` 缓存才留得住
        self.staging = StagingStore(self.settings, lambda: self.vault.dek)
        self.watcher = self.new_watcher()

    def new_watcher(self) -> InboxWatcher:
        """新 watcher、**老 StagingStore** —— 模拟「监听线程重启，进程和缓存还活着」。"""
        return InboxWatcher(self.settings, self.staging, interval=2.0)

    def batch_files(self) -> list[str]:
        return sorted(path.name for path in self.settings.staging_dir.glob("sb_*.enc"))

    def drop(self, name: str, content: str) -> Path:
        path = self.inbox / name
        path.write_text(content, encoding="utf-8")
        return path

    def scan(self, watcher: InboxWatcher | None = None) -> list[str]:
        return list((watcher or self.watcher).scan_once())

    def make_batch(self, name: str, content: str | None = None):
        body = content if content is not None else f"占位-{name}"
        path = self.drop(name, body)
        return self.staging.create_from_file(
            path=path,
            text=body,
            drafts=[Record(title=f"记录-{name}", password="p-1")],
        )


# =====================================================================  H1
class DigestIndexReimportTests(Round2Base):
    """H1：`_digest_index()` 的文件名缓存会不会让「同一份文件永久无法重新导入」。"""

    def test_cache_key_is_batch_file_and_evicts_deleted_files(self) -> None:
        """缓存的 key 是**批次文件名**（`sb_xxx.enc`），不是收件箱文件名。

        这决定了缓存不可能「记住一个已删除批次」：批次文件不在了，key 也就被剔除。
        直接注入一条指向不存在文件的缓存项来证明这一点。
        """
        batch = self.make_batch("cache.txt")
        self.scan()
        index = self.staging._digest_index()
        self.assertEqual(index.get(self._digest_of(batch)), batch.batch_id)

        # 注入一条幽灵缓存：文件名不存在，摘要随意
        self.staging._outer_index["sb_deadbeef0000.enc"] = ("f" * 64, "sb_deadbeef0000")
        self.staging._digest_index()
        self.assertNotIn(
            "sb_deadbeef0000.enc",
            self.staging._outer_index,
            "指向不存在批次文件的缓存项必须被剔除，否则删除过的摘要会永久挡住重导",
        )
        self.assertNotIn("f" * 64, self.staging._digest_index())

    def test_cached_digest_matches_source_sha256(self) -> None:
        """缓存里的摘要必须等于源文件的真实 sha256（不是被谁改写的占位值）。"""
        import hashlib

        path = self.drop("consistency.txt", "缓存一致性\n")
        # 注意：必须按**盘上的字节**算（Windows 的 write_text 会把 \n 换成 \r\n）
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        batch = self.staging.create_from_file(
            path=path, text="缓存一致性\n", drafts=[Record(title="记录-consistency", password="p")]
        )
        self.assertEqual(batch.source.get("sha256"), digest)
        self.assertEqual(self.staging.batches_by_hash().get(digest), batch.batch_id)
        self.assertEqual(
            self.staging._digest_index().get(digest),
            batch.batch_id,
            "第二次调用（走缓存）拿到的摘要/批次必须与第一次一致",
        )

    def test_redrop_after_external_delete_creates_new_batch(self) -> None:
        """批次文件被外部删掉（清理 / 用户手删）后，同一份文件必须能重新导入。

        这是缓存失效最该覆盖的一条：文件没了 → 索引剔除 → 不再判重。
        """
        self.drop("deleted.txt", "外部删除后重导\n")
        created = self.scan()
        self.assertEqual(len(created), 1, "第一次丢进去必须建一批")
        batch_id = created[0]
        self.assertEqual(self.scan(), [], "同一内容不该建第二批")

        (self.settings.staging_dir / f"{batch_id}.enc").unlink()
        self.assertNotIn(batch_id, self.staging.batches_by_hash().values())

        # 新 watcher（模拟监听线程重启）但**同一个 StagingStore / 同一个缓存**
        fresh = self.new_watcher()
        self.drop("deleted.txt", "外部删除后重导\n")
        created = self.scan(fresh)
        self.assertEqual(
            len(created),
            1,
            "批次文件已被删除，缓存必须剔除该摘要，同一份文件必须能重新建批",
        )

    def test_redrop_after_discard_is_blocked_by_tombstone(self) -> None:
        """丢弃 → 重导：**按设计**不建批，但必须留下墓碑（可解释）。

        这条是 H1 的对照组：`discard()` 走了墓碑，所以「不建批」是有据可查的。
        """
        batch = self.make_batch("discard.txt", "丢弃后重导\n")
        self.scan()
        self.staging.discard(batch.batch_id)
        self.assertIn(
            self._digest_of(batch),
            self.staging.seen_hashes(),
            "丢弃必须写墓碑，否则「不再导入」这个决定就没有任何记录",
        )
        self.assertEqual(self.scan(self.new_watcher()), [], "墓碑应阻止重导")

    def test_redrop_after_rollback_is_silently_ignored(self) -> None:
        """回滚 → 重导：被 `batches_by_hash()` 挡住，**且没有任何墓碑或状态说明原因**。

        Q-08（低-中）：`discard()` 会写墓碑，`rollback()` 不写；但回滚后批次文件
        仍在盘上，`batches_by_hash()` 依旧返回「这个 sha256 有批次」，于是
        收件箱里再出现同一份文件时静默跳过 —— 既不建批、也不报错、也不落墓碑。
        用户视角：「我撤销了入库，重新丢一次文件，什么都没发生」。
        只有等 `purge_expired_batches()` 在 `staging_ttl_days`（默认 30 天）之后
        删掉批次文件，这个摘要才重新可用。
        """
        batch = self.make_batch("rollback.txt", "回滚后重导\n")
        self.scan()
        self.staging.transition(batch.batch_id, "review")
        result = self.staging.commit(batch.batch_id, store=self.store)
        self.assertEqual(result["status"], "committed")
        self.staging.rollback(batch.batch_id, store=self.store)
        self.assertEqual(self.staging.get(batch.batch_id).status, "rolled_back")

        # 回滚**不写**墓碑
        self.assertNotIn(
            self._digest_of(batch),
            self.staging.seen_hashes(),
            "回滚不写墓碑（这正是它和 discard 的区别，也是缺陷成立的前提）",
        )
        # 但批次文件还在 → 摘要仍被判重
        self.assertIn(self._digest_of(batch), self.staging.batches_by_hash())

        self.drop("rollback.txt", "回滚后重导\n")
        created = self.scan(self.new_watcher())
        self.assertEqual(
            created,
            [],
            "现状（Q-08）：回滚后重导同一份文件不会建批；如果这里变成 1，说明已修好",
        )

    def test_direct_create_after_rollback_returns_the_rolled_back_batch(self) -> None:
        """Q-08 的根因面：判重**不看批次状态**，所以 `rolled_back` 批次会被当成「已存在」。

        与 inbox 路径的区别：inbox 至少还会先查墓碑，直接调 `create_from_file`
        （手工上传 / Web 重新上传同一份文件）连墓碑都不查，直接返回一个
        `rolled_back` 的旧批次并标记 `deduped=True`。

        同一个根因在 `discarded` 上的表现另有一条用例（`tests/test_staging_dedupe.py`
        的 expectedFailure，由另一位同学钉住）—— 两边结论一致：`_digest_index()`
        只过滤「文件不存在」，不过滤 `status` 与墓碑。
        """
        batch = self.make_batch("直接重传.txt", "回滚后直接重传\n")
        self.scan()
        self.staging.transition(batch.batch_id, "review")
        self.staging.commit(batch.batch_id, store=self.store)
        self.staging.rollback(batch.batch_id, store=self.store)

        path = self.drop("直接重传.txt", "回滚后直接重传\n")
        again = self.staging.create_from_file(
            path=path,
            text="回滚后直接重传\n",
            drafts=[Record(title="记录-直接重传", password="p-1")],
        )
        self.assertTrue(
            again.deduped,
            "现状（Q-08）：直接调用时仍判重命中；变成 False 说明已修好",
        )
        self.assertEqual(again.batch_id, batch.batch_id)
        self.assertEqual(again.status, "rolled_back", "返回的是一个已经撤销的批次")

    def test_redrop_after_commit_is_not_reimported(self) -> None:
        """入库 → 重导：不建批（允许），但同样没有任何可解释的信号。"""
        batch = self.make_batch("committed.txt", "入库后重导\n")
        self.scan()
        self.staging.transition(batch.batch_id, "review")
        self.staging.commit(batch.batch_id, store=self.store)
        self.assertFalse(
            (self.inbox / "committed.txt").exists(),
            "入库后源文件应被移进 processed/（批量导入不该在收件箱里越堆越多）",
        )
        self.drop("committed.txt", "入库后重导\n")
        self.assertEqual(self.scan(self.new_watcher()), [])

    def test_scan_reports_nothing_about_skipped_duplicates(self) -> None:
        """`scan_once()` 的返回值只包含**新建**批次，被判重跳过时没有任何输出。

        这是 H1 真正成立的那一半：不是缓存坏了，而是「跳过」这件事对调用方不可见。
        钉住现状，避免将来把「静默」当成「正常」。
        """
        batch = self.make_batch("silent.txt", "静默跳过\n")
        self.scan()
        self.staging.discard(batch.batch_id)
        self.drop("silent.txt", "静默跳过\n")
        fresh = self.new_watcher()
        self.assertEqual(self.scan(fresh), [], "被判重时应返回空列表")
        status = fresh.status()
        self.assertEqual(
            int(status.get("pending") or 0),
            0,
            "被判重跳过的文件既不算新建也不算 pending —— 用户无从得知它被忽略",
        )

    # ------------------------------------------------------------ 工具
    def _digest_of(self, batch) -> str:
        """批次记录的源文件摘要（外层明文 JSON 里就有，不必重新读文件）。"""
        return str(batch.source.get("sha256") or "")


# =====================================================================  H2
class StaleMemoryFlagTests(Round2Base):
    """H2：`_stale_memory` 在「恢复失败」时会不会永远停在 True。"""

    def _add_record(self) -> Record:
        record = Record(title="原始记录", notes="干净")
        self.store.commit([Operation.add(record)])
        return record

    def test_flag_clears_after_successful_restore(self) -> None:
        record = self._add_record()
        with mock.patch.object(Record, "apply_changes", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(record.id, {"notes": "脏"})])
        self.assertFalse(self.store._stale_memory, "恢复成功后标记必须清掉")

    def test_flag_survives_failed_restore_and_refresh_keeps_retrying(self) -> None:
        """盘读不出来时标记留在 True，`refresh()` 每次都会再试（不清标记、不静默）。"""
        record = self._add_record()
        with mock.patch.object(Record, "apply_changes", side_effect=RuntimeError("boom")), \
                mock.patch.object(VaultStore, "_reload", side_effect=CorruptVault("盘坏了")):
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(record.id, {"notes": "脏"})])
            self.assertTrue(self.store._stale_memory, "恢复失败必须留下脏标记")
            for _ in range(3):
                self.assertFalse(self.store.refresh(), "盘仍然坏着，refresh 只能返回 False")
            self.assertTrue(self.store._stale_memory, "重读一直失败时不能假装已经干净")

    def test_flag_clears_and_refresh_stops_reloading_after_recovery(self) -> None:
        """盘恢复之后：标记清掉，且 `refresh()` 回到「零次重读」。"""
        record = self._add_record()
        with mock.patch.object(Record, "apply_changes", side_effect=RuntimeError("boom")), \
                mock.patch.object(VaultStore, "_reload", side_effect=CorruptVault("盘坏了")):
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(record.id, {"notes": "脏"})])
        self.assertTrue(self.store._stale_memory)

        calls = {"n": 0}
        original = VaultStore._reload

        def counting(instance):
            calls["n"] += 1
            return original(instance)

        with mock.patch.object(VaultStore, "_reload", counting):
            self.store.refresh()
            self.assertFalse(self.store._stale_memory, "盘恢复后第一次 refresh 就该清标记")
            first_round = calls["n"]
            for _ in range(5):
                self.store.refresh()
            self.assertEqual(
                calls["n"],
                first_round,
                "标记清掉之后 refresh 不该再重读整个库（否则每次 SSE 轮询都全量解密）",
            )

    def test_write_still_works_after_stale_and_recovery(self) -> None:
        record = self._add_record()
        with mock.patch.object(Record, "apply_changes", side_effect=RuntimeError("boom")), \
                mock.patch.object(VaultStore, "_reload", side_effect=CorruptVault("盘坏了")):
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(record.id, {"notes": "脏"})])
        self.assertTrue(self.store._stale_memory)

        result = self.store.commit([Operation.update(record.id, {"notes": "新备注"})])
        self.assertEqual(result.updated, 1, "标记位不该让后续写永久失败")
        self.assertFalse(self.store._stale_memory)
        fresh = self.store._reload()
        self.assertEqual(fresh.find_by_id(record.id).notes, "新备注")

    def test_failed_write_dirt_never_reaches_disk(self) -> None:
        """Q-02 的正向回归：失败那次的改动一个字节都不能落盘。"""
        record = self._add_record()
        with mock.patch.object(Record, "apply_changes", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(record.id, {"notes": "DIRT"})])
        self.store.commit([Operation.add(Record(title="无关记录"))])
        fresh = self.store._reload()
        self.assertEqual(fresh.find_by_id(record.id).notes, "干净")
        self.assertNotIn("DIRT", json.dumps([r.to_dict() for r in fresh.records], ensure_ascii=False))

    def test_mutate_exception_path_also_restores(self) -> None:
        """`mutate(fn)` 里 `fn` 抛异常：与 `commit` 同一套恢复逻辑。"""
        record = self._add_record()

        def boom(fresh):
            fresh.find_by_id(record.id).notes = "DIRT-MUTATE"
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            self.store.mutate(boom)
        self.assertFalse(self.store._stale_memory, "恢复成功后标记必须清掉")
        self.store.commit([Operation.add(Record(title="无关记录2"))])
        fresh = self.store._reload()
        self.assertEqual(fresh.find_by_id(record.id).notes, "干净")

    def test_mutate_header_exception_path_also_restores(self) -> None:
        """`mutate_header(fn)` 里 `fn` 抛异常：同上。"""
        record = self._add_record()

        def boom(header):
            header["marker"] = "DIRT-HEADER"
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            self.store.mutate_header(boom)
        self.assertFalse(self.store._stale_memory)
        fresh = self.store._reload()
        self.assertNotIn("marker", fresh.header)

    def test_mutate_returning_false_after_inplace_change_must_not_leak(self) -> None:
        """**回归测试 Q-10**：`mutate(fn)` 的 `fn` 就地改了数据、却返回 `False`（「没改动」）
        时，脏改动必须被丢掉，不能被**下一次无关写入**带到盘上。

        这是 Q-02 的同一条根因，原实现漏了 `changed == False` 这个分支：

        ```python
        if not changed:
            finished = True          # ← 没有 _restore_from_disk()
            return CommitResult(...)
        ```

        `fn` 返回 False 意味着 `vault.save()` 没跑，盘上 revision 不变；下一次
        `commit` 看到 `disk == self._vault.revision`，判定「无需 reload」，
        把上一轮留下的脏数据一起写进去。

        修法（已落地）：`if not changed:` 分支里无条件按盘恢复一次。
        当前**没有**生产调用者会这么写（`cli._apply` / `_apply_passwd` 都硬返回 True），
        所以这是潜伏缺陷而不是在用缺陷。
        """
        record = self._add_record()

        def sneaky(fresh):
            fresh.find_by_id(record.id).notes = "DIRT-FROM-CHANGED-FALSE"
            return False

        self.store.mutate(sneaky)
        self.store.commit([Operation.add(Record(title="之后的一次无关写入"))])
        fresh = self.store._reload()
        self.assertEqual(
            fresh.find_by_id(record.id).notes,
            "干净",
            "Q-10：改写被 mutate 判定为「无改动」的那次内存脏数据，不该由后续写入落盘",
        )


# =====================================================================  H3
class _MemoryClipboard:
    """把剪贴板换成内存里一格字符串；**不**碰 `copy_with_autoclear` / 定时器。"""

    def __init__(self, case: unittest.TestCase) -> None:
        self.value = ""
        self._orig_copy = clipboard.copy_text
        self._orig_read = clipboard.read_text
        clipboard.copy_text = self.copy_text
        clipboard.read_text = self.read_text
        case.addCleanup(self._restore)

    def _restore(self) -> None:
        clipboard.copy_text = self._orig_copy
        clipboard.read_text = self._orig_read

    def copy_text(self, text: str) -> None:
        self.value = text

    def read_text(self) -> str:
        return self.value


class CopyFieldAutoClearTests(unittest.TestCase):
    """H3：`seconds=0` 到底清不清剪贴板（O-1 的行为反转）。"""

    def setUp(self) -> None:
        self.record = Record(title="淘宝", username="zhangsan", password="pw-机密-123")
        self.board = _MemoryClipboard(self)

    def test_zero_seconds_copies_and_never_clears(self) -> None:
        receipt = service.copy_field(self.record, field="password", seconds=0, spawn=False)
        self.assertTrue(receipt["copied"])
        self.assertFalse(receipt["auto_clear"], "0 秒不该报「已装自动清空」")
        self.assertEqual(receipt["auto_clear_in"], 0)
        self.assertEqual(receipt["auto_clear_mode"], "none")
        self.assertEqual(self.board.value, "pw-机密-123")

        # 0.2s / 1s / 2s 三个时点内容都必须还在（旧实现 Timer(0) 会立刻清空）
        for delay in (0.2, 0.8, 1.0):
            time.sleep(delay)
            self.assertEqual(
                self.board.value,
                "pw-机密-123",
                f"过了 {delay}s 剪贴板被清空了：seconds=0 不该装定时器",
            )

    def test_negative_seconds_behaves_like_zero(self) -> None:
        receipt = service.copy_field(self.record, field="password", seconds=-5, spawn=False)
        self.assertFalse(receipt["auto_clear"])
        time.sleep(0.3)
        self.assertEqual(self.board.value, "pw-机密-123")

    def test_one_second_really_clears(self) -> None:
        """反向对照：真装了定时器的那一档必须到点清空，否则上面的用例就是假绿。"""
        receipt = service.copy_field(self.record, field="password", seconds=1, spawn=False)
        self.assertTrue(receipt["auto_clear"], "秒数 > 0 时必须如实报告已装定时器")
        self.assertEqual(receipt["auto_clear_in"], 1)
        self.assertEqual(receipt["auto_clear_mode"], "process")
        self.assertEqual(self.board.value, "pw-机密-123")

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and self.board.value:
            time.sleep(0.05)
        self.assertEqual(self.board.value, "", "1.5s 内定时器必须把剪贴板清空")

    def test_autoclear_refuses_to_wipe_users_new_content(self) -> None:
        """到点前用户又复制了别的东西 → 摘要不匹配，绝不清空。"""
        service.copy_field(self.record, field="password", seconds=1, spawn=False)
        self.board.copy_text("用户后来复制的东西")
        time.sleep(1.8)
        self.assertEqual(self.board.value, "用户后来复制的东西")

    def test_receipt_has_no_plaintext(self) -> None:
        receipt = service.copy_field(self.record, field="password", seconds=0, spawn=False)
        dumped = json.dumps(receipt, ensure_ascii=False)
        self.assertNotIn("pw-机密-123", dumped)


# =====================================================================  Q-09
class StagingConfigOverrideTests(Round2Base):
    """Q-09：`[staging] editor_lock_seconds` / `lock_timeout_seconds` 是否真的能覆盖常量。

    发现时（本文件写下第一版的那一刻）`staging.py` 的 `_lock_timeout()` /
    `_editor_lock_seconds()` 读的是 `settings.staging_lock_timeout_seconds` /
    `settings.staging_editor_lock_seconds`，而 `Settings` 里根本没有这两个字段 ——
    `getattr(..., None)` 永远拿到 None，注释里承诺的「配置优先」是死的。

    跑这一轮的时候 `config.py` 已经补上了这两个字段（`_as_optional_float`），
    所以本用例断言的是**修好之后**的行为：配置真的生效、并且真的改变了运行时判定。
    """

    def test_config_overrides_editor_lock_and_lock_timeout(self) -> None:
        qa.write_config(
            self.home,
            self.home / "data.enc",
            lock_timeout=10.0,
            lock_poll=0.01,
            staging_extra=(
                f"lease_seconds = {LEASE_SECONDS}\n"
                "editor_lock_seconds = 1\n"
                "lock_timeout_seconds = 1\n"
            ),
        )
        settings = load_settings()
        self.assertEqual(settings.staging_editor_lock_seconds, 1.0, "配置字段必须被读进来")
        self.assertEqual(settings.staging_lock_timeout_seconds, 1.0)
        store = StagingStore(settings, lambda: self.vault.dek)
        self.assertEqual(store._editor_lock_seconds(), 1.0, "编辑锁必须用配置值")
        self.assertNotEqual(
            store._editor_lock_seconds(),
            float(staging_module.EDITOR_LOCK_SECONDS),
            "配置值与模块常量恰好相等的话，这个用例证明不了任何事",
        )
        self.assertEqual(store._lock_timeout(), 1.0, "staging 锁等待上限必须用配置值")

    def test_zero_or_garbage_falls_back_to_constant(self) -> None:
        qa.write_config(
            self.home,
            self.home / "data.enc",
            lock_timeout=10.0,
            lock_poll=0.01,
            staging_extra=(
                f"lease_seconds = {LEASE_SECONDS}\n"
                'editor_lock_seconds = ""\n'
                'lock_timeout_seconds = "不是数字"\n'
            ),
        )
        settings = load_settings()
        store = StagingStore(settings, lambda: self.vault.dek)
        self.assertEqual(
            store._editor_lock_seconds(),
            float(staging_module.EDITOR_LOCK_SECONDS),
            "空值必须退回模块常量，而不是 0（0 会让编辑锁立刻失效，两个窗口直接互相覆盖）",
        )
        self.assertEqual(store._lock_timeout(), float(staging_module.STAGING_LOCK_TIMEOUT))

    def test_configured_one_second_lock_changes_real_behaviour(self) -> None:
        """配置成 1 秒后，真实墙钟上 0.2 秒仍然锁着、1.2 秒可以接管。"""
        qa.write_config(
            self.home,
            self.home / "data.enc",
            lock_timeout=10.0,
            lock_poll=0.01,
            staging_extra=f"lease_seconds = {LEASE_SECONDS}\neditor_lock_seconds = 1\n",
        )
        settings = load_settings()
        staging = StagingStore(settings, lambda: self.vault.dek)
        path = self.drop("配置锁.txt", "配置锁正文\n")
        batch = staging.create_from_file(
            path=path, text="配置锁正文\n", drafts=[Record(title="配置锁记录", password="p")]
        )
        staging.transition(batch.batch_id, "review")
        staging.begin_edit(batch.batch_id, holder="win-A")
        time.sleep(0.2)
        with self.assertRaises(StagingBusy, msg="配置的 1 秒锁在 0.2 秒时仍然有效"):
            staging.begin_edit(batch.batch_id, holder="win-B")
        time.sleep(1.1)
        taken = staging.begin_edit(batch.batch_id, holder="win-B")
        self.assertTrue((taken.editor or {}).get("taken_over"), "过期接管要留痕")
