"""锁与记录级 rebase 测试。

并发测试分三层，逐层加码（同进程多线程会互相保底，测不出跨进程丢数据）：

1. 纯锁层：同进程互斥 / 同线程重入 / 超时 / **真多进程抢锁**（子进程写 start/end 标记）
2. 纯写入层：子进程 `pv add` ×50 ∥ 进程内 `commit(add)` ×50 → 100 条、revision +100
3. 冲突层：两边改同一条 → 后到者拿 `Conflict(kind="stale")`，且**盘上一个字节都没变**
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support
from pwdvault.errors import LockTimeout, StaleWrite, VaultError
from pwdvault.locks import CommitResult, Conflict, LockManager, Operation, VaultStore
from pwdvault.models import MASK, Record
from pwdvault.vault import Vault, read_revision

LOCKER = Path(__file__).resolve().parent / "_locker.py"


class LockManagerTests(unittest.TestCase):
    def setUp(self):
        self.home = support.make_home(self)
        self.lock_path = self.home / "data.enc.lock"

    def test_same_process_threads_mutual_exclusion(self):
        manager = LockManager(self.lock_path, default_timeout=10.0)
        state = {"active": 0, "peak": 0}
        guard = threading.Lock()

        def worker() -> None:
            for _ in range(5):
                with manager.hold(purpose="test"):
                    with guard:
                        state["active"] += 1
                        state["peak"] = max(state["peak"], state["active"])
                    time.sleep(0.004)
                    with guard:
                        state["active"] -= 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(state["peak"], 1, "同进程的两个线程同时进入了临界区")

    def test_reentrant_same_thread(self):
        """钉死 R3：staging.commit 里再调 VaultStore.commit 必须放行，不能锁超时。"""
        manager = LockManager(self.lock_path, default_timeout=1.0)
        # 同线程、**不同实例**（模拟 staging 与 VaultStore 各持一把）
        other = LockManager(self.lock_path, default_timeout=1.0)

        with manager.hold(purpose="outer"):
            self.assertTrue(manager.busy(), "持锁时 busy() 应为 True")
            with manager.hold(purpose="inner"):
                with manager.hold(purpose="innermost"):
                    with other.hold(purpose="staging->vault"):
                        pass
            # 内层都退出后，外层仍然有效
            self.assertTrue(manager.busy())

        self.assertFalse(manager.busy(), "全部释放后 busy() 应为 False")

    def test_timeout_raises_lock_timeout(self):
        holder = LockManager(self.lock_path, default_timeout=5.0)
        waiter = LockManager(self.lock_path, default_timeout=5.0, poll_seconds=0.01)
        started = threading.Event()
        release = threading.Event()

        def hold_for_a_while() -> None:
            with holder.hold(purpose="holder"):
                started.set()
                release.wait(3.0)

        thread = threading.Thread(target=hold_for_a_while)
        thread.start()
        try:
            self.assertTrue(started.wait(5.0))
            begin = time.monotonic()
            with self.assertRaises(LockTimeout) as ctx:
                with waiter.hold(timeout=0.2, purpose="commit"):
                    pass
            elapsed = time.monotonic() - begin
            self.assertLess(elapsed, 2.0, "超时必须自管，不能被 LK_LOCK 拖到 9 秒")
            self.assertEqual(ctx.exception.code, "lock_timeout")
        finally:
            release.set()
            thread.join(timeout=5)

    def test_lock_timeout_message_has_no_field_values(self):
        exc = LockTimeout(3.0, "commit")
        self.assertEqual(exc.code, "lock_timeout")
        self.assertIn("稍等", exc.hint or "")

    def test_busy_false_when_free(self):
        manager = LockManager(self.lock_path, default_timeout=1.0)
        self.assertFalse(manager.busy())

    def test_multiprocess_lock_is_real(self):
        """4 个真子进程抢同一把锁，日志里 start/end 不允许嵌套。"""
        log_path = self.home / "markers.txt"
        procs = []
        for tag in ("a", "b", "c", "d"):
            procs.append(
                subprocess.Popen(
                    [support.PYTHON, str(LOCKER), str(self.lock_path), tag, "300", str(log_path)],
                    cwd=str(support.PROJECT_ROOT),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        for proc in procs:
            _, err = proc.communicate(timeout=90)
            self.assertEqual(proc.returncode, 0, f"locker 失败：{err}")

        lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 8, f"标记数量不对：{lines}")

        depth = 0
        for line in lines:
            if line.startswith("start"):
                depth += 1
                self.assertEqual(depth, 1, f"检测到锁重叠：{lines}")
            else:
                depth -= 1
                self.assertEqual(depth, 0, f"检测到锁重叠：{lines}")
        self.assertEqual(depth, 0)
        self.assertEqual(sum(1 for line in lines if line.startswith("start")), 4)


class VaultStoreCommitTests(unittest.TestCase):
    def setUp(self):
        self.home = support.make_home(self)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)

    def _reopen(self) -> Vault:
        return Vault.open(self.settings, password=support.PASSWORD)

    def test_add_commit_bumps_revision(self):
        result = self.store.commit([Operation.add(Record(title="淘宝"))])
        self.assertIsInstance(result, CommitResult)
        self.assertEqual(result.added, 1)
        self.assertEqual(result.revision, 1)
        self.assertEqual(len(self._reopen().records), 1)

    def test_empty_commit_does_not_bump(self):
        before = read_revision(self.settings.vault_path)
        result = self.store.commit([])
        self.assertEqual(result.revision, before)
        self.assertEqual(result.added + result.updated + result.deleted, 0)
        self.assertEqual(read_revision(self.settings.vault_path), before)

    def test_add_id_conflict_skip_is_idempotent(self):
        record = Record(title="淘宝")
        self.store.commit([Operation.add(record)])
        replay = self.store.commit([Operation.add(record, on_id_conflict="skip")])
        self.assertEqual(replay.added, 0)
        self.assertEqual(len(self._reopen().records), 1)

    def test_add_id_conflict_reassigns(self):
        record = Record(title="淘宝")
        self.store.commit([Operation.add(record)])
        clone = Record(title="淘宝副本")
        clone.id = record.id
        result = self.store.commit([Operation.add(clone)])
        self.assertEqual(result.added, 1)
        self.assertNotEqual(clone.id, record.id)
        self.assertEqual(len(self._reopen().records), 2)

    def test_rebase_no_overlap_both_applied(self):
        mine = Record(title="我的记录")
        self.store.commit([Operation.add(mine)])

        # 模拟另一个进程写了一条
        other = self._reopen()
        other.records.append(Record(title="别人的记录"))
        other.save()

        result = self.store.commit([Operation.update(mine.id, {"notes": "我改的备注"})])
        self.assertTrue(result.reloaded, "盘上 revision 变了，必须发生 rebase")
        fresh = self._reopen()
        self.assertEqual(len(fresh.records), 2)
        self.assertEqual(fresh.find_by_id(mine.id).notes, "我改的备注")
        self.assertIn("别人的记录", [r.title for r in fresh.records])

    def test_conflict_stale_does_not_touch_disk(self):
        record = Record(title="淘宝", username="zhangsan", password="old")
        record.updated = "2019-01-01T00:00:00+00:00"
        self.store.commit([Operation.add(record)])
        my_base = record.updated

        other = self._reopen()
        target = other.find_by_id(record.id)
        target.password = "changed-by-other"
        target.updated = "2020-02-02T00:00:00+00:00"
        other.save()

        before_bytes = self.settings.vault_path.read_bytes()
        result = self.store.commit(
            [Operation.update(record.id, {"password": "mine"}, expected_updated=my_base)]
        )
        self.assertEqual(len(result.conflicts), 1)
        conflict = result.conflicts[0]
        self.assertEqual(conflict.kind, "stale")
        self.assertEqual(conflict.record_id, record.id)
        # 冲突结构里对方的数据必须已脱敏
        self.assertEqual(conflict.theirs["password"], MASK)
        self.assertEqual(conflict.mine["password"], MASK)
        # **反向断言更重要**：盘上一个字节都没变
        self.assertEqual(self.settings.vault_path.read_bytes(), before_bytes)
        self.assertEqual(self._reopen().find_by_id(record.id).password, "changed-by-other")

    def test_conflict_deleted(self):
        record = Record(title="要被删掉的")
        self.store.commit([Operation.add(record)])

        other = self._reopen()
        other.records = [r for r in other.records if r.id != record.id]
        other.save()

        result = self.store.commit([Operation.update(record.id, {"notes": "x"})])
        self.assertEqual(result.conflicts[0].kind, "deleted")
        self.assertIsNone(result.conflicts[0].theirs)

    def test_delete_missing_is_idempotent(self):
        result = self.store.commit([Operation.delete("不存在的 id")])
        self.assertEqual(result.conflicts, [])
        self.assertEqual(result.deleted, 0)

    def test_expected_revision_guard(self):
        self.store.commit([Operation.add(Record(title="A"))])
        disk = read_revision(self.settings.vault_path)
        with self.assertRaises(StaleWrite):
            self.store.commit(
                [Operation.update("whatever", {"notes": "x"})],
                expected_revision=disk + 5,
            )

    def test_reload_policy_never_raises(self):
        self.store.commit([Operation.add(Record(title="A"))])
        other = self._reopen()
        other.records.append(Record(title="B"))
        other.save()
        with self.assertRaises(StaleWrite):
            self.store.commit([Operation.add(Record(title="C"))], reload_policy="never")

    def test_mutate_header_keeps_records(self):
        self.store.commit([Operation.add(Record(title="A"))])

        def rename(header: dict) -> None:
            header["label"] = "新名字"

        revision = self.store.mutate_header(rename)
        self.assertEqual(revision, read_revision(self.settings.vault_path))
        fresh = self._reopen()
        self.assertEqual(fresh.header.get("label"), "新名字")
        self.assertEqual(len(fresh.records), 1)

    def test_on_revision_callback(self):
        seen: list[tuple[int, int]] = []
        store = VaultStore(self.settings, self._reopen(), on_revision=lambda a, b: seen.append((a, b)))
        store.commit([Operation.add(Record(title="A"))])
        self.assertEqual(len(seen), 1)
        self.assertLess(seen[0][0], seen[0][1])

    def test_callback_failure_does_not_break_commit(self):
        def boom(old: int, new: int) -> None:
            raise RuntimeError("回调炸了")

        store = VaultStore(self.settings, self._reopen(), on_revision=boom)
        result = store.commit([Operation.add(Record(title="A"))])
        self.assertEqual(result.added, 1)


class CrossProcessWriteTests(unittest.TestCase):
    """子进程 `pv add` ×50 ∥ 进程内 commit(add) ×50。"""

    def test_fifty_plus_fifty_no_loss(self):
        home = support.make_home(self)
        fixture = support.make_vault(home, snapshot_keep=3)
        settings = fixture.settings
        support.write_config(home, settings.vault_path)

        store = VaultStore(settings, fixture.vault)
        env = {"PV_MASTER_PASSWORD": support.PASSWORD}

        procs = [
            support.popen_py(
                ["add", "--json", "-t", f"子进程{i}", "-p", f"pw-{i}"],
                home=home,
                env=env,
            )
            for i in range(50)
        ]

        failures: list[BaseException] = []

        def in_process() -> None:
            try:
                for i in range(50):
                    store.commit([Operation.add(Record(title=f"主进程{i}", password=f"pw-{i}"))])
            except BaseException as exc:  # noqa: BLE001
                failures.append(exc)

        worker = threading.Thread(target=in_process)
        worker.start()

        for index, proc in enumerate(procs):
            out, err = proc.communicate(timeout=240)
            self.assertEqual(proc.returncode, 0, f"第 {index} 个子进程失败：{err[-800:]}")

        worker.join(timeout=240)
        if failures:
            raise failures[0]

        fresh = Vault.open(settings, password=support.PASSWORD)
        titles = {record.title for record in fresh.records}
        self.assertEqual(len(fresh.records), 100, f"丢数据了：只拿到 {len(fresh.records)} 条")
        self.assertEqual(len({record.id for record in fresh.records}), 100, "出现重复 id")
        self.assertEqual(fresh.revision, 100, f"revision 应为 100，实际 {fresh.revision}")
        self.assertEqual(len(titles), 100)


class ConflictShapeTests(unittest.TestCase):
    def test_conflict_to_dict_is_json_safe(self):
        conflict = Conflict(record_id="abc", kind="stale", mine={"password": MASK}, theirs=None)
        payload = conflict.to_dict()
        self.assertEqual(payload["record_id"], "abc")
        self.assertEqual(payload["kind"], "stale")
        self.assertIsNone(payload["theirs"])


if __name__ == "__main__":
    unittest.main()
