"""锁的**异常路径**与 fd 泄漏 —— 工程师的 `test_locks.py` 测不到的地方。

`test_locks.py` 覆盖的是「正常路径下锁是对的」：同进程互斥、同线程重入、超时、
4 个真进程抢锁。它没有一条用例在**临界区里抛异常**，而 `locks.py` 的正确性恰恰
依赖「`depth` 账本与 fd 生命周期严格配对」——任何 early-return / 异常路径漏掉一次
释放，锁文件就会被长期占用，用户看到的现象是「重启后所有写操作卡 3 秒然后超时」。

本文件逐个打这些路径，并且**每个用例的收尾动作都相同**：在异常发生之后，
必须能用「另一个线程」+「另一个进程」两条独立通道把锁重新拿到。
只用同线程再拿一次是假绿 —— `threading.RLock` 对同线程是可重入的，
即使上面漏了 release，同线程也会「拿到」，测不出泄漏。
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _qa_runner as qa
import _support as support

from pwdvault import locks as locks_module
from pwdvault.errors import LockTimeout
from pwdvault.locks import LockManager, Operation, VaultStore
from pwdvault.models import Record
from pwdvault.vault import Vault, read_revision

RUNNER = Path(__file__).resolve().parent / "_qa_runner.py"

PASSWORD = support.PASSWORD


# ---------------------------------------------------------------- 探针
def thread_book_depth() -> int:
    """当前线程在所有锁上的重入深度总和（正常必须是 0）。"""
    book = getattr(locks_module._THREAD_STATE, "book", None) or {}
    return sum(entry.depth for entry in book.values())


def handle_count() -> int:
    """当前进程的内核句柄数。fd 泄漏 → 这个数字单调上涨。"""
    if sys.platform != "win32":  # pragma: no cover - 本机是 win32
        try:
            return len(os.listdir("/proc/self/fd"))
        except OSError:
            return -1
    kernel32 = ctypes.windll.kernel32
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessHandleCount.restype = ctypes.c_int
    count = ctypes.c_ulong(0)
    handle = ctypes.c_void_p(kernel32.GetCurrentProcess())
    if not kernel32.GetProcessHandleCount(handle, ctypes.byref(count)):
        return -1
    return int(count.value)


class LockProbeMixin:
    """两条独立探针：别的线程（测 RLock 泄漏）、别的进程（测 fd / 文件锁泄漏）。"""

    def probe_from_thread(self, lock_path: Path, *, timeout: float = 0.6) -> tuple[bool, float]:
        manager = LockManager(Path(lock_path), default_timeout=timeout, poll_seconds=0.005)
        box: dict = {"ok": False, "elapsed": -1.0}

        def run() -> None:
            started = time.monotonic()
            try:
                with manager.hold(timeout=timeout, purpose="probe-thread"):
                    box["ok"] = True
            except LockTimeout:
                box["ok"] = False
            box["elapsed"] = time.monotonic() - started

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout + 5.0)
        return bool(box["ok"]), float(box["elapsed"])

    def probe_from_process(self, home: Path, *, timeout: float = 1.0, purpose: str = "data") -> dict:
        args = [support.PYTHON, str(RUNNER), "probe-lock", str(timeout)]
        if purpose != "data":
            args.append(purpose)
        proc = subprocess.run(
            args,
            cwd=str(support.PROJECT_ROOT),
            env=qa.child_env(home, PASSWORD),
            capture_output=True,
            text=True,
            timeout=120,
        )
        line = (proc.stdout or "").strip().splitlines()
        payload = json.loads(line[-1]) if line else {"ok": False, "error": proc.stderr[-400:]}
        payload["returncode"] = proc.returncode
        return payload

    def assert_lock_free(self, home: Path, lock_path: Path, *, purpose: str = "data") -> None:
        """异常之后，锁必须能被「另一个线程」和「另一个进程」分别拿到。"""
        self.assertEqual(thread_book_depth(), 0, "重入深度账本没有归零（depth 泄漏）")
        ok_thread, elapsed = self.probe_from_thread(lock_path)
        self.assertTrue(ok_thread, f"另一个线程 {elapsed:.2f}s 内拿不到锁 → 进程内 RLock 泄漏")
        probe = self.probe_from_process(home, purpose=purpose)
        self.assertTrue(probe.get("ok"), f"另一个进程拿不到锁 → fd / 文件锁泄漏：{probe}")
        self.assertLess(probe.get("elapsed", 99), 1.0, "另一个进程拿锁耗时应远小于超时")


class ExceptionPathTests(LockProbeMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(self.home, self.home / "data.enc", lock_timeout=1.0, lock_poll=0.01)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.record = Record(title="淘宝", username="u1", password="old-pw")
        self.store.commit([Operation.add(self.record)])
        self.baseline_bytes = self.settings.vault_path.read_bytes()

    # ------------------------------------------------------------ 三个盲区场景
    def test_commit_internal_apply_changes_exception_releases_lock(self):
        """`VaultStore.commit` 内部抛异常：锁要放掉，盘要没变，下一次写入要成功。"""
        original = Record.apply_changes

        def boom(self, changes):
            raise RuntimeError("模拟 apply_changes 崩了")

        Record.apply_changes = boom
        try:
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(self.record.id, {"notes": "会被丢弃"})])
        finally:
            Record.apply_changes = original

        self.assertEqual(self.settings.vault_path.read_bytes(), self.baseline_bytes, "失败提交动了盘")
        self.assert_lock_free(self.home, self.settings.lock_path)

        result = self.store.commit([Operation.add(Record(title="事后补一条"))])
        self.assertEqual(result.added, 1, "异常之后的下一次写入失败了")

    def test_commit_save_exception_releases_lock(self):
        """写盘本身失败（os.replace 最终失败）：锁必须放掉。"""
        original = Vault.save

        def boom(save_self, *args, **kwargs):
            raise OSError(28, "磁盘写满（模拟）")

        Vault.save = boom
        try:
            with self.assertRaises(OSError):
                self.store.commit([Operation.add(Record(title="写不进去"))])
        finally:
            Vault.save = original

        self.assertEqual(self.settings.vault_path.read_bytes(), self.baseline_bytes)
        self.assert_lock_free(self.home, self.settings.lock_path)
        self.assertEqual(self.store.commit([Operation.add(Record(title="恢复后"))]).added, 1)

    def test_mutate_fn_exception_releases_lock(self):
        """`store.mutate(fn)` 的 `fn` 抛异常：锁要放掉，不能把库留在半改状态。"""

        def explode(vault: Vault) -> bool:
            vault.records.append(Record(title="半途而废"))
            raise ValueError("模拟 fn 崩了")

        with self.assertRaises(ValueError):
            self.store.mutate(explode)

        self.assertEqual(self.settings.vault_path.read_bytes(), self.baseline_bytes)
        self.assert_lock_free(self.home, self.settings.lock_path)
        self.assertEqual(self.store.mutate(lambda vault: True).revision, self.store.revision())

    def test_nested_three_levels_outer_raises(self):
        """嵌套 3 层，最外层抛异常：中间两层的 finally 必须都跑到，depth 归零。"""
        manager = self.store.lock
        with self.assertRaises(RuntimeError):
            with manager.hold(timeout=1.0, purpose="l1"):
                with manager.hold(timeout=1.0, purpose="l2"):
                    with manager.hold(timeout=1.0, purpose="l3"):
                        self.assertEqual(thread_book_depth(), 3)
                        raise RuntimeError("最外层炸了")

        self.assertEqual(thread_book_depth(), 0, "嵌套异常后 depth 没有归零")
        self.assertFalse(manager.busy(), "全部退出后 busy() 仍为 True")
        self.assert_lock_free(self.home, self.settings.lock_path)

    def test_keyboard_interrupt_inside_critical_section(self):
        """`KeyboardInterrupt` 不是 `Exception`。
        如果实现用 `except Exception` 兜底放锁，Ctrl-C 就会永久占住锁。"""
        original = Vault.save

        def boom(save_self, *args, **kwargs):
            raise KeyboardInterrupt

        Vault.save = boom
        try:
            with self.assertRaises(KeyboardInterrupt):
                self.store.commit([Operation.add(Record(title="被打断"))])
        finally:
            Vault.save = original

        self.assertEqual(self.settings.vault_path.read_bytes(), self.baseline_bytes)
        self.assert_lock_free(self.home, self.settings.lock_path)

    def test_keyboard_interrupt_during_acquire_releases_rlock(self):
        """`_acquire_file_lock` 里抛 `BaseException`：`self._rlock` 必须被 release，
        否则同进程后续所有线程都会卡在进程内第一层。"""
        manager = LockManager(self.settings.lock_path, default_timeout=5.0, poll_seconds=0.005)
        original = manager._try_lock_once
        state = {"n": 0}

        def flaky(fd: int) -> bool:
            state["n"] += 1
            if state["n"] >= 3:
                raise KeyboardInterrupt
            return False

        manager._try_lock_once = flaky
        try:
            with self.assertRaises(KeyboardInterrupt):
                with manager.hold(timeout=5.0, purpose="kb-acquire"):
                    pass
        finally:
            manager._try_lock_once = original

        ok, elapsed = self.probe_from_thread(self.settings.lock_path)
        self.assertTrue(ok, f"拿到锁前抛 KeyboardInterrupt 后，另一个线程 {elapsed:.2f}s 内拿不到锁")

    def test_lock_timeout_during_acquire_releases_rlock(self):
        """超时路径（LockTimeout）同样不能把进程内 RLock 留在手里。"""
        holder_release = threading.Event()

        def hold_then_release() -> None:
            manager = LockManager(self.settings.lock_path, default_timeout=10.0)
            with manager.hold(purpose="holder"):
                holder_release.wait(5.0)

        thread = threading.Thread(target=hold_then_release, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not self.store.lock.busy():
            time.sleep(0.01)
        try:
            with self.assertRaises(LockTimeout):
                with self.store.lock.hold(timeout=0.2, purpose="timeout-case"):
                    pass
        finally:
            holder_release.set()
            thread.join(timeout=5)

        # holder 退出后，本进程的主线程必须能再拿到（RLock 没被超时路径吞掉）
        with self.store.lock.hold(timeout=2.0, purpose="after-timeout"):
            pass
        self.assertEqual(thread_book_depth(), 0)

    def test_fifty_exception_retries_do_not_accumulate(self):
        """50 次「抛异常 → 重试成功」：depth 不累积、句柄数不涨、第 50 次也不变慢。"""
        original = Record.apply_changes
        handles_before = handle_count()
        elapsed_last = 0.0

        def boom(self, changes):
            raise RuntimeError("模拟 apply_changes 崩了")

        Record.apply_changes = boom
        try:
            for index in range(50):
                with self.assertRaises(RuntimeError):
                    self.store.commit([Operation.update(self.record.id, {"notes": f"x{index}"})])
                self.assertEqual(thread_book_depth(), 0, f"第 {index} 轮 depth 没归零")
                started = time.monotonic()
                self.assertEqual(
                    self.store.commit([Operation.add(Record(title=f"重试{index}"))]).added, 1
                )
                elapsed_last = time.monotonic() - started
        finally:
            Record.apply_changes = original

        handles_after = handle_count()
        if handles_before > 0 and handles_after > 0:
            self.assertLess(
                handles_after - handles_before,
                10,
                f"50 轮异常后句柄数涨了 {handles_after - handles_before} 个 → fd 在泄漏",
            )
        self.assertLess(elapsed_last, 0.5, f"第 50 次重试耗时 {elapsed_last:.2f}s，疑似被上一轮的残留锁拖慢")
        self.assert_lock_free(self.home, self.settings.lock_path)

    def test_staging_commit_exception_releases_staging_lock(self):
        """暂存区持 `.staging.lock` 时再调 `VaultStore.commit`，后者炸了：
        暂存区的锁也必须放掉，否则整个待整理功能卡死。"""
        from pwdvault.staging import StagingStore

        settings = self.settings
        staging = StagingStore(settings, lambda: self.vault.dek)
        inbox = settings.inbox_path
        inbox.mkdir(parents=True, exist_ok=True)
        path = inbox / "待入库.txt"
        path.write_text("淘宝 u1 old-pw\n", encoding="utf-8")
        batch = staging.create_from_file(
            path=path, text="", drafts=[Record(title="入库失败", username="u9")]
        )
        staging.transition(batch.batch_id, "review")
        outer_before = (settings.staging_dir / f"{batch.batch_id}.enc").read_bytes()

        original = VaultStore.commit

        def boom(store_self, *args, **kwargs):
            raise OSError(5, "模拟入库时写盘失败")

        VaultStore.commit = boom
        try:
            with self.assertRaises(OSError):
                staging.commit(batch.batch_id, store=self.store)
        finally:
            VaultStore.commit = original

        # 1) staging 锁没泄漏（另起进程探 .staging.lock）
        probe = self.probe_from_process(self.home, timeout=1.0, purpose="staging")
        self.assertTrue(probe.get("ok"), f"staging 锁被泄漏：{probe}")
        self.assertEqual(thread_book_depth(), 0)
        # 2) 批次仍在 review，且盘上没有被写进「提交意图」
        self.assertEqual(staging.get(batch.batch_id).status, "review")
        self.assertEqual(
            (settings.staging_dir / f"{batch.batch_id}.enc").read_bytes(),
            outer_before,
            "失败的 commit 改了批次文件（commit.intent 应只存在于内存）",
        )
        # 3) 功能恢复：这次能正常入库
        result = staging.commit(batch.batch_id, store=self.store)
        self.assertEqual(result["status"], "committed")

    # ------------------------------------------------------------ 回归钉子（已修）
    def test_failed_commit_does_not_possibly_persist_partial_change_later(self):
        """回归测试 Q-02：`commit` 失败后内存里的半改状态，会被**下一次成功写入**带到盘上。

        `Record.apply_changes` 就地改对象，异常前已经改了一半；`vault.save()` 没跑，
        所以盘上 revision 不变，下一次 commit 时 `disk == self._vault.revision`
        判定「无需 reload」，于是把上一轮失败留下的脏数据一起写进去。
        用户视角：一个明确报错的操作，在几分钟后因为一次无关的写入悄悄生效了。
        """
        original = Record.apply_changes

        def half_apply(self, changes):
            original(self, changes)  # 真改了内存
            raise RuntimeError("改到一半崩了")

        Record.apply_changes = half_apply
        try:
            with self.assertRaises(RuntimeError):
                self.store.commit([Operation.update(self.record.id, {"notes": "不该留下"})])
        finally:
            Record.apply_changes = original

        self.store.commit([Operation.add(Record(title="无关的新记录"))])
        fresh = Vault.open(self.settings, password=PASSWORD)
        notes = fresh.find_by_id(self.record.id).notes
        self.assertEqual(notes, "", f"失败的提交把 notes={notes!r} 泄露到盘上了")


class LockFileOpenRaceTests(unittest.TestCase):
    """锁文件**首次创建**时的共享冲突 —— `atomic_write` 有重试，`_open_fd` 没有。"""

    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(self.home, self.home / "data.enc", lock_timeout=3.0, lock_poll=0.01)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.store = VaultStore(self.settings, fixture.vault)

    def test_transient_open_error_is_retried(self):
        """回归测试 Q-01（实测 6/80 ≈ 7.5% 复现率）。

        两个进程同时**首次创建** `data.enc.lock` 时，Windows 会对其中一个返回
        `PermissionError`（Errno 13）。`_open_fd()` 里 `os.open(...)` 一次都不重试，
        `hold()` 也不翻译这个异常，于是它一路冒到 `cli.main` 之外 ——
        用户看到的是裸 traceback（退出码 1），既不是 `lock_timeout` 也不是任何 `VaultError`。

        对照：`vault.atomic_write` 与 `vault._read_text_retry` 都为同类瞬时冲突写了
        6 次指数退避（注释里明确写了「网盘同步与杀软会显著放大这个窗口」），
        锁文件打开这一处被漏掉了。
        """
        real_open = os.open
        state = {"raised": False}

        def flaky_open(path, flags, mode=0o777):
            if not state["raised"] and str(path).endswith(".lock"):
                state["raised"] = True
                raise PermissionError(13, "模拟并发创建锁文件时的瞬时共享冲突")
            return real_open(path, flags, mode)

        os.open = flaky_open
        try:
            result = self.store.commit([Operation.add(Record(title="瞬时冲突"))])
        finally:
            os.open = real_open
        self.assertEqual(result.added, 1, "一次瞬时 PermissionError 就让整个写入失败了")


class CrossProcessCrashTests(LockProbeMixin, unittest.TestCase):
    """真跨进程：一个是「被 SIGKILL 打断的持锁者」，一个是并发写者。"""

    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(self.home, self.home / "data.enc", lock_timeout=3.0, lock_poll=0.01)
        fixture = support.make_vault(self.home, snapshot_keep=3)
        self.settings = fixture.settings
        self.vault = fixture.vault
        # 预热锁文件：缺陷 Q-01（首次并发创建锁文件时 PermissionError）会让本类的
        # 跨进程用例以 ~6% 的概率变成环境性失败，掩盖真正要测的东西。
        # Q-01 本身由 LockFileOpenRaceTests 确定性钉住，这里只需要避开它的窗口。
        self.settings.lock_path.write_bytes(b"\0")
        self.settings.staging_lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings.staging_lock_path.write_bytes(b"\0")

    def _start_holder(self, seconds: float = 30.0) -> subprocess.Popen:
        proc = subprocess.Popen(
            [support.PYTHON, str(RUNNER), "hold-lock", str(seconds)],
            cwd=str(support.PROJECT_ROOT),
            env=qa.child_env(self.home, PASSWORD),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = proc.stdout.readline()
        # 注意：断言消息里的 stderr.read() 会阻塞到子进程退出，绝不能写在这里
        self.assertIn('"held"', line, f"子进程没能拿到锁：{line!r}")
        return proc

    @staticmethod
    def _stop(proc: subprocess.Popen) -> None:
        proc.kill()
        proc.wait(timeout=20)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass

    def test_killed_holder_does_not_block_next_writer(self):
        """持锁进程被强杀：锁文件残留，但下一个写者必须能立刻写入（不允许卡满超时）。"""
        proc = self._start_holder()
        time.sleep(0.2)
        self._stop(proc)
        self.assertIsNotNone(proc.returncode)
        self.assertTrue(self.settings.lock_path.exists(), "锁文件本应残留（这是正常现象）")

        started = time.monotonic()
        result = support.run_py(
            ["add", "--json", "-t", "杀掉之后", "-p", "pw-after-kill"],
            home=self.home,
            env={"PV_MASTER_PASSWORD": PASSWORD},
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, f"强杀之后写入失败：{result.stderr[-800:]}")
        self.assertLess(elapsed, 3.0, f"强杀之后写入耗时 {elapsed:.2f}s（说明在等 3 秒超时）")

        fresh = Vault.open(self.settings, password=PASSWORD)
        self.assertIn("杀掉之后", {record.title for record in fresh.records})
        self.assertEqual(read_revision(self.settings.vault_path), fresh.revision)

    def test_reads_are_not_blocked_while_lock_is_held(self):
        """读路径永不加锁：别人拿着写锁时，`pv list` 不该被卡住。"""
        proc = self._start_holder(seconds=20.0)
        try:
            started = time.monotonic()
            result = support.run_py(
                ["list", "--json"], home=self.home, env={"PV_MASTER_PASSWORD": PASSWORD}
            )
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 0, result.stderr[-400:])
            self.assertLess(elapsed, 5.0, f"读操作被写锁挡住了 {elapsed:.2f}s")
        finally:
            self._stop(proc)

    def test_two_simultaneous_cli_adds_both_land(self):
        """两个真进程同时 `pv add --password-stdin`：都要成功，且都不丢。

        两个子进程都阻塞在 `sys.stdin.read()` 上，用两个线程同时把口令喂进去，
        保证它们真的同时进入写锁竞争，而不是一前一后。
        """
        procs = [
            subprocess.Popen(
                [
                    support.PYTHON,
                    str(support.PV_ENTRY),
                    "add",
                    "--password-stdin",
                    "--json",
                    "-t",
                    f"并发写入{index}",
                    "-p",
                    f"pw-{index}",
                ],
                cwd=str(support.PROJECT_ROOT),
                env=qa.child_env(self.home, PASSWORD),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(2)
        ]
        results: list[tuple[str, str] | None] = [None] * len(procs)

        def feed(index: int) -> None:
            results[index] = procs[index].communicate(input=PASSWORD + "\n", timeout=180)

        threads = [threading.Thread(target=feed, args=(index,)) for index in range(len(procs))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=200)

        for index, proc in enumerate(procs):
            self.assertEqual(
                proc.returncode,
                0,
                f"第 {index} 个并发 add 失败：{(results[index] or ('', ''))[1][-800:]}",
            )

        fresh = Vault.open(self.settings, password=PASSWORD)
        self.assertEqual(len(fresh.records), 2, f"并发写入丢了记录：{len(fresh.records)}")
        self.assertEqual(len({record.id for record in fresh.records}), 2)

    def test_leftover_lock_file_with_garbage_bytes(self):
        """崩溃可能留下一个非空锁文件（我们写过 1 字节哨兵）。再写入必须照常。"""
        self.settings.lock_path.write_bytes(b"garbage" * 512)
        result = support.run_py(
            ["add", "--json", "-t", "残留锁文件", "-p", "pw"],
            home=self.home,
            env={"PV_MASTER_PASSWORD": PASSWORD},
        )
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertEqual(len(Vault.open(self.settings, password=PASSWORD).records), 1)


if __name__ == "__main__":
    unittest.main()
