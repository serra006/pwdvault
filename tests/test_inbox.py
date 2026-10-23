"""inbox 监听测试：扫描幂等、重启后仍幂等、墓碑、未解锁、干净停止、坏文件。

全部用 `scan_once()` 同步驱动，不依赖线程时序（唯一用线程的是 stop 测试）。
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault.inbox import InboxWatcher, decode_bytes
from pwdvault.staging import StagingStore

TXT = """淘宝
账号: zhangsan@example.com
密码: Tb#2024xy
网址: https://taobao.com

京东
账号: lisi
密码: Jd@9988
"""


class InboxBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        self.dek: dict = {"value": self.vault.dek}
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.events: list[tuple[str, dict]] = []
        self.staging = self.new_staging()
        self.watcher = InboxWatcher(
            self.settings,
            self.staging,
            on_event=lambda event, data: self.events.append((event, data)),
            interval=0.05,
        )

    def new_staging(self, *, available: bool = True) -> StagingStore:
        return StagingStore(self.settings, lambda: self.dek["value"] if available else None)

    def drop(self, name: str, text: str) -> Path:
        path = self.inbox / name
        path.write_text(text, encoding="utf-8")
        return path


class ScanIdempotencyTests(InboxBase):
    def test_scan_three_times_creates_one_batch(self):
        self.drop("旧账号.txt", TXT)
        first = self.watcher.scan_once()
        self.assertEqual(len(first), 1)
        self.assertEqual(self.watcher.scan_once(), [])
        self.assertEqual(self.watcher.scan_once(), [])
        batches = self.staging.list_batches()
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0].status, "drafted")
        self.assertEqual(batches[0].item_count, 2)

    def test_rescan_after_restart_still_one_batch(self):
        self.drop("旧账号.txt", TXT)
        self.watcher.scan_once()
        # 模拟进程重启：新的 StagingStore（内存缓存全丢）+ 新的 watcher
        restarted_store = self.new_staging()
        restarted = InboxWatcher(self.settings, restarted_store, interval=0.05)
        self.assertEqual(restarted.scan_once(), [])
        self.assertEqual(len(restarted_store.list_batches()), 1)

    def test_identical_content_different_name_not_duplicated(self):
        self.drop("a.txt", TXT)
        self.watcher.scan_once()
        self.drop("b.txt", TXT)  # 内容相同 → 同一个 sha256
        self.assertEqual(self.watcher.scan_once(), [])
        self.assertEqual(len(self.staging.list_batches()), 1)

    def test_tombstone_prevents_reimport_after_discard(self):
        self.drop("丢弃我.txt", TXT)
        created = self.watcher.scan_once()
        self.assertEqual(len(created), 1)
        self.staging.discard(created[0])

        # 同一份文件再出现（用户又从别处拷回来）
        (self.inbox / "丢弃我.txt").unlink(missing_ok=True)
        self.drop("丢弃我.txt", TXT)
        restarted = InboxWatcher(self.settings, self.new_staging(), interval=0.05)
        self.assertEqual(restarted.scan_once(), [])
        self.assertEqual(len(self.staging.list_batches(include_finished=True)), 1)

    def test_oversize_skipped(self):
        from dataclasses import replace

        path = self.inbox / "大文件.txt"
        path.write_text("x" * 2000, encoding="utf-8")
        small = replace(self.settings, inbox_max_file_bytes=100)
        watcher = InboxWatcher(small, self.staging, interval=0.05)
        self.assertEqual(watcher.scan_once(), [])
        self.assertEqual(watcher.status()["oversize"], 1)
        self.assertEqual(self.staging.list_batches(), [])


class LockedTests(InboxBase):
    def test_locked_does_not_create_batch_but_creates_after_unlock(self):
        self.drop("旧账号.txt", TXT)
        saved_dek = self.dek["value"]
        self.dek["value"] = None  # 模拟未解锁
        locked_store = self.new_staging()
        locked = InboxWatcher(self.settings, locked_store, interval=0.05)

        self.assertEqual(locked.scan_once(), [])
        self.assertEqual(locked.status()["pending"], 1)
        self.assertEqual(locked_store.list_batches(), [])

        # 解锁：同一个 watcher 下一 tick 自动补上
        self.dek["value"] = saved_dek
        created = locked.scan_once()
        self.assertEqual(len(created), 1)
        self.assertEqual(locked.status()["pending"], 0)
        self.assertEqual(len(locked_store.list_batches()), 1)


class ThreadTests(InboxBase):
    def test_start_is_idempotent_and_stop_is_fast(self):
        self.watcher.start()
        first = self.watcher._thread
        self.watcher.start()
        self.assertIs(self.watcher._thread, first, "start() 必须幂等，只起一个线程")
        self.assertTrue(self.watcher.status()["watching"])

        started = time.monotonic()
        self.watcher.stop(timeout=3.0)
        elapsed = time.monotonic() - started
        self.assertFalse(self.watcher.status()["watching"])
        self.assertLess(elapsed, 3.0, "stop() 不能等满一个轮询周期")

    def test_thread_picks_up_new_file(self):
        self.watcher.start()
        try:
            self.drop("晚到的.txt", TXT)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if self.staging.list_batches():
                    break
                time.sleep(0.02)
            self.assertEqual(len(self.staging.list_batches()), 1)
        finally:
            self.watcher.stop(timeout=3.0)

    def test_event_emitted(self):
        self.drop("事件.txt", TXT)
        self.watcher.scan_once()
        self.assertTrue(self.events)
        event, data = self.events[0]
        self.assertEqual(event, "staging")
        self.assertEqual(data["status"], "drafted")
        self.assertEqual(data["item_count"], 2)


class BadFileTests(InboxBase):
    def test_gbk_file_does_not_raise(self):
        path = self.inbox / "gbk存档.txt"
        path.write_bytes(TXT.encode("gbk"))
        created = self.watcher.scan_once()
        self.assertEqual(len(created), 1)
        batch = self.staging.list_batches()[0]
        self.assertIn(batch.status, ("drafted", "failed"))

    def test_binary_file_does_not_raise(self):
        path = self.inbox / "二进制.dat"
        path.write_bytes(bytes(range(256)) * 8)
        created = self.watcher.scan_once()
        self.assertEqual(len(created), 1)
        self.assertIn(self.staging.list_batches()[0].status, ("drafted", "failed"))

    def test_empty_file_makes_failed_batch(self):
        self.drop("空的.txt", "")
        created = self.watcher.scan_once()
        self.assertEqual(len(created), 1)
        self.assertEqual(self.staging.get(created[0]).status, "failed")

    def test_unknown_suffix_ignored(self):
        self.drop("图片.png", "not really a png")
        self.assertEqual(self.watcher.scan_once(), [])
        self.assertEqual(self.staging.list_batches(), [])

    def test_decode_fallback_never_raises(self):
        self.assertIsInstance(decode_bytes(b"\xff\xfe\x00abc"), str)


class StatusTests(InboxBase):
    def test_status_shape(self):
        status = self.watcher.status()
        for key in ("watching", "dir", "interval", "last_scan", "pending", "error_count"):
            self.assertIn(key, status)
        self.assertEqual(status["dir"], str(self.settings.inbox_path))

    def test_missing_inbox_dir_is_fine(self):
        watcher = InboxWatcher(self.settings, self.staging, interval=0.05)
        import shutil

        shutil.rmtree(self.inbox, ignore_errors=True)
        self.assertEqual(watcher.scan_once(), [])
        self.assertIsNotNone(watcher.status()["last_scan"])


if __name__ == "__main__":
    unittest.main()
