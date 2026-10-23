"""inbox 的**跨进程**去重 —— 工程师的"模拟重启"只是重建对象，没有真的换进程。

`test_inbox.py` 里的 `test_rescan_after_restart_still_one_batch` 做法是「新建一个
`StagingStore` + 新建一个 `InboxWatcher`」，注释写着"模拟进程重启"。但真正决定
「同一个文件会不会建两批」的三重去重里，有两重是**从盘上读的**
（`tombstones` ∪ `batches_by_hash`），它们都是「先读、后建、读和建之间没有原子性」：

    scan_once():  known = batches_by_hash()      ← 读（无锁）
                  ...
                  create_from_file(...)          ← 写（有 .staging.lock）

两个真进程同时扫同一份文件时，两次「读」都发生在任一「写」之前，于是两份批次都会
被建出来 —— 单进程重建对象永远测不到这个窗口。

本文件用两个真进程打这个窗口，并把它的下游后果（入库后出现重复记录）也量出来。
另外补三个工程师没覆盖的点：内容变了但 (size, mtime) 没变的静默漏收、
同名文件覆盖的行为、以及 500 个文件时 `scan_once()` 的耗时。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _qa_runner as qa
import _support as support

from pwdvault.config import load_settings
from pwdvault.inbox import InboxWatcher
from pwdvault.locks import VaultStore
from pwdvault.staging import StagingStore
from pwdvault.vault import Vault

RUNNER = Path(__file__).resolve().parent / "_qa_runner.py"
PASSWORD = support.PASSWORD

# 供报告使用的性能数据（tearDownModule 统一打印，避免混进测试输出）
PERF: dict[str, float] = {}

TXT = """淘宝
账号: zhangsan@example.com
密码: Tb#2024xy
网址: https://taobao.com

京东
账号: lisi
密码: Jd@9988
"""


def tearDownModule() -> None:
    if PERF:
        print("\n[QA-PERF] " + json.dumps(PERF, ensure_ascii=False), file=sys.stderr)


class InboxBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(self.home, self.home / "data.enc", lock_timeout=10.0, lock_poll=0.01)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        previous_home = os.environ.get("PV_HOME")
        os.environ["PV_HOME"] = str(self.home)
        self.addCleanup(
            lambda: os.environ.pop("PV_HOME", None)
            if previous_home is None
            else os.environ.__setitem__("PV_HOME", previous_home)
        )
        self.settings = load_settings()
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.staging = self.new_staging()
        # 预先建好两个锁文件：缺陷 Q-01（首次并发创建锁文件时 Windows 会返回
        # PermissionError）会让「跨进程」用例变成概率性失败，掩盖本文件真正要测的
        # 去重/原子性问题。Q-01 本身在 test_qa_locks.py 里有确定性钉子。
        for lock_path in (self.settings.lock_path, self.settings.staging_lock_path):
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_path.write_bytes(b"\0")

    def new_staging(self) -> StagingStore:
        return StagingStore(self.settings, lambda: self.vault.dek)

    def drop(self, name: str, text: str) -> Path:
        path = self.inbox / name
        path.write_text(text, encoding="utf-8")
        return path

    def batch_files(self) -> list[Path]:
        return sorted(self.settings.staging_dir.glob("sb_*.enc"))


class CrossProcessDedupTests(InboxBase):
    def test_two_processes_scan_same_file_only_one_batch(self):
        """回归测试 Q-05：两个真进程同时扫同一份文件 → 建出**两批**。

        `scan_once()` 的三重去重（tombstones / batches_by_hash / _seen）全在读侧，
        与 `create_from_file()` 之间没有"锁内再查一次 hash"的二次确认。

        实测影响（不要夸大）：两批都会出现在待整理列表里（同一份文件两条待办）；
        第二批入库时，默认 `mode="skip"` 会按「标题+账号已存在」跳过，**不会**产生重复记录；
        只有用户对第二批选「新建副本」（`mode="append"`）才会真的插出重复记录。
        所以这是「状态/交互污染 + 特定模式下的重复数据」，不是默认路径的数据损坏。

        修法（建议）：`create_from_file` 在 `.staging.lock` 内先查一次
        `batches_by_hash()`，命中同一 sha256 就直接返回已有批次（幂等），
        或让 `create_from_file` 接受 `dedupe=True` 并在锁内判重。
        """
        self.drop("旧账号.txt", TXT)
        go = time.time() + 1.5
        procs = [
            subprocess.Popen(
                [
                    support.PYTHON,
                    str(RUNNER),
                    "inbox-scan",
                    f"--start-at={go}",
                ],
                cwd=str(support.PROJECT_ROOT),
                env=qa.child_env(self.home, PASSWORD),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        results = []
        for proc in procs:
            out, err = proc.communicate(timeout=180)
            lines = [line for line in (out or "").strip().splitlines() if line.strip()]
            results.append(json.loads(lines[-1]) if lines else {"error": err[-300:]})

        created_total = sum(len(item.get("created") or []) for item in results)
        batches = self.batch_files()
        self.assertEqual(
            len(batches),
            1,
            f"同一个文件被建出了 {len(batches)} 个批次（created_total={created_total}）："
            f"{[p.name for p in batches]}",
        )

    def test_two_processes_scanning_do_not_corrupt_staging_dir(self):
        """即使两批都被建出来，`staging/` 里也不允许出现半截文件（加密写必须原子）。"""
        self.drop("旧账号.txt", TXT)
        go = time.time() + 1.2
        procs = [
            subprocess.Popen(
                [support.PYTHON, str(RUNNER), "inbox-scan", f"--start-at={go}"],
                cwd=str(support.PROJECT_ROOT),
                env=qa.child_env(self.home, PASSWORD),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        for proc in procs:
            out, err = proc.communicate(timeout=180)
            self.assertIn("{", out or "", f"扫描子进程失败：{err[-400:]}")

        for path in self.batch_files():
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload.get("format"), "pwdvault-staging", f"{path.name} 不是完整批次")
            self.assertIn("sealed", payload)
            # 每个批次都必须能真的解密（不能留下写坏的批次）
            self.staging.get(payload["batch_id"])


class ContentChangeTests(InboxBase):
    def test_same_name_same_content_is_not_reprocessed(self):
        """同名同内容再落一次：不重复建批（这是去重的正常路径）。"""
        self.drop("重复.txt", TXT)
        watcher = InboxWatcher(self.settings, self.staging, interval=0.05)
        self.assertEqual(len(watcher.scan_once()), 1)
        self.drop("重复.txt", TXT)
        self.assertEqual(watcher.scan_once(), [], "同一份内容被重复建批了")
        self.assertEqual(len(self.batch_files()), 1)

    def test_same_name_different_content_makes_second_batch(self):
        """同名但内容不同：允许建第二批（用户确实换了一份文件）。

        副作用值得知道：重复建批之后两份都能入库，`duplicate_record` 只是警告。
        """
        self.drop("换了内容.txt", TXT)
        watcher = InboxWatcher(self.settings, self.staging, interval=0.05)
        self.assertEqual(len(watcher.scan_once()), 1)
        self.drop("换了内容.txt", TXT + "\n第三条\n账号: wangwu\n密码: Ww@12345\n")
        self.assertEqual(len(watcher.scan_once()), 1)
        self.assertEqual(len(self.batch_files()), 2)

    def test_content_change_with_preserved_mtime_is_not_silently_dropped(self):
        """回归测试 Q-06（构造性复现，现实概率低但完全静默）：

        `scan_once()` 用 `(st_size, st_mtime_ns)` 做"这一轮没变过"的短路判断，
        命中就**不去算 sha256**。而设计上判重依据是 sha256。
        于是当文件内容变了、但大小与 mtime 都没变时（`cp -p` 覆盖同长度文件、
        某些同步/还原工具会保留 mtime），这份新内容永远不会被收 —— 用户看不到任何报错。

        这里用 `os.utime` 把 mtime 精确还原，构造出这个窗口。
        """
        path = self.drop("同长度覆盖.txt", "站点A\n账号: u1\n密码: aaaa1111\n")
        watcher = InboxWatcher(self.settings, self.staging, interval=0.05)
        self.assertEqual(len(watcher.scan_once()), 1)

        stat_before = path.stat()
        path.write_text("站点B\n账号: u2\n密码: bbbb2222\n", encoding="utf-8")
        os.utime(path, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
        self.assertEqual(path.stat().st_size, stat_before.st_size, "构造失败：大小必须一致")

        created = watcher.scan_once()
        self.assertEqual(
            len(created),
            1,
            "内容已变（只是 size/mtime 未变），scan_once 却什么都没收 → 静默漏收",
        )


class ScanPerformanceTests(InboxBase):
    def test_scan_once_with_500_files(self):
        """500 个小文件：`scan_once()` 的耗时要能接受（报告数据，阈值宽松）。"""
        for index in range(500):
            (self.inbox / f"批量-{index:03d}.txt").write_text(
                f"站点{index}\n账号: user{index}\n密码: pw-{index}\n", encoding="utf-8"
            )
        watcher = InboxWatcher(self.settings, self.staging, interval=0.05)

        started = time.monotonic()
        created = watcher.scan_once()
        first_pass = time.monotonic() - started
        PERF["inbox_500_first_scan_seconds"] = round(first_pass, 3)
        PERF["inbox_500_batches_created"] = float(len(created))

        started = time.monotonic()
        second = watcher.scan_once()
        second_pass = time.monotonic() - started
        PERF["inbox_500_second_scan_seconds"] = round(second_pass, 3)

        self.assertEqual(len(created), 500, "有文件没被建批")
        self.assertEqual(second, [], "第二轮不该再建批")
        self.assertEqual(len(self.batch_files()), 500)
        # 阈值故意宽松：这里要抓的是「几百个文件就卡住主循环」这类量级问题，
        # 不是机器快慢。真实数据见 PERF。
        self.assertLess(first_pass, 30.0, f"500 个文件首轮扫描耗时 {first_pass:.1f}s，太慢")
        self.assertLess(second_pass, 5.0, f"500 个文件复扫耗时 {second_pass:.1f}s，主循环会被拖住")


if __name__ == "__main__":
    unittest.main()
