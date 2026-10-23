"""暂存区的**真实时间竞态** —— 工程师的全部时间用例都注入假时钟，测不到这里。

`test_staging.py` 用 `FakeClock` 把「租约过期」「编辑锁过期」都做成确定性断言，这是好实践，
但它顺带跳过了一整类真实世界的问题：

1. 时间戳是 `isoformat(timespec="seconds")` —— 秒级截断，`>=` 与 `>` 的差别在真实墙钟上
   会被「最多 1 秒的截断误差」放大，`lease_seconds=3` 实际可能只有 2.0 秒；
2. 两个**真进程**同时抢同一个 `reviewing` 批次时，".staging.lock 内重读" 是否真的
   兜住了「恰好一个成功」；
3. 编辑锁的粒度是 `holder` 字符串。DESIGN §3 的默认值就是常量 `"ui"` ——
   两个窗口同名时，这把锁什么也没锁住；
4. commit 与 rollback 并发时，「批次状态」与「库里的记录」是否自洽。

本文件把这些都用真进程 / 真墙钟打一遍，不用假时钟。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _qa_runner as qa
import _support as support

from pwdvault import staging as staging_module
from pwdvault.config import load_settings
from pwdvault.errors import StagingBusy
from pwdvault.locks import VaultStore
from pwdvault.models import Record
from pwdvault.staging import StagingStore
from pwdvault.vault import Vault

RUNNER = Path(__file__).resolve().parent / "_qa_runner.py"
PASSWORD = support.PASSWORD

LEASE_SECONDS = 2


class StagingRaceBase(unittest.TestCase):
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
        # 父进程必须和子进程读到**同一份 config.toml**，否则父进程用的是
        # Settings() 的内置默认值（lease=180s），测的就不是配置覆盖了。
        previous_home = os.environ.get("PV_HOME")
        os.environ["PV_HOME"] = str(self.home)
        self.addCleanup(
            lambda: os.environ.pop("PV_HOME", None)
            if previous_home is None
            else os.environ.__setitem__("PV_HOME", previous_home)
        )
        self.settings = load_settings()
        self.assertEqual(
            str(self.settings.vault_path), str(self.home / "data.enc"), "父进程读错了库路径"
        )
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.staging = self.new_staging()

    def new_staging(self) -> StagingStore:
        return StagingStore(self.settings, lambda: self.vault.dek)

    # ------------------------------------------------------------ 夹具
    def make_batch(self, *, name: str = "竞态.txt", records: list[Record] | None = None):
        records = records if records is not None else [
            Record(title="淘宝", username="u1", password="p1"),
            Record(title="京东", username="u2", password="p2"),
        ]
        path = self.inbox / name
        # 正文必须每次不同：create_from_file 现在按源文件 sha256 幂等（Q-05 修复），
        # 同内容会直接返回既有批次（可能是上一轮已入库的那一批）。
        seq = getattr(self, "_batch_seq", 0) + 1
        self._batch_seq = seq
        path.write_text(f"占位-{seq:04d}\n", encoding="utf-8")
        batch = self.staging.create_from_file(path=path, text="", drafts=records)
        return batch

    def to_review(self, batch_id: str):
        return self.staging.transition(batch_id, "review")

    def spawn(self, action: str, batch_id: str, *, holder: str | None = None, start_at: float | None = None,
              extra: list[str] | None = None) -> object:
        args = [support.PYTHON, str(RUNNER), "staging", action, batch_id]
        if holder is not None:
            args.append(f"--holder={holder}")
        if start_at is not None:
            args.append(f"--start-at={start_at}")
        args.extend(extra or [])
        return subprocess.Popen(
            args,
            cwd=str(support.PROJECT_ROOT),
            env=qa.child_env(self.home, PASSWORD),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @staticmethod
    def collect(proc) -> dict:
        out, err = proc.communicate(timeout=180)
        lines = [line for line in (out or "").strip().splitlines() if line.strip()]
        payload = json.loads(lines[-1]) if lines else {"ok": False, "error": err[-500:]}
        payload["returncode"] = proc.returncode
        return payload

    def run_both(self, first, second) -> tuple[dict, dict]:
        return self.collect(first), self.collect(second)


class BeginEditRaceTests(StagingRaceBase):
    def test_two_processes_distinct_holders_exactly_one_wins(self):
        """两个真进程、不同 holder 同时 `begin_edit`：必须恰好一个成功。

        两个都成功 = 「用户 A 的编辑被用户 B 的保存覆盖」的数据事故；
        两个都失败 = 谁也进不去，功能不可用。
        """
        batch = self.make_batch(name="抢编辑.txt")
        self.to_review(batch.batch_id)
        go = time.time() + 1.5
        first = self.spawn("begin-edit", batch.batch_id, holder="窗口A", start_at=go)
        second = self.spawn("begin-edit", batch.batch_id, holder="窗口B", start_at=go)
        result_a, result_b = self.run_both(first, second)

        wins = int(bool(result_a.get("ok"))) + int(bool(result_b.get("ok")))
        self.assertEqual(
            wins,
            1,
            f"必须恰好一个成功，实际 {wins} 个：A={result_a} B={result_b}",
        )
        loser = result_a if not result_a.get("ok") else result_b
        self.assertEqual(loser.get("code"), "staging_busy", f"失败方应是 staging_busy：{loser}")

        stored = self.staging.get(batch.batch_id)
        self.assertEqual(stored.status, "reviewing")
        winner = "窗口A" if result_a.get("ok") else "窗口B"
        self.assertEqual(stored.editor["holder"], winner, "编辑锁的持有者与真正成功的一方不一致")

    def test_two_processes_same_default_holder_only_one_wins(self):
        """回归测试 Q-03：`holder` 默认值就是常量 `"ui"`（DESIGN §3 的签名就是 `holder="ui"`）。

        两个真进程都用默认 holder（也就是两个浏览器窗口，或 web 进程与 CLI 同时操作），
        第二个 `begin_edit` 会**静默成功**：它拿到一个「编辑中」的批次，
        没有任何 `StagingBusy`，随后两边的 `save_items` 互相覆盖 —— 用户填写的内容被吞掉。

        `_editor_valid() and editor.holder == holder → return`（staging.py:859-862）
        把"同一个 holder"当作"同一个编辑者"，但 holder 的粒度只是一句字符串，
        它并不标识窗口/会话实例。
        """
        batch = self.make_batch(name="同名抢编辑.txt")
        self.to_review(batch.batch_id)
        go = time.time() + 1.5
        first = self.spawn("begin-edit", batch.batch_id, start_at=go)
        second = self.spawn("begin-edit", batch.batch_id, start_at=go)
        result_a, result_b = self.run_both(first, second)

        wins = int(bool(result_a.get("ok"))) + int(bool(result_b.get("ok")))
        self.assertEqual(
            wins,
            1,
            f"同名 holder 下两个进程都进入了编辑态（后者的保存会覆盖前者）：A={result_a} B={result_b}",
        )

    def test_editor_lock_expiry_allows_takeover_wallclock(self):
        """编辑锁过期的**真实墙钟**行为：接管必须真的发生，且不能在有效期内提前发生。

        `EDITOR_LOCK_SECONDS` 是模块常量而不是配置项（DESIGN §4.4 定为 120s），
        所以这里用运行时改常量（不改源码默认值）压缩到 2 秒来测真实时间路径。

        为什么取 2 而不是 1：`_iso()` 用 `timespec="seconds"` 截断小数秒，
        `now - since` 因此最多被放大约 1 秒（见下面的 Q-04 用例）。
        取 2 秒可以让「0.2s 时仍有效 / 2.1s 时已失效」两个断言在截断误差下依然确定。
        """
        original = staging_module.EDITOR_LOCK_SECONDS
        staging_module.EDITOR_LOCK_SECONDS = 2
        try:
            batch = self.make_batch(name="编辑锁过期.txt")
            self.to_review(batch.batch_id)
            self.staging.begin_edit(batch.batch_id, holder="窗口A")

            time.sleep(0.2)
            with self.assertRaises(StagingBusy, msg="still inside EDITOR_LOCK_SECONDS, B must not take over"):
                self.staging.begin_edit(batch.batch_id, holder="窗口B")

            time.sleep(1.9)
            taken = self.staging.begin_edit(batch.batch_id, holder="窗口B")
            self.assertEqual(taken.editor["holder"], "窗口B", "过期后必须允许接管，否则批次永久锁死")
        finally:
            staging_module.EDITOR_LOCK_SECONDS = original

    def test_editor_lock_shorter_than_one_second_is_unusable(self):
        """回归测试 Q-04：时间戳秒级截断让「不足 1 秒的锁」几乎瞬间失效。

        `_iso(stamp)` 把 `since` 截到整秒，于是 `now - since` 比真实持有时间最多多出近 1 秒。
        编辑锁 120s、租约 180s 时这点误差无害；但任何想用「3 秒租约」做短周期
        （DESIGN §10.2 自己就建议用 3 秒来测竞态）的场景，实际可用时间会掉到 2.0~3.0 秒，
        而「1 秒编辑锁」会变成「0~1 秒随机失效」。

        这里用注入时钟把最坏情况钉死：在 12:00:00.999999 进入编辑，
        since 被截成 12:00:00 —— 1 毫秒后就"过期"了。
        """
        clock = {"now": datetime(2026, 1, 5, 12, 0, 0, 999999, tzinfo=timezone.utc)}
        staging = StagingStore(self.settings, lambda: self.vault.dek, clock=lambda: clock["now"])
        original = staging_module.EDITOR_LOCK_SECONDS
        staging_module.EDITOR_LOCK_SECONDS = 1
        try:
            batch = self.make_batch(name="亚秒编辑锁.txt")
            self.to_review(batch.batch_id)
            staging.begin_edit(batch.batch_id, holder="窗口A")

            clock["now"] = clock["now"] + timedelta(milliseconds=1)
            with self.assertRaises(StagingBusy, msg="editor lock considered expired 1ms after take: sub-second locks unusable"):
                staging.begin_edit(batch.batch_id, holder="窗口B")
        finally:
            staging_module.EDITOR_LOCK_SECONDS = original


class ClaimRaceTests(StagingRaceBase):
    def test_two_processes_claim_exactly_one_wins(self):
        """两个真进程同时 `claim`：一个拿租约，另一个 `staging_busy`。"""
        batch = self.make_batch(name="抢认领.txt")
        go = time.time() + 1.5
        first = self.spawn("claim", batch.batch_id, holder="agent-1", start_at=go)
        second = self.spawn("claim", batch.batch_id, holder="agent-2", start_at=go)
        result_a, result_b = self.run_both(first, second)

        wins = int(bool(result_a.get("ok"))) + int(bool(result_b.get("ok")))
        self.assertEqual(wins, 1, f"必须恰好一个认领成功：A={result_a} B={result_b}")
        loser = result_a if not result_a.get("ok") else result_b
        self.assertEqual(loser.get("code"), "staging_busy")

        stored = self.staging.get(batch.batch_id)
        self.assertEqual(stored.status, "refining")
        self.assertIsNotNone(stored.lease)

    def test_configured_lease_seconds_really_applies(self):
        """配置覆盖真的生效：`[staging] lease_seconds = 2` → 租约就是 2 秒，不是 180。"""
        batch = self.make_batch(name="租约配置.txt")
        claimed = self.staging.claim(batch.batch_id, holder="agent")
        expires = datetime.fromisoformat(claimed.lease["expires"])
        acquired = datetime.fromisoformat(claimed.lease["acquired"])
        span = (expires - acquired).total_seconds()
        self.assertLessEqual(span, LEASE_SECONDS, f"租约跨度 {span}s 大于配置的 {LEASE_SECONDS}s")
        self.assertGreater(span, LEASE_SECONDS - 1.5, "租约跨度过短，配置可能没生效")


class LeaseBoundaryTests(StagingRaceBase):
    """租约过期边界：`expires` 前 0.01s / 恰好 / 后 0.01s。"""

    def _wait_until(self, moment: datetime) -> None:
        target = moment.timestamp()
        while True:
            remaining = target - time.time()
            if remaining <= 0:
                return
            time.sleep(min(0.005, remaining))

    def test_boundary_before_and_after_expiry_wallclock(self):
        """真实墙钟：`expires-0.01s` 仍算持有，`expires+0.01s` 必须已过期。"""
        batch = self.make_batch(name="边界.txt")
        claimed = self.staging.claim(batch.batch_id, holder="A")
        expires = datetime.fromisoformat(claimed.lease["expires"])

        self._wait_until(expires - timedelta(seconds=0.01))
        with self.assertRaises(StagingBusy, msg="租约未到期时别人不该能认领"):
            self.staging.claim(batch.batch_id, holder="B")

        self._wait_until(expires + timedelta(seconds=0.01))
        self.assertEqual(
            self.staging.expire_leases(), 1, "租约到期后 expire_leases 应把 refining 回落到 drafted"
        )
        self.assertEqual(self.staging.get(batch.batch_id).status, "drafted")
        self.assertEqual(self.staging.claim(batch.batch_id, holder="B").lease["holder"], "B")

    def test_exact_expiry_instant_is_already_invalid(self):
        """**恰好等于** `expires` 的那一瞬：`_lease_valid` 用严格 `>`，所以此时已经不算持有。

        这一条只能用注入时钟做（真实墙钟打不到「恰好一整秒」），
        它是 `>=` / `>` 语义的唯一确定答案：定为 `>`（到期即失效），与实现一致。
        """
        clock = {"now": datetime(2026, 1, 5, 4, 0, 0, tzinfo=timezone.utc)}
        staging = StagingStore(self.settings, lambda: self.vault.dek, clock=lambda: clock["now"])
        batch = self.make_batch(name="精确边界.txt")
        claimed = staging.claim(batch.batch_id, holder="A", lease_seconds=3)
        expires = datetime.fromisoformat(claimed.lease["expires"])

        clock["now"] = expires - timedelta(microseconds=1)
        self.assertTrue(staging._lease_valid(staging._load_outer(batch.batch_id).get("lease")))

        clock["now"] = expires
        self.assertFalse(
            staging._lease_valid(staging._load_outer(batch.batch_id).get("lease")),
            "恰好等于 expires 时必须已失效（严格 >）",
        )

    def test_seconds_truncation_shrinks_the_lease(self):
        """时间戳 `timespec="seconds"` 会截断小数秒 → 实际租约短于配置值，最多短 1 秒。

        这不是崩溃，但对「3 秒租约」「2 秒编辑锁」这类短周期场景是 50% 的误差；
        本用例把误差量出来，供报告使用（不是失败断言）。
        """
        batch = self.make_batch(name="截断.txt")
        claimed = self.staging.claim(batch.batch_id, holder="A")
        expires = datetime.fromisoformat(claimed.lease["expires"])
        acquired_wall = time.time()
        real_span = expires.timestamp() - acquired_wall
        self.assertGreater(real_span, 0)
        self.assertLessEqual(real_span, LEASE_SECONDS)
        # 记录给报告用：真实可用时长比名义值短多少
        self.assertLess(
            LEASE_SECONDS - real_span, 1.05, f"秒级截断导致的误差 {LEASE_SECONDS - real_span:.2f}s"
        )


class CommitRollbackRaceTests(StagingRaceBase):
    def test_two_processes_commit_same_batch_never_duplicates(self):
        """双击「提交」/ 两个窗口同时点提交：只能入库一次，不许出现重复记录。

        这是 staging 锁 + `status == "committed"` 幂等分支的组合行为；
        工程师的 `test_commit_is_idempotent` 是同一进程里顺序调两次，测不到并发。
        """
        batch = self.make_batch(name="双击提交.txt")
        self.to_review(batch.batch_id)
        go = time.time() + 1.5
        first = self.spawn("commit", batch.batch_id, start_at=go)
        second = self.spawn("commit", batch.batch_id, start_at=go)
        result_a, result_b = self.run_both(first, second)

        for label, result in (("A", result_a), ("B", result_b)):
            self.assertTrue(result.get("ok"), f"并发提交 {label} 失败了：{result}")

        titles = sorted(record.title for record in Vault.open(self.settings, password=PASSWORD).records)
        self.assertEqual(titles, ["京东", "淘宝"], f"并发提交产生了重复记录：{titles}")
        self.assertEqual(self.staging.get(batch.batch_id).status, "committed")
        already = [result for result in (result_a, result_b)
                   if (result.get("result") or {}).get("already_committed")]
        self.assertEqual(len(already), 1, f"应恰有一次性命中幂等分支：{result_a} / {result_b}")

    def test_commit_and_rollback_concurrently_stay_consistent(self):
        """一边 commit、一边 rollback 同一个批次：结果必须自洽。

        允许「rollback 抢在前面 → 报 staging_busy，commit 成功」，
        也允许「commit 先落地 → rollback 撤销成功」。
        不允许「批次显示已入库，但记录缺了」或「显示已撤销，但记录还在」。
        """
        for round_index in range(4):
            batch = self.make_batch(name=f"并发入库{round_index}.txt")
            self.to_review(batch.batch_id)
            go = time.time() + 1.2
            # 前两轮同时开跑（rollback 会撞上未提交态），后两轮让 rollback 晚 0.6s
            # （保证它落在 commit 已落地之后，走真正的撤销路径）。
            undo_at = go if round_index < 2 else go + 0.6
            committer = self.spawn("commit", batch.batch_id, start_at=go)
            undoer = self.spawn("rollback", batch.batch_id, start_at=undo_at)
            committed, rolled = self.run_both(committer, undoer)

            status = self.staging.get(batch.batch_id).status
            fresh = Vault.open(self.settings, password=PASSWORD)
            titles = sorted(record.title for record in fresh.records)

            with self.subTest(round=round_index, commit=committed, rollback=rolled, status=status):
                self.assertIn(status, ("committed", "rolled_back"), f"批次停在中间态：{status}")
                if status == "committed":
                    self.assertEqual(
                        titles,
                        ["京东", "淘宝"],
                        f"批次显示已入库，但库里的记录不完整：{titles}",
                    )
                    self.assertTrue(committed.get("ok"), f"committed 状态但 commit 报了错：{committed}")
                else:
                    self.assertEqual(titles, [], f"批次显示已撤销，但记录还在：{titles}")
                    self.assertTrue(rolled.get("ok"), f"rolled_back 状态但 rollback 报了错：{rolled}")

            # 每一轮用独立的库更接近真实，但为了验证「不会互相看见」只用一次库：
            # 清空以便下一轮断言（直接删库重建代价高，这里按需删记录）
            if titles:
                def drop_all(vault) -> bool:
                    vault.records = []
                    return True

                self.store.mutate(drop_all)


if __name__ == "__main__":
    unittest.main()
