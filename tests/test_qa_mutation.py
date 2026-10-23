"""变异测试（防"假绿"）—— **用语义打桩，不再用字符串替换源码**。

上一版的做法是「把源码里某行字符串替换掉」，它有一个致命毛病：**锚点会漂**。
`locks.py` / `staging.py` / `inbox.py` 一直在重构（本轮里 `inbox.py` 的读侧去重、
`staging.py` 的 `_digest_index`、`config.py` 的 `[staging]` 段都是现改的），
锚点一变，`mutate()` 里那句 `assert occurrences >= count` 就会抛 `AssertionError`，
或者更糟——锚点还在但已经不再是那个语义，变异静默变成空操作，于是**所有测试都绿**，
报告上看起来是「测试有效」，实际上什么都没验。

现在改成**语义打桩**：用 `unittest.mock.patch` 把被测函数的**行为**换掉，
不管源码怎么写、怎么重构，只要语义还在，桩就打得中；语义真被删了，
`patch` 会因为属性不存在而直接报错，同样不会静默。

每条变异都必须先证明两件事：

1. **基线绿**：不打桩时这条测试确实通过（否则"变红"不能归因于变异）；
2. **变异红**：打桩之后确实失败。

如果打桩之后还是绿，本文件不会去调桩把它弄红，而是**如实记一条「这条测试是假的」**
（见 `test_single_scan_three_times_case_is_not_sufficient_alone` 与
`test_read_side_dedup_alone_is_not_covered_by_single_scan_case`）。
"""

from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pwdvault.locks as locks_module
from pwdvault import crypto
from pwdvault.locks import VaultStore
from pwdvault.staging import StagingStore

SKIP_ENV = "PV_QA_SKIP_MUTATION"


class MutationBase(unittest.TestCase):
    """在**当前进程内**跑指定单条测试，可以套 `mock.patch`。"""

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get(SKIP_ENV):
            raise unittest.SkipTest(f"{SKIP_ENV}=1，跳过变异测试")

    # ------------------------------------------------------------ 工具
    @staticmethod
    def run_one(target: str) -> unittest.TestResult:
        suite = unittest.TestLoader().loadTestsFromName(target)
        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=0)
        result = runner.run(suite)
        # 让失败信息在断言里可读：这是变异检测的「证据」
        MutationBase.last_output = stream.getvalue()
        return result

    def assert_baseline_green(self, target: str) -> None:
        result = self.run_one(target)
        self.assertGreaterEqual(result.testsRun, 1, f"目标 {target} 一条用例都没加载到")
        self.assertTrue(
            result.wasSuccessful(),
            f"基线（没打桩）上 {target} 就没过，变异结论无效：{self.last_output[-1500:]}",
        )

    def assert_mutation_detected(self, target: str, patchers: list, *, why: str) -> None:
        self.assert_baseline_green(target)
        with ExitStack() as stack:
            for patcher in patchers:
                stack.enter_context(patcher)
            result = self.run_one(target)
        self.assertGreaterEqual(result.testsRun, 1)
        self.assertFalse(
            result.wasSuccessful(),
            f"【假绿】{why} 之后 `{target}` 仍然通过 —— 这条测试测不到它声称要测的东西。"
            f"输出：{self.last_output[-1500:]}",
        )

    def assert_mutation_survives(self, target: str, patchers: list, *, why: str) -> None:
        """变异之后**仍然绿**，且这是有正当理由的（被另一层兜住了）。

        这条用来把「弱测试」与「纵深防御」区分开：如果不去显式记下它，
        下一个人看到「变异没打死」时无法判断是哪一种。
        """
        self.assert_baseline_green(target)
        with ExitStack() as stack:
            for patcher in patchers:
                stack.enter_context(patcher)
            result = self.run_one(target)
        self.assertTrue(
            result.wasSuccessful(),
            f"这条用例现在能测出「{why}」了 —— 它已经不再冗余，请删除本用例。"
            f"输出：{self.last_output[-1500:]}",
        )


# =====================================================================  锁
class LockMutationTests(MutationBase):
    def test_reentrancy_shortcut_is_actually_required(self) -> None:
        """`test_reentrant_same_thread` 必须真的依赖「同线程不碰文件锁」这条短路。

        变异：让 `hold()` 每次都想拿 `threading.local` 里的深度本（`_thread_book`）
        拿到一个**空**字典 —— 于是第二层重入短路永远走不到，同线程第二次 `hold`
        会拿同一个文件的另一个句柄去 `msvcrt.locking`，必然冲突。
        """
        self.assert_mutation_detected(
            "tests.test_locks.LockManagerTests.test_reentrant_same_thread",
            [
                mock.patch.object(
                    locks_module,
                    "_thread_book",
                    lambda: {},
                    create=True,
                )
            ],
            why="关掉 hold() 的同线程重入短路（深度本永远为空）",
        )

    def test_lock_rebase_is_actually_required(self) -> None:
        """`test_rebase_no_overlap_both_applied` 必须真的依赖锁内的 `_reload()`。

        变异：`VaultStore._reload()` 直接返回内存里的旧对象 —— 等价于
        「commit 在锁内不重读库」，别人刚写进去的记录就看不见了。
        """
        self.assert_mutation_detected(
            "tests.test_locks.VaultStoreCommitTests.test_rebase_no_overlap_both_applied",
            [mock.patch.object(VaultStore, "_reload", lambda self: self._vault)],
            why="commit 在锁内不再 reload（rebase 消失）",
        )


# =====================================================================  暂存区
class StagingMutationTests(MutationBase):
    def test_aad_batch_binding_is_actually_required(self) -> None:
        """`test_sealed_cannot_move_between_batches` 必须真的依赖 AAD 里的 batch_id。

        变异：AAD 里把 batch_id 换成常量 —— 于是把 A 批次的密文搬到 B 批次文件里
        仍然能解开，用例期待的那个 `AuthenticationFailed` 就不会出现。
        """
        self.assert_mutation_detected(
            "tests.test_staging.EncryptionTests.test_sealed_cannot_move_between_batches",
            [
                mock.patch.object(
                    StagingStore,
                    "_aad",
                    lambda self, batch_id, vault_id: crypto.make_aad(vault_id, "staging/shared"),
                )
            ],
            why="AAD 去掉 batch_id（跨批次搬运不再失败）",
        )


# =====================================================================  inbox 去重
class InboxMutationTests(MutationBase):
    RESTART = "tests.test_inbox.ScanIdempotencyTests.test_rescan_after_restart_still_one_batch"
    THREE_TIMES = "tests.test_inbox.ScanIdempotencyTests.test_scan_three_times_creates_one_batch"

    def test_digest_index_is_really_covered(self) -> None:
        """`_digest_index()` 恒返回空 → 重启场景（内存全丢）必须变红。

        重启后墓碑为空、`_seen` 为空，跨重启去重唯一的数据来源就是这个索引
        （读侧快照与锁内二次确认都以它为数据源）。它一空，同一份文件会建出第二批。
        """
        self.assert_mutation_detected(
            self.RESTART,
            [mock.patch.object(StagingStore, "_digest_index", lambda self: {})],
            why="关掉「按 sha256 索引已建批次」这一层去重",
        )

    def test_read_side_snapshot_is_redundant_with_lock_recheck(self) -> None:
        """只关读侧快照（`batches_by_hash()`）时用例**仍然**绿 —— 这是纵深防御，不是假绿。

        `scan_once()` 在进锁前取的 `known` 快照被清空之后，`create_from_file()` 里
        那次**锁内** `_digest_index()` 二次确认（Q-05 的修复）仍然把它挡住了。
        如实记下来：读侧快照单独失效不会造成重复建批。
        """
        self.assert_mutation_survives(
            self.RESTART,
            [mock.patch.object(StagingStore, "batches_by_hash", lambda self: {})],
            why="关掉读侧的 sha256 快照（锁内二次确认仍在）",
        )

    def test_single_scan_case_does_not_cover_index_layer(self) -> None:
        """**弱测试（Q-07，测试强度问题，不是产品缺陷）**：

        `test_scan_three_times_creates_one_batch` 在「读侧快照被关掉」之后依然绿 ——
        它实际验证的是 `_seen` 集合 + 锁内二次确认，而不是它名字暗示的「三重去重」。
        """
        self.assert_mutation_survives(
            self.THREE_TIMES,
            [mock.patch.object(StagingStore, "batches_by_hash", lambda self: {})],
            why="关掉「按 sha256 索引已建批次」这一层去重",
        )

    def test_all_dedup_layers_off_makes_the_module_red(self) -> None:
        """再把锁内二次确认的数据源也关掉，`tests.test_inbox` 必须整体变红。

        这条是「单条弱测试 ≠ 整模块弱」的反证：模块层面确实咬住了去重。
        """
        self.assert_mutation_detected(
            "tests.test_inbox",
            [
                mock.patch.object(StagingStore, "_digest_index", lambda self: {}),
                mock.patch.object(StagingStore, "seen_hashes", lambda self: set()),
            ],
            why="索引层（含锁内二次确认）+ 墓碑层同时关闭",
        )


if __name__ == "__main__":
    unittest.main()
