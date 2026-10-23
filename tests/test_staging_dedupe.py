"""`create_from_file()` 三层判重的回归钉子。

## 为什么需要这个文件

`staging.create_from_file()` 现在是**唯一**的建批入口，判重分三层：

    第 1 层  dedupe_index（调用方那一轮的 sha256→batch_id 快照）—— 便宜，但可能是进锁前的状态
    第 2 层  self._digest_index()（锁内读真实目录，按文件名增量缓存）—— **权威层**
    第 3 层  都没命中 → 新建

第 2 层不能省。第 1 层是「进锁之前」的快照：两个进程同时扫同一份文件时，两边的快照都会
读到「还没有这个 sha256」，于是各建一批 —— 这正是 Q-05 的窗口，跨进程唯一可靠的判重点
只有锁内。`known_hashes` → `dedupe_index` 改名、以及第 2 层那次 `_digest_index()` 调用，
在代码里只有两行，看起来极其像「重复劳动」，很容易被下一个维护者顺手简化掉。

而「简化掉了」这件事**很难被发现**：只有跨进程用例会红，而那条用例本身有时序抖动
（`test_qa_inbox.py` 里跑两个真进程），一次偶发红很容易被当成环境问题重跑掉。

所以这里用**单进程、确定性**的用例把第 2 层单独钉住：删掉那两行，本文件必红。

## 覆盖

1. 第 1 层未命中 → 必须回退到第 2 层（**核心**，且**冷实例**，等于跨进程对手刚建完批）
2. 第 1 层命中 → 走快路径，**不许重扫目录**（批量扫描 500 个文件时这是性能命门）
3. 第 1 层未命中、磁盘也没有 → 正常新建，并**回登记**进传入的 dict（否则同一轮里
   后续文件会重复判重）
4. `discard` 之后同一份内容能重新建批（墓碑 vs 目录缓存的冲突点）

## 约定

- 只读 `staging.py` 的公开行为，**不打桩它的内部方法**（除了第 2 条里为了证明
  「没被调用」而替换 `_digest_index`），这样内部重构不会让本文件失效。
- 不 import `inbox`，也不起子进程：这里要的是确定性，不是并发覆盖。
"""

from __future__ import annotations

import hashlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support
from pwdvault.models import Record
from pwdvault.staging import StagingStore

# 一份「像密码库文本」的固定内容：sha256 稳定，便于断言
CONTENT_A = "淘宝 zhangsan\nPw-A-9f2c1d\n密保问题：故乡\n"
CONTENT_B = "京东 lisi\nPw-B-4a7e88\n"
CONTENT_C = "知乎 wangwu\nPw-C-1b3f22\n"


class _Clock:
    """可注入时钟：让 `created`/`updated` 可预测，且每次调用前进 1 秒。

    不用真实时钟：本文件要断的是判重，不是时间。前进 1 秒是为了避免
    「两个批次时间戳完全相同」干扰排查时的可读性。
    """

    def __init__(self) -> None:
        self.moment = datetime(2026, 1, 5, 4, 31, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.moment
        self.moment = self.moment + timedelta(seconds=1)
        return current


class DedupeBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        fixture = support.make_vault(self.home, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        self.dek: dict = {"value": self.vault.dek}
        self.clock = _Clock()
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.staging = self.new_store()

    # ---------------------------------------------------------------- 工具
    def new_store(self) -> StagingStore:
        """新实例 = 进程内索引全空。用来模拟「另一个进程已经建过批」的冷启动视角。"""
        return StagingStore(
            self.settings,
            lambda: self.dek["value"],
            clock=self.clock,
        )

    def make_file(self, name: str, text: str) -> Path:
        self.inbox.mkdir(parents=True, exist_ok=True)
        path = self.inbox / name
        path.write_text(text, encoding="utf-8")
        return path

    @staticmethod
    def digest_of(path: Path) -> str:
        """判重用的 sha256 —— **必须从文件字节算**，不能从 `text.encode()` 算。

        坑：`create_from_file` 的 digest 是 `path.read_bytes()` 的 sha256，而 Windows 上
        `Path.write_text()` 会把 `\\n` 写成 `\\r\\n`。所以「我传进去的字符串」和
        「盘上的字节」不是同一份内容，从字符串算出来的 digest 永远匹配不上。
        （本文件第一版就是这么写的，于是「第 1 层命中」的桩根本没被走到，
        看起来像产品缺陷，其实是夹具算错了。记在这里省下一个人半小时。）
        """
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def create(self, store: StagingStore, path: Path, text: str, *, index=None):
        return store.create_from_file(
            path=path,
            text=text,
            drafts=[Record(title="淘宝", username="u1", password="Pw-A-9f2c1d")],
            origin="local",
            dedupe_index=index,
        )

    def batch_files(self) -> list[Path]:
        return sorted(self.settings.staging_dir.glob("sb_*.enc"))

    def batch_count(self) -> int:
        return len(self.batch_files())


# ---------------------------------------------------------------- ① 核心
class LayerTwoFallbackTests(DedupeBase):
    """第 1 层未命中时，必须回退到锁内的 `_digest_index()`（第 2 层）。"""

    def test_layer_two_is_consulted_when_caller_snapshot_misses(self) -> None:
        """**本文件最重要的一条。**

        场景 = 跨进程判重的单进程等价物：
          进程 A 建了 sha256=X 的批次；
          进程 B 冷启动，它那一轮的 `dedupe_index` 是空快照（{}），所以第 1 层必 miss；
          只有第 2 层（锁内读真实目录）能救——命中就返回既有批次，不新建。

        如果有人删掉 `existing_id = self._digest_index().get(digest)` 那一行，
        这里会从 `deduped=True + 1 个批次` 变成 `deduped=False + 2 个批次`。
        下面第二条用例就是这句话的可执行证明。
        """
        path = self.make_file("同一份.txt", CONTENT_A)
        first = self.create(self.staging, path, CONTENT_A)
        self.assertFalse(first.deduped, "第一次建批不该是 dedupe")
        self.assertEqual(self.batch_count(), 1)

        # 冷实例：`_outer_index` 为空，等价于「另一个进程刚建完一批」
        cold = self.new_store()
        again = self.create(cold, path, CONTENT_A, index={})

        self.assertTrue(again.deduped, "第 1 层未命中时必须回退到锁内目录判重（第 2 层）")
        self.assertEqual(again.batch_id, first.batch_id, "必须返回既有批次，而不是新建")
        self.assertEqual(self.batch_count(), 1, "磁盘上多出了一个批次 = 判重破了")
        self.assertEqual(again.sha256, self.digest_of(path))

    def test_without_layer_two_dedup_really_breaks(self) -> None:
        """反向证明：把第 2 层掐掉，上一条用例守的性质**真的会破**。

        做法是把 `_digest_index()` 桩成空表 —— 效果等价于「删掉那一行
        `existing_id = self._digest_index().get(digest)`」，但**不需要改被测源码、
        也不依赖任何源码文本**，所以不会被下一次重构打红。
        （这比把源码字符串替换掉再跑的变异测试更耐久：它测的是行为，不是排版。）

        如果哪天这条**开始失败**（即掐掉第 2 层也不重复建批），说明判重又多了一条
        我们不知道的兜底路径 —— 那也是需要有人来解释的变化。
        """
        path = self.make_file("掐掉第2层.txt", CONTENT_A)
        self.create(self.staging, path, CONTENT_A)
        self.assertEqual(self.batch_count(), 1)

        cold = self.new_store()
        with mock.patch.object(cold, "_digest_index", return_value={}):
            orphan = self.create(cold, path, CONTENT_A, index={})

        self.assertFalse(
            orphan.deduped,
            "第 2 层被掐掉之后居然还能判重 —— 说明还有别的兜底，用例的前提变了",
        )
        self.assertEqual(
            self.batch_count(),
            2,
            "掐掉第 2 层后应产生重复批次；若没有，说明上一条用例其实没在守第 2 层",
        )

    def test_layer_two_works_even_when_caller_snapshot_maps_other_digest(self) -> None:
        """第 1 层有内容但**不含**这个 digest 时，同样必须回退到第 2 层。

        真实场景：同一轮扫描里已经建过 B 的批次，index 里只有 B 的条目；
        这时又遇到 A（其实是跨进程重复），第 1 层 miss，仍要靠第 2 层。
        """
        path_a = self.make_file("A.txt", CONTENT_A)
        path_b = self.make_file("B.txt", CONTENT_B)
        first_a = self.create(self.staging, path_a, CONTENT_A)
        self.assertEqual(self.create(self.staging, path_b, CONTENT_B).deduped, False)

        cold = self.new_store()
        again = self.create(
            cold,
            path_a,
            CONTENT_A,
            index={self.digest_of(path_b): "sb_whatever"},
        )
        self.assertTrue(again.deduped)
        self.assertEqual(again.batch_id, first_a.batch_id)
        self.assertEqual(self.batch_count(), 2)


# ---------------------------------------------------------------- ② 快路径
class LayerOneFastPathTests(DedupeBase):
    """第 1 层命中时必须走快路径：不许再扫一遍 staging 目录。"""

    def test_layer_one_hit_does_not_rescan_directory(self) -> None:
        """500 文件扫描的性能命门：每建一批都重扫目录 = O(n²)。"""
        path = self.make_file("快路径.txt", CONTENT_A)
        first = self.create(self.staging, path, CONTENT_A)
        digest = self.digest_of(path)

        cold = self.new_store()
        with mock.patch.object(cold, "_digest_index", return_value={}) as spy:
            hit = self.create(cold, path, CONTENT_A, index={digest: first.batch_id})

        self.assertTrue(hit.deduped)
        self.assertEqual(hit.batch_id, first.batch_id)
        self.assertFalse(
            spy.called,
            "第 1 层命中却还去扫了目录 —— O(n²) 就是这么回来的",
        )
        self.assertEqual(self.batch_count(), 1)


# ---------------------------------------------------------------- ③ 回登记
class IndexRegistrationTests(DedupeBase):
    """第 1 层未命中且磁盘也没有 → 新建后必须把 sha256→id 写回传入的 dict。"""

    def test_new_batch_is_registered_back_into_caller_index(self) -> None:
        path = self.make_file("新内容.txt", CONTENT_C)
        index: dict[str, str] = {}
        created = self.create(self.new_store(), path, CONTENT_C, index=index)

        self.assertFalse(created.deduped)
        digest = self.digest_of(path)
        self.assertEqual(
            index.get(digest),
            created.batch_id,
            "新建的批次没有回登记 —— 同一轮扫描里后续文件会重复判重",
        )
        self.assertEqual(self.batch_count(), 1)

    def test_registered_index_prevents_second_batch_in_same_round(self) -> None:
        """回登记的直接价值：同一轮里再遇到同一份内容，走第 1 层就够（不必问磁盘）。"""
        path = self.make_file("同轮重复.txt", CONTENT_C)
        index: dict[str, str] = {}
        first = self.create(self.new_store(), path, CONTENT_C, index=index)
        self.assertFalse(first.deduped)

        cold = self.new_store()
        with mock.patch.object(cold, "_digest_index", return_value={}) as spy:
            second = self.create(cold, path, CONTENT_C, index=index)
        self.assertTrue(second.deduped)
        self.assertEqual(second.batch_id, first.batch_id)
        self.assertFalse(spy.called, "回登记生效时不该再问磁盘")
        self.assertEqual(self.batch_count(), 1)


# ---------------------------------------------------------------- ④ 墓碑
class DiscardThenReimportTests(DedupeBase):
    """`discard` 之后，同一份内容必须能**重新建批**。

    这条是「墓碑（tombstones.json）与目录增量缓存（`_digest_index`）会不会打架」的
    探针：`_digest_index()` 扫的是 `sb_*.enc` 全部批次文件，被丢弃的批次**文件仍在**
    （`discard` 只改状态、写墓碑、可选删源文件），如果判重路径不看状态/墓碑，
    就会把「已丢弃」的那一批当成「已存在」返回 —— 用户丢掉的东西又自己回来了。
    """

    def test_discard_allows_reimport_of_same_content(self) -> None:
        """丢弃过的批次**不**再算「已存在」—— 顺着判重拿回来等于把用户丢掉的东西塞回去。

        这里曾经是 `@unittest.expectedFailure`（2026-10-23 作为已知缺陷记录）。现状是
        已修复，于是摘掉装饰器改成普通断言 —— 反转方向是修复的一部分，不是放宽。

        被丢弃的批次**文件仍在盘上**（`discard` 只改状态 + 写墓碑，默认不删源文件），
        所以判重路径必须看状态，光看「文件在不在」会把它当成已存在递回来。
        """
        path = self.make_file("丢弃后重来.txt", CONTENT_B)
        first = self.create(self.staging, path, CONTENT_B)
        self.assertFalse(first.deduped)

        self.staging.discard(first.batch_id)
        self.assertEqual(self.staging.get(first.batch_id).status, "discarded")

        # 机理：被丢弃的批次必须从判重索引里消失（只改状态、文件还在也在所不惜）
        self.assertIsNone(
            self.new_store()._digest_index().get(self.digest_of(path)),
            "丢弃的批次不该还出现在判重索引里",
        )

        # 冷实例 + 空快照：把第 1 层摘掉，逼判重去问真实目录
        cold = self.new_store()
        again = self.create(cold, path, CONTENT_B, index={})

        self.assertFalse(
            again.deduped,
            "丢弃之后又重新命中旧批次：用户丢掉的东西自己回来了",
        )
        self.assertNotEqual(again.batch_id, first.batch_id, "必须是一个新批次")
        self.assertEqual(self.batch_count(), 2, "旧批次文件仍在，新批次应额外多一个")

    def test_discard_then_reimport_in_a_long_lived_process(self) -> None:
        """**真实用户就在这一条上**：Web / MCP 是长驻进程，同一个 store 实例活很久。

        `_digest_index()` 为了不让「一次扫 500 个文件」退化成 O(n²)，会把
        `文件名 → (sha256, batch_id, status)` 缓存下来，之后**按缓存读、不再碰磁盘**。
        于是只改磁盘上的 status 是不够的 —— 缓存里那份若不跟着变，长驻进程会一直
        把这个批次当成它「刚被扫过时」的状态，上一条的修复就只在重启后才生效。

        只有「这个批次被读过至少一次」才会复现，所以用例里必须先预热缓存。
        """
        path = self.make_file("长驻进程重来.txt", CONTENT_B)
        store = self.staging

        store._digest_index()  # 预热：让后续批次文件进入缓存
        batch = self.create(store, path, CONTENT_B)
        store._digest_index()  # 把这一批也缓存住，此时 status 还是 drafted
        store.discard(batch.batch_id)

        again = self.create(store, path, CONTENT_B, index={})
        self.assertFalse(
            again.deduped,
            "长驻进程里缓存的 status 没跟着状态变更同步 —— 丢弃的批次又回来了",
        )
        self.assertNotEqual(again.batch_id, batch.batch_id, "必须是一个新批次")


if __name__ == "__main__":
    unittest.main()
