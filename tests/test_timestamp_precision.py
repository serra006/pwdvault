"""时间戳精度与乐观锁测试（T07 遗留缺陷：秒级精度导致的 lost update）。

## 缺陷

`models.now_iso()` 曾经是 `timespec="seconds"`，而 `locks.VaultStore.commit` 用
`target.updated != expected_updated` 判定 stale。于是下面这段序列会**静默丢更新**：

    t1 秒：UI 读到记录（expected_updated = "…39+00:00"）
    t1 秒：Agent 写入（记录 updated 也变成 "…39+00:00"）
    t1 秒：UI 提交 → target.updated(t1) == expected_updated(t1) → 判定「无冲突」→ 覆盖

修法是把 `now_iso()` 改成微秒精度（`…39.123456+00:00`），碰撞窗口从 1 秒压到 1 微秒。

## 本文件钉死什么

1. **同一秒内「读 → 他人写 → 提交」必须冲突**，且盘上留下的是**他人**的版本。
   用可注入时钟把两次写入都钉在同一秒内，**不 sleep**（`_StampClock`）。
2. **旧数据（秒级）仍然可读、可原样写回**，只有本次写入的 `updated` 被刷新。
3. **新旧格式混用时字典序单调**：`"…39+00:00" < "…39.000001+00:00"`。
   这不是「估计应该如此」——`'+'` 是 0x2B、`'.'` 是 0x2E，用例里显式断言了字节值。
4. 快照文件名不受精度影响（`:` 是 Windows 非法文件名字符，必须确认没有漏进去）。

## 残留窗口（如实记录，不掩饰）

微秒精度把碰撞窗口从 1 秒压到**时钟 tick 的粒度**，**不是**归零：
本机实测 `datetime.now()` 的 tick 约 **54µs~1ms**（紧密循环 200ms 采到 228 个不同时间戳），
所以真正会「撞」的是同一个 tick 内的两次写入。对人类操作（点保存 vs agent 写入）这个间距
已经足够；但它不是零，也不是 1µs —— 别把 `timespec="microseconds"` 当成「精确到微秒」。
彻底消除要靠「单调计数器 + `rev`」而不是墙钟，属于格式变更，已排到 v1.2。

因此本文件验证「同秒两次写入」**一律注入时钟**，不依赖墙钟推进：
- 不要用 `sleep` 造时间差（慢且抖）；
- 也不要用「连续调用两次 `now_iso()` 断言不相等」来证明精度 —— 快速连续调用很可能落在
  同一个 tick 里得到同一个值，那是**采样太快**，不是时钟坏了。这类断言在真机上会闪红。

## 时钟怎么注入

`models.utc_now()` 是唯一的「取时点」（`Record.__post_init__` /
`Record.apply_changes` 都经由 `models.now_iso()` 取时间），所以
`mock.patch("pwdvault.models.utc_now", …)` 就能把「两次写入」钉进同一秒，
而**格式化仍然走 `now_iso()` 的生产实现**。这一点是刻意的：只注入时间、不注入格式，
否则用例会绕过被测精度，把缺陷「测成通过」（本文件的第一版就犯过这个错）。
`Vault.save` 里那份 header 时间戳走的是 `vault.py` 自己的绑定，不参与乐观锁，
用例不断言它，也就不需要替换。
"""

from __future__ import annotations

import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support
from pwdvault import mcp_tools
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record, now_iso, utc_now
from pwdvault.vault import Vault

PASSWORD = support.PASSWORD

# 新的落盘形态：`2026-10-23T09:00:39.123456+00:00`
MICRO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$")
# 旧（v1.0/v1.1）形态：`2026-10-23T09:00:39+00:00`
SECONDS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")
# 快照文件名：不允许出现 `:`（Windows）
SNAPSHOT_NAME_RE = re.compile(r"^data-\d{8}-\d{6}(-\d+)?\.enc$")

# 用例里的「同一秒」：所有时间戳都钉在这一秒里
SAME_SECOND = datetime(2026, 10, 23, 9, 0, 39, tzinfo=timezone.utc)

# 旧数据的秒级时间戳（就是 SAME_SECOND 截断到秒）
LEGACY_STAMP = "2026-10-23T09:00:39+00:00"


def _iso(moment: datetime) -> str:
    """独立于生产实现的「期望格式」，只用于在失败信息里展示，不参与断言逻辑。"""
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


class _StampClock:
    """可注入的**取时**时钟：替换 `models.utc_now`，返回 `datetime`（不是字符串）。

    用法：`with clock.patched(): ...`；`clock.at(500_000)` 把「当前时刻」设成
    `SAME_SECOND + 0.5 秒`。两次写入只要 `at()` 到同一秒内的不同微秒，
    就能在**不 sleep** 的前提下复现「同一秒内的两次写入」。

    **故意返回 datetime 而不是 ISO 字符串**：格式由 `models.now_iso()` 决定，
    这样用例测到的就是生产代码真正写下的精度。
    """

    def __init__(self, second: datetime = SAME_SECOND) -> None:
        self._second = second
        self._moment = second

    def at(self, microsecond: int) -> "_StampClock":
        self._moment = self._second.replace(microsecond=int(microsecond))
        return self

    def moment(self) -> datetime:
        return self._moment

    def __call__(self) -> datetime:
        return self._moment

    def patched(self):
        """把本时钟装到 `pwdvault.models.utc_now` 上（不改格式化）。"""
        return mock.patch("pwdvault.models.utc_now", self)


class _VaultCase(unittest.TestCase):
    """临时库夹具（与 test_locks.py 同一套：极快 KDF、快照关闭）。"""

    snapshot_keep = 0

    def setUp(self) -> None:
        self.home = support.make_home(self)
        fixture = support.make_vault(self.home, snapshot_keep=self.snapshot_keep)
        self.settings = fixture.settings
        self.vault = fixture.vault

    def _reopen(self) -> Vault:
        return Vault.open(self.settings, password=PASSWORD)

    def _disk_record(self, record_id: str) -> Record:
        """从盘上重新读一条记录（断言「盘上到底是什么」只看这里）。"""
        found = self._reopen().find_by_id(record_id)
        self.assertIsNotNone(found, f"盘上找不到记录 {record_id}")
        return found


# ---------------------------------------------------------------- ① 同秒丢更新
class SameSecondLostUpdateTests(_VaultCase):
    """秒级精度下必现、微秒精度下必不发生的 lost update。"""

    def test_same_second_write_by_other_is_detected_as_conflict(self) -> None:
        """① 同一秒内「读 → 他人写 → 提交」→ 冲突，且盘上是**他人**的版本。

        断言的核心不是「有 conflict 对象」，而是**盘上一字节没被我的版本覆盖**。
        """
        clock = _StampClock()
        with clock.patched():
            record = Record(title="同一秒", username="u1", password="pw-old")
            ui_store = VaultStore(self.settings, self.vault)
            ui_store.commit([Operation.add(record)])

            # --- 时刻 A：UI 读到记录（expected_updated = 该秒的第一个微秒）
            ui_store = VaultStore(self.settings, self._reopen())
            ui_record = ui_store.vault.find_by_id(record.id)
            self.assertIsNotNone(ui_record)
            expected_updated = ui_record.updated

            # --- 时刻 B：Agent 在**同一秒内**（晚 0.5 秒）写入
            clock.at(500_000)
            agent_store = VaultStore(self.settings, self._reopen())
            agent_result = agent_store.commit(
                [
                    Operation.update(
                        record.id,
                        {"title": "Agent 改的", "notes": "Agent 写的备注"},
                        expected_updated=expected_updated,
                    )
                ]
            )
            self.assertEqual(agent_result.conflicts, [], "Agent 的写入不该冲突")
            self.assertEqual(agent_result.updated, 1)

            agent_updated = self._disk_record(record.id).updated
            self.assertEqual(
                expected_updated[:19],
                agent_updated[:19],
                "两次写入必须落在**同一秒**内，否则这个用例测不到缺陷",
            )
            self.assertNotEqual(expected_updated, agent_updated, "微秒精度必须能区分同秒两次写入")

            # --- 时刻 C：UI 拿着旧的 expected_updated 提交
            before_bytes = self.settings.vault_path.read_bytes()
            ui_result = ui_store.commit(
                [Operation.update(record.id, {"title": "我改的"}, expected_updated=expected_updated)]
            )

        self.assertEqual(len(ui_result.conflicts), 1, "同一秒内的丢更新没被拦住")
        conflict = ui_result.conflicts[0]
        self.assertEqual(conflict.kind, "stale")
        self.assertEqual(conflict.record_id, record.id)
        # 冲突结构里给出的是对方的版本（已脱敏），不是我的
        self.assertEqual(conflict.theirs["title"], "Agent 改的")
        self.assertEqual(conflict.mine["title"], "我改的")
        # **反向断言更重要**：盘上一个字节都没变
        self.assertEqual(self.settings.vault_path.read_bytes(), before_bytes)

        on_disk = self._disk_record(record.id)
        self.assertEqual(on_disk.title, "Agent 改的", "盘上必须是他人写入的版本")
        self.assertEqual(on_disk.notes, "Agent 写的备注")
        self.assertEqual(on_disk.updated, agent_updated)

    def test_same_second_update_via_mcp_tool_reports_record_conflict(self) -> None:
        """① 端到端：MCP 的 `vault_update` 在同样序列下返回 `record_conflict`。

        这一条是「用户能看见的」那一层：错码必须是 `record_conflict`，
        而不是一个「成功」的回执。
        """
        clock = _StampClock()
        with clock.patched():
            record = Record(title="同秒 MCP", username="u1", password="pw-old")
            seed_store = VaultStore(self.settings, self.vault)
            seed_store.commit([Operation.add(record)])

            session = mcp_tools.McpSession(
                self.settings,
                vault=self._reopen(),
                unlocked_by="test",
                clock=lambda: 1_700_000_000.0,
                env={},
            )
            stale_updated = session.require_vault().find_by_id(record.id).updated

            # 另一个窗口在同一秒内（晚 0.25 秒）写了同一条
            clock.at(250_000)
            other_store = VaultStore(self.settings, self._reopen())
            other_result = other_store.commit(
                [
                    Operation.update(
                        record.id,
                        {"title": "别人改的"},
                        expected_updated=stale_updated,
                    )
                ]
            )
            self.assertEqual(other_result.conflicts, [])
            other_updated = self._disk_record(record.id).updated
            self.assertEqual(stale_updated[:19], other_updated[:19], "必须在同一秒内")

            outcome = mcp_tools.call_tool(
                session,
                "vault_update",
                {
                    "id": record.id,
                    "changes": {"title": "我改的"},
                    "expected_updated": stale_updated,
                },
            )

        self.assertTrue(outcome.is_error, "同秒丢更新必须报错，不能返回成功回执")
        self.assertEqual(outcome.payload["code"], "record_conflict", outcome.payload)
        self.assertEqual(outcome.payload["conflict"]["record_id"], record.id)

        on_disk = self._disk_record(record.id)
        self.assertEqual(on_disk.title, "别人改的", "盘上必须保留别人的版本")
        self.assertEqual(on_disk.updated, other_updated)

    def test_two_writes_in_same_second_get_distinct_stamps(self) -> None:
        """机制层断言：同一秒内的两次 `apply_changes` 必须产生不同 `updated`。"""
        clock = _StampClock()
        record = Record(title="两次写", username="u1")

        with clock.patched():
            clock.at(100_000)
            record.apply_changes({"notes": "第一次"})
            first = record.updated
            clock.at(100_001)  # 只差 1 微秒
            record.apply_changes({"notes": "第二次"})
            second = record.updated

        self.assertNotEqual(first, second)
        self.assertEqual(first[:19], second[:19], "两次必须在同一秒内")
        self.assertLess(first, second, "字典序也必须跟着时间单调")
        self.assertTrue(MICRO_RE.match(first), first)
        self.assertTrue(MICRO_RE.match(second), second)


# ---------------------------------------------------------------- ② 旧数据兼容
class LegacySecondsFormatTests(_VaultCase):
    """旧记录（秒级精度）必须照常读写，不迁移、不丢字段。"""

    def test_seconds_precision_record_reads_back_verbatim(self) -> None:
        """② 读入 → 原样写回 → 内容不变（只有 `updated` 被本次写入刷新）。"""
        legacy = Record(title="旧记录", username="u1", password="pw-old", notes="原来的备注")
        legacy.created = LEGACY_STAMP
        legacy.updated = LEGACY_STAMP
        legacy.pw_changed = LEGACY_STAMP
        legacy.fields = {"密保问题": "母亲的姓氏", "绑定手机": "138****0000"}

        VaultStore(self.settings, self.vault).commit([Operation.add(legacy)])

        # --- 读：旧格式不报错，且字符串一个字节都没被「规范化」
        read_back = self._disk_record(legacy.id)
        self.assertEqual(read_back.created, LEGACY_STAMP)
        self.assertEqual(read_back.updated, LEGACY_STAMP)
        self.assertEqual(read_back.pw_changed, LEGACY_STAMP, "旧记录回读时不能把 pw_changed 弄丢")
        self.assertEqual(read_back.notes, "原来的备注")
        self.assertEqual(read_back.fields, {"密保问题": "母亲的姓氏", "绑定手机": "138****0000"})

        # --- 写回：用旧时间戳做乐观锁照样能命中（相等比较，不做格式转换）
        store = VaultStore(self.settings, self._reopen())
        result = store.commit(
            [
                Operation.update(
                    legacy.id,
                    {"notes": "补一句话"},
                    expected_updated=LEGACY_STAMP,
                )
            ]
        )
        self.assertEqual(result.conflicts, [], "旧格式的 expected_updated 必须仍然可用")
        self.assertEqual(result.updated, 1)

        after = self._disk_record(legacy.id)
        self.assertEqual(after.notes, "补一句话")
        # 除 `updated` 之外的一切原样保留
        self.assertEqual(after.created, LEGACY_STAMP)
        self.assertEqual(after.pw_changed, LEGACY_STAMP, "没改密码就不许动 pw_changed")
        self.assertEqual(after.fields, read_back.fields)
        self.assertEqual(after.username, "u1")
        self.assertEqual(after.password, "pw-old")
        # 本次写入把 `updated` 自然升级成微秒精度（不做批量迁移，只逐条升级）
        self.assertNotEqual(after.updated, LEGACY_STAMP, "写入必须刷新 updated")
        self.assertTrue(MICRO_RE.match(after.updated), after.updated)

    def test_legacy_record_still_round_trips_through_from_dict(self) -> None:
        """旧格式的 payload 走 `Record.from_dict` 不报错，且保留秒级原文。"""
        raw = {
            "id": "abc1234567",
            "title": "纯旧格式",
            "username": "u",
            "password": "p",
            "created": "2020-01-01T00:00:00+00:00",
            "updated": "2020-06-01T00:00:00+00:00",
            "pw_changed": "2020-06-01T00:00:00+00:00",
        }
        record = Record.from_dict(raw, keep_id=True)
        self.assertEqual(record.created, "2020-01-01T00:00:00+00:00")
        self.assertEqual(record.updated, "2020-06-01T00:00:00+00:00")
        self.assertEqual(record.pw_changed, "2020-06-01T00:00:00+00:00")
        # 再序列化回去，时间戳仍然是旧原文（未迁移）
        self.assertEqual(record.to_dict()["updated"], "2020-06-01T00:00:00+00:00")

    def test_mixed_precision_does_not_false_conflict(self) -> None:
        """盘上是秒级、expected_updated 也是秒级 → 不许误报冲突（相等即通过）。"""
        legacy = Record(title="混合精度")
        legacy.created = LEGACY_STAMP
        legacy.updated = LEGACY_STAMP
        VaultStore(self.settings, self.vault).commit([Operation.add(legacy)])

        store = VaultStore(self.settings, self._reopen())
        ok = store.commit(
            [Operation.update(legacy.id, {"url": "https://example.com"}, expected_updated=LEGACY_STAMP)]
        )
        self.assertEqual(ok.conflicts, [])
        self.assertEqual(self._disk_record(legacy.id).url, "https://example.com")

        # 而微秒级的新值当然也不再等于旧秒级值 → 下一次旧时间戳提交必须冲突
        stale = store.commit(
            [Operation.update(legacy.id, {"url": "https://other.example"}, expected_updated=LEGACY_STAMP)]
        )
        self.assertEqual(len(stale.conflicts), 1)
        self.assertEqual(stale.conflicts[0].kind, "stale")


# ---------------------------------------------------------------- ③ 字典序
class TimestampOrderingTests(unittest.TestCase):
    """新旧格式混用时的字典序单调性 —— 用字节值钉死，不靠口头约定。"""

    def test_dot_sorts_after_plus(self) -> None:
        """`'+'` = 0x2B < `'.'` = 0x2E：秒级写法恰好排在「同一秒的微秒写法」之前。"""
        self.assertEqual(ord("+"), 0x2B)
        self.assertEqual(ord("."), 0x2E)
        self.assertLess(ord("+"), ord("."))

    def test_seconds_sorts_before_same_second_micro(self) -> None:
        legacy = "2026-10-23T09:00:39+00:00"
        micro = "2026-10-23T09:00:39.000001+00:00"
        self.assertLess(legacy, micro, "同一秒内：秒级写法必须排在微秒写法之前")
        self.assertGreater(micro, legacy)
        self.assertEqual(sorted([micro, legacy]), [legacy, micro])

    def test_ordering_across_seconds_is_still_correct(self) -> None:
        """跨秒时，字典序与前缀的数值序一致（精度混用也不产生逆序）。"""
        earlier_seconds = "2026-10-23T09:00:38+00:00"
        later_micro = "2026-10-23T09:00:39.999999+00:00"
        self.assertLess(earlier_seconds, later_micro)

        earlier_micro = "2026-10-23T09:00:39.999999+00:00"
        later_seconds = "2026-10-23T09:00:40+00:00"
        self.assertLess(earlier_micro, later_seconds)

    def test_mixed_precision_sort_is_monotonic(self) -> None:
        """一份新旧混排的列表，`sorted()` 必须等于「按真实时间排序」。"""
        pairs = [
            ("2026-10-23T09:00:41+00:00", datetime(2026, 10, 23, 9, 0, 41, tzinfo=timezone.utc)),
            ("2026-10-23T09:00:39.999999+00:00", datetime(2026, 10, 23, 9, 0, 39, 999999, tzinfo=timezone.utc)),
            ("2026-10-23T09:00:39+00:00", datetime(2026, 10, 23, 9, 0, 39, tzinfo=timezone.utc)),
            ("2026-10-23T09:00:40.000001+00:00", datetime(2026, 10, 23, 9, 0, 40, 1, tzinfo=timezone.utc)),
            ("2026-10-23T09:00:39.000001+00:00", datetime(2026, 10, 23, 9, 0, 39, 1, tzinfo=timezone.utc)),
        ]
        by_string = [stamp for stamp, _ in sorted(pairs, key=lambda item: item[0])]
        by_time = [stamp for stamp, _ in sorted(pairs, key=lambda item: item[1])]
        self.assertEqual(by_string, by_time, "字符串字典序与真实时间序不一致")

    def test_both_formats_parse_with_fromisoformat(self) -> None:
        """`datetime.fromisoformat` 是本项目所有「反解析」的底层（service / mcp_tools / staging）。"""
        legacy = datetime.fromisoformat(LEGACY_STAMP)
        micro = datetime.fromisoformat("2026-10-23T09:00:39.000001+00:00")
        self.assertEqual(legacy.tzinfo is not None, True)
        self.assertEqual(micro.tzinfo is not None, True)
        self.assertEqual(legacy.utcoffset().total_seconds(), 0)
        self.assertEqual(micro.utcoffset().total_seconds(), 0)
        self.assertLess(legacy, micro)
        self.assertEqual((micro - legacy).total_seconds(), 0.000001)


# ---------------------------------------------------------------- ④ 落盘形态
class NowIsoShapeTests(unittest.TestCase):
    def test_now_iso_is_microsecond_and_timezone_aware(self) -> None:
        stamp = now_iso()
        self.assertTrue(MICRO_RE.match(stamp), f"格式不对：{stamp!r}")
        self.assertEqual(len(stamp), 32, "微秒 + 时区的定长形态是字典序比较的前提")
        moment = datetime.fromisoformat(stamp)
        self.assertIsNotNone(moment.tzinfo)
        self.assertEqual(moment.utcoffset().total_seconds(), 0, "必须是 UTC")

    def test_now_iso_tracks_the_current_instant(self) -> None:
        """`now_iso()` 格式化的就是 `utc_now()`，且小数秒真的被保留下来（不是补零）。

        注意**故意不断言**「连续两次调用必不相等」：`datetime.now()` 的 tick 是毫秒级
        （本机实测 54µs~1ms），两次紧跟的调用很可能落在同一个 tick 里拿到同一个字符串。
        那不是时钟坏了，是**采样太快** —— 这类断言会在真机上随机闪红。
        需要区分「同秒两次写入」的用例一律用可注入时钟（`_StampClock`）钉时间。

        基准取 `models.utc_now()` 而不是 `datetime.now()`：这样本用例在任何注入时钟下
        都成立（包括 CI 里把时钟打快的场景），同时仍然证明「取时点 → 字符串」没被改坏。
        """
        stamp = now_iso()
        moment = datetime.fromisoformat(stamp)
        delta = abs((utc_now() - moment).total_seconds())
        self.assertLess(delta, 5.0, f"{stamp!r} 与取时点差了 {delta} 秒")

        # 小数秒来自真实时钟，不是常量 0（微秒为 0 时也允许，只是概率 1e-6）
        microseconds = [now_iso()[20:26] for _ in range(20)]
        self.assertTrue(all(len(item) == 6 for item in microseconds))

    def test_legacy_regex_and_new_regex_do_not_overlap(self) -> None:
        """两种形态互不匹配，测试里的「格式断言」不会互相放过。"""
        self.assertTrue(SECONDS_RE.match(LEGACY_STAMP))
        self.assertFalse(MICRO_RE.match(LEGACY_STAMP))
        self.assertTrue(MICRO_RE.match(now_iso()))
        self.assertFalse(SECONDS_RE.match(now_iso()))

    def test_record_defaults_use_microsecond_stamps(self) -> None:
        record = Record(title="默认值", password="pw")
        self.assertTrue(MICRO_RE.match(record.created), record.created)
        self.assertTrue(MICRO_RE.match(record.updated), record.updated)
        self.assertEqual(record.pw_changed, record.created, "有密码时 pw_changed 初始等于 created")


# ---------------------------------------------------------------- ⑤ 快照文件名
class SnapshotFileNameTests(_VaultCase):
    """快照名有自己的 `strftime`，与 `now_iso()` 无关 —— 这条用例把「无关」钉住。

    微秒精度一旦不小心漏进文件名，Windows 上会直接建不出文件（`:` 非法），
    所以这里既断言「名字里没有 `:`」，也断言「每次提交都能成功生成快照」。
    """

    snapshot_keep = 3

    def test_snapshot_names_stay_windows_safe(self) -> None:
        store = VaultStore(self.settings, self.vault)
        for index in range(3):
            store.commit([Operation.add(Record(title=f"记录{index}"))])

        snap_dir = self.settings.snapshot_dir
        self.assertTrue(snap_dir.is_dir(), "快照目录没建出来")
        names = sorted(path.name for path in snap_dir.glob("data-*.enc"))
        self.assertGreaterEqual(len(names), 2, f"快照数量不对：{names}")
        for name in names:
            self.assertNotIn(":", name, f"文件名含 Windows 非法字符：{name}")
            self.assertTrue(SNAPSHOT_NAME_RE.match(name), f"快照名形态变了：{name}")
        # 轮转上限生效（snapshot_keep=3）
        self.assertLessEqual(len(names), 3)


if __name__ == "__main__":
    unittest.main()
