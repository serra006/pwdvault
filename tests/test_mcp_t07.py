"""T07 测试：MCP 整理/写工具、空闲自锁、审计，以及「回执不许说谎」的安全修复。

本文件覆盖 10 条验收：
  ① `staging_list` 不含正文（哨兵不出现）
  ② `claim` 拿到 raw_text + 租约，二次 claim → staging_busy
  ③ `submit` 在 review / reviewing 被拒
  ④ `add(dry_run=true)` 不写库（revision 与条数都不变），`dry_run=false` 才写库且写审计
  ⑤ `update` 缺 expected_updated → 参数错误；过期 → record_conflict 且盘上未被覆盖
  ⑥ 解锁链三档（locked / vault_not_found / vault_corrupt）各一例
  ⑦ 空闲自锁：推进注入时钟 → 再次调用会重新解锁（mock 计数）
  ⑧ audit.jsonl 全文搜不到任何哨兵值
  ⑨ 五个高危工具名 → -32602 Unknown tool
 ⑩ 剪贴板：spawn=False 不起子进程、到点清空、被第三方改动则不清空

原则：不真 sleep 30 秒（用 0.05 秒 + `threading.Event().wait()`）；不碰真实剪贴板
（全部 mock）；时间可注入。
"""

from __future__ import annotations

import ast
import io
import json
import os
import sys
import threading
import unittest
from contextlib import redirect_stderr
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import audit, clipboard, mcp_server, mcp_tools, service
from pwdvault.config import Settings
from pwdvault.errors import CorruptVault, Locked, VaultNotFound
from pwdvault.locks import VaultStore
from pwdvault.models import Record
from pwdvault.vault import Vault, read_revision

PASSWORD = support.PASSWORD
SHORT_WINDOW = 0.05  # 极短窗口：只要 50ms，不真等 30 秒


class SilentTimer:
    """记录参数但**永不触发**的假 Timer：避免测试留下真实的 30 秒线程。"""

    instances: list["SilentTimer"] = []

    def __init__(self, delay, function, *args, **kwargs) -> None:
        del args, kwargs
        self.delay = float(delay)
        self.function = function
        self.daemon = False
        self.started = False
        SilentTimer.instances.append(self)

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:  # pragma: no cover - 只是补齐接口
        self.started = False


# ---------------------------------------------------------------- 公共夹具
class Clock:
    """可注入时钟（秒）。所有「过了多久」的断言都靠它，绝不真 sleep。"""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.value = float(start)

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += float(seconds)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        self.fixture = support.make_vault(self.home)
        self.settings = self.fixture.settings
        self.vault = self.fixture.vault
        self.clock = Clock()
        self.session = mcp_tools.McpSession(
            self.settings,
            vault=self.vault,
            unlocked_by="test",
            clock=self.clock,
            env={},
        )
        self.audit_file = audit.audit_path(self.settings)

    # ------------------------------------------------------------ 便捷
    def call(self, name: str, arguments: dict | None = None) -> mcp_tools.ToolOutcome:
        return mcp_tools.call_tool(self.session, name, arguments or {})

    def payload(self, name: str, arguments: dict | None = None) -> dict:
        outcome = self.call(name, arguments)
        self.assertFalse(outcome.is_error, outcome.payload)
        return outcome.payload

    def failure(self, name: str, arguments: dict | None = None) -> dict:
        outcome = self.call(name, arguments)
        self.assertTrue(outcome.is_error, outcome.payload)
        return outcome.payload

    def audit_lines(self) -> list[dict]:
        if not self.audit_file.is_file():
            return []
        text = self.audit_file.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def audit_text(self) -> str:
        if not self.audit_file.is_file():
            return ""
        return self.audit_file.read_text(encoding="utf-8")

    def make_batch(self, *, text: str, drafts: list[Record], name: str = "旧账号.txt") -> str:
        """在 inbox 里放一个文件并建成一个待整理批次（走真实的 create_from_file）。"""
        inbox = self.settings.inbox_path
        inbox.mkdir(parents=True, exist_ok=True)
        path = inbox / name
        path.write_text(text, encoding="utf-8")
        store = self.session.staging()
        batch = store.create_from_file(path=path, text=text, drafts=drafts, origin="local")
        return batch.batch_id


# ---------------------------------------------------------------- ① 列表
class StagingListTest(Base):
    def test_list_has_no_body_text(self) -> None:
        """① 列表只有元数据：源文件正文与草稿值都不能出现。"""
        text = f"淘宝 zhangsan\n{support.SENTINEL_PW}\n"
        batch_id = self.make_batch(
            text=text,
            drafts=[Record(title="淘宝", username="zhangsan", password=support.SENTINEL_PW)],
        )
        payload = self.payload("vault_staging_list")
        body = json.dumps(payload, ensure_ascii=False)

        self.assertEqual(payload["count"], 1)
        row = payload["batches"][0]
        self.assertEqual(set(row), {"id", "source_file", "status", "item_count", "origin", "age_seconds"})
        self.assertEqual(row["id"], batch_id)
        self.assertEqual(row["source_file"], "旧账号.txt")
        self.assertEqual(row["status"], "drafted")
        self.assertEqual(row["item_count"], 1)
        self.assertEqual(row["origin"], "local")
        self.assertGreaterEqual(row["age_seconds"], 0)

        self.assertNotIn(support.SENTINEL_PW, body, "列表泄露了正文/草稿值")
        self.assertNotIn("zhangsan", body, "列表泄露了账号")
        keys = set()

        def collect(node) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    keys.add(key)
                    collect(value)
            elif isinstance(node, list):
                for item in node:
                    collect(item)

        collect(payload)
        for forbidden in ("raw_text", "items", "draft", "record", "password", "notes", "fields"):
            self.assertNotIn(forbidden, keys)

    def test_list_empty_is_not_error(self) -> None:
        payload = self.payload("vault_staging_list")
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["batches"], [])
        self.assertIn("hint", payload)

    def test_list_parameter_error(self) -> None:
        with self.assertRaises(mcp_tools.InvalidArguments):
            self.call("vault_staging_list", {"whatever": 1})


# ---------------------------------------------------------------- ② claim
class StagingClaimTest(Base):
    def test_claim_returns_raw_text_and_drafts_without_values(self) -> None:
        """② 认领拿到 raw_text 与租约；草稿里的密码恒为掩码。"""
        batch_id = self.make_batch(
            text="淘宝 zhangsan\n（密码见下）\n",
            drafts=[Record(title="淘宝", username="zhangsan", password=support.SENTINEL_PW)],
        )
        payload = self.payload("vault_staging_claim", {"batch_id": batch_id})

        self.assertEqual(payload["batch_id"], batch_id)
        self.assertEqual(payload["status"], "refining")
        self.assertEqual(payload["lease_seconds"], 180)
        self.assertIn("zhangsan", payload["raw_text"])
        self.assertIn("next_step", payload)

        self.assertEqual(len(payload["local_draft"]), 1)
        draft = payload["local_draft"][0]
        self.assertEqual(draft["title"], "淘宝")
        self.assertEqual(draft["username"], "zhangsan")
        self.assertTrue(draft["has_password"])
        self.assertNotIn("password", draft, "草稿里连掩码都不给，避免误读")
        self.assertIsInstance(payload["warnings"], list)
        self.assertGreaterEqual(payload["max_items_hint"], 1)

        body = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(support.SENTINEL_PW, body, "认领响应泄露了草稿里的密码")

    def test_second_claim_is_busy(self) -> None:
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        self.payload("vault_staging_claim", {"batch_id": batch_id})
        payload = self.failure("vault_staging_claim", {"batch_id": batch_id})
        self.assertEqual(payload["code"], "staging_busy")

    def test_claim_unknown_batch(self) -> None:
        payload = self.failure("vault_staging_claim", {"batch_id": "sb_不存在"})
        self.assertEqual(payload["code"], "staging_not_found")

    def test_claim_lease_is_capped(self) -> None:
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        payload = self.payload(
            "vault_staging_claim", {"batch_id": batch_id, "lease_seconds": mcp_tools.MAX_LEASE_SECONDS}
        )
        self.assertEqual(payload["lease_seconds"], mcp_tools.MAX_LEASE_SECONDS)

    def test_claim_while_locked_does_not_touch_batch(self) -> None:
        """锁着时认领必须直接报 locked，且**不能**把批次改成 refining。"""
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        before = self.session.staging().get(batch_id).status

        locked = mcp_tools.McpSession(self.settings, env={})
        outcome = mcp_tools.call_tool(locked, "vault_staging_claim", {"batch_id": batch_id})
        self.assertTrue(outcome.is_error)
        self.assertEqual(outcome.payload["code"], "locked")

        self.assertEqual(
            self.session.staging().get(batch_id).status,
            before,
            "认领失败不能留下 refining/租约这种半截状态",
        )

    def test_claim_parameter_errors(self) -> None:
        for bad in (
            {},
            {"batch_id": ""},
            {"batch_id": 5},
            {"batch_id": "sb_x", "lease_seconds": 0},
            {"batch_id": "sb_x", "lease_seconds": 601},
            {"batch_id": "sb_x", "lease_seconds": 1.5},
        ):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_staging_claim", bad)


# ---------------------------------------------------------------- ③ submit
class StagingSubmitTest(Base):
    def test_submit_writes_drafts_only(self) -> None:
        batch_id = self.make_batch(
            text="淘宝 zhangsan\n",
            drafts=[Record(title="旧标题", username="zhangsan")],
        )
        before_count = len(self.session.vault.records)
        before_rev = read_revision(self.settings.vault_path)

        self.payload("vault_staging_claim", {"batch_id": batch_id})
        payload = self.payload(
            "vault_staging_submit",
            {
                "batch_id": batch_id,
                "records": [
                    {"title": "淘宝", "username": "zhangsan", "password": support.SENTINEL_PW},
                    {"title": "京东", "username": "lisi", "url": "https://jd.com"},
                ],
                "summary": "从旧账号.txt 归纳出 2 条",
            },
        )

        self.assertEqual(payload["batch_id"], batch_id)
        self.assertEqual(payload["status"], "review")
        self.assertEqual(payload["item_count"], 2)
        self.assertEqual(payload["accepted"], 2)
        self.assertEqual(len(payload["warnings_by_item"]), 2)
        self.assertNotIn(support.SENTINEL_PW, json.dumps(payload, ensure_ascii=False))

        # 只写草稿：库文件一个字节都没变
        self.assertEqual(len(self.session.vault.records), before_count)
        self.assertEqual(read_revision(self.settings.vault_path), before_rev)

    def test_submit_rejected_while_review(self) -> None:
        """③ 批次进入 review 后再交回 → staging_busy（文案说明正在人工编辑）。"""
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        self.payload("vault_staging_claim", {"batch_id": batch_id})
        self.payload(
            "vault_staging_submit", {"batch_id": batch_id, "records": [{"title": "淘宝"}]}
        )

        payload = self.failure(
            "vault_staging_submit", {"batch_id": batch_id, "records": [{"title": "淘宝"}]}
        )
        self.assertEqual(payload["code"], "staging_busy")
        self.assertIn("人工编辑", payload["message"])

    def test_submit_rejected_while_reviewing(self) -> None:
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        store = self.session.staging()
        self.payload("vault_staging_claim", {"batch_id": batch_id})
        self.payload(
            "vault_staging_submit", {"batch_id": batch_id, "records": [{"title": "淘宝"}]}
        )
        store.begin_edit(batch_id, holder="ui")

        payload = self.failure(
            "vault_staging_submit", {"batch_id": batch_id, "records": [{"title": "淘宝"}]}
        )
        self.assertEqual(payload["code"], "staging_busy")
        self.assertIn("人工编辑", payload["message"])

    def test_submit_without_claim_is_busy(self) -> None:
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        payload = self.failure(
            "vault_staging_submit", {"batch_id": batch_id, "records": [{"title": "淘宝"}]}
        )
        self.assertEqual(payload["code"], "staging_busy")

    def test_submit_empty_records_is_parameter_error(self) -> None:
        batch_id = self.make_batch(text="正文\n", drafts=[Record(title="淘宝")])
        for bad in (
            {},
            {"batch_id": batch_id},
            {"batch_id": batch_id, "records": []},
            {"batch_id": batch_id, "records": "nope"},
            {"batch_id": batch_id, "records": ["nope"]},
            {"batch_id": batch_id, "records": [{"title": "x"}], "unknown": 1},
        ):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_staging_submit", bad)

        # 全空对象 → 无法推断标题 → 业务错误（invalid_record），不是参数错误
        payload = self.failure("vault_staging_submit", {"batch_id": batch_id, "records": [{}]})
        self.assertEqual(payload["code"], "invalid_record")


# ---------------------------------------------------------------- ④ add
class AddToolTest(Base):
    def test_dry_run_does_not_touch_vault(self) -> None:
        """④ dry_run=true 时条数与 revision 都不变，且真的返回 warnings。"""
        before_count = len(self.session.vault.records)
        before_rev = read_revision(self.settings.vault_path)

        payload = self.payload(
            "vault_add",
            {
                "record": {
                    "title": "新站点",
                    "username": "13800138000",
                    "password": "short",
                }
            },
        )

        self.assertTrue(payload["dry_run"], "dry_run 默认必须是 true")
        self.assertFalse(payload["created"])
        self.assertTrue(payload["warnings"], "手机号账号至少应有一条 info 级提示")
        self.assertTrue(any(row["code"] == "phone_username" for row in payload["warnings"]))
        self.assertEqual(len(self.session.vault.records), before_count)
        self.assertEqual(read_revision(self.settings.vault_path), before_rev)
        self.assertIn("hint", payload)
        # 试运行不写任何业务审计
        self.assertEqual([line for line in self.audit_lines() if line["action"] == "add"], [])

    def test_real_add_writes_record_and_audit(self) -> None:
        before_count = len(self.session.vault.records)
        before_rev = read_revision(self.settings.vault_path)
        payload = self.payload(
            "vault_add",
            {
                "record": {
                    "title": "新站点",
                    "username": "zhangsan",
                    "password": support.SENTINEL_PW,
                    "备注": "随手记",
                },
                "dry_run": False,
            },
        )

        self.assertFalse(payload["dry_run"])
        self.assertTrue(payload["created"])
        self.assertEqual(payload["count"], before_count + 1)
        self.assertGreaterEqual(payload["revision"], before_rev + 1)

        reopened = Vault.open(self.settings, password=PASSWORD)
        created = reopened.find_by_id(payload["id"])
        self.assertIsNotNone(created, "写库后必须能按 id 读回")
        self.assertEqual(created.meta.get("origin"), "agent_written")
        self.assertEqual(created.meta.get("written_by"), "agent")
        self.assertNotIn("agent_written", created.fields, "来源标记绝不能污染 fields")

        rows = self.audit_lines()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "add")
        self.assertEqual(rows[0]["record_id"], payload["id"])
        self.assertEqual(rows[0]["actor"], "agent")

    def test_add_without_title_is_invalid(self) -> None:
        # 所有字段都为空 → 无法推断标题 → invalid_record（业务错误，不是参数错误）
        payload = self.failure("vault_add", {"record": {"password": ""}})
        self.assertEqual(payload["code"], "invalid_record")

    def test_add_duplicate_is_refused_even_when_not_dry_run(self) -> None:
        self.payload(
            "vault_add",
            {
                "record": {"title": "淘宝", "username": "zhangsan", "password": "pw-one"},
                "dry_run": False,
            },
        )
        before = len(self.session.vault.records)
        payload = self.failure(
            "vault_add",
            {
                "record": {"title": "淘宝", "username": "zhangsan", "password": "pw-two"},
                "dry_run": False,
            },
        )
        self.assertEqual(payload["code"], "invalid_record")
        self.assertIn("duplicate_record", payload["message"])
        self.assertEqual(len(Vault.open(self.settings, password=PASSWORD).records), before)

    def test_add_parameter_errors(self) -> None:
        for bad in ({}, {"record": "nope"}, {"record": "nope", "dry_run": True}, {"record": {}, "dry_run": "yes"}):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_add", bad)


# ---------------------------------------------------------------- ⑤ update
class UpdateToolTest(Base):
    def _seed(self) -> dict:
        self.payload(
            "vault_add",
            {
                "record": {"title": "待改", "username": "u1", "password": support.SENTINEL_PW},
                "dry_run": False,
            },
        )
        detail = self.payload("vault_get", {"query": "待改"})
        return detail

    def test_missing_expected_updated_is_parameter_error(self) -> None:
        detail = self._seed()
        with self.assertRaises(mcp_tools.InvalidArguments):
            self.call("vault_update", {"id": detail["id"], "changes": {"title": "新标题"}})

    def test_update_ok(self) -> None:
        detail = self._seed()
        payload = self.payload(
            "vault_update",
            {
                "id": detail["id"],
                "changes": {"title": "改好了", "备注": "补一句"},
                "expected_updated": detail["updated"],
            },
        )
        self.assertTrue(payload["updated"])
        self.assertEqual(payload["id"], detail["id"])

        reopened = Vault.open(self.settings, password=PASSWORD)
        self.assertEqual(reopened.find_by_id(detail["id"]).title, "改好了")
        actions = [line for line in self.audit_lines() if line["action"] == "update"]
        self.assertEqual({line["field_name"] for line in actions}, {"title", "备注"})

    def test_stale_update_conflicts_and_does_not_overwrite(self) -> None:
        """⑤ expected_updated 过期 → record_conflict，盘上保持原来的版本。

        `updated` 自 T07 缺陷修复起是**微秒**精度（`models.now_iso()`），同一秒内的
        两次写入已经能被乐观锁区分（同秒丢更新见 `test_timestamp_precision.py`）。
        本用例仍然用「一个明显过期的旧时间戳」来表达 stale：要验的是「比对逻辑 +
        不覆盖」，不是时钟分辨率。
        """
        detail = self._seed()
        before = Vault.open(self.settings, password=PASSWORD).find_by_id(detail["id"])
        before_updated = before.updated

        payload = self.failure(
            "vault_update",
            {
                "id": detail["id"],
                "changes": {"title": "我改的"},
                "expected_updated": "2000-01-01T00:00:00+00:00",
            },
        )
        self.assertEqual(payload["code"], "record_conflict")
        self.assertEqual(payload["conflict"]["record_id"], detail["id"])
        self.assertIn("theirs", payload["conflict"])
        body = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(support.SENTINEL_PW, body, "冲突结构泄露了密码")

        after = Vault.open(self.settings, password=PASSWORD).find_by_id(detail["id"])
        self.assertEqual(after.title, before.title, "绝不许静默覆盖")
        self.assertEqual(after.updated, before_updated, "被拒绝的写入连时间戳都不许动")

    def test_update_uses_other_windows_version_as_theirs(self) -> None:
        """两个窗口：B 先改，A 拿着旧时间戳提交 → 冲突里给出脱敏后的 theirs。"""
        detail = self._seed()
        stale_updated = detail["updated"]

        # 另一个窗口改同一条（时间戳钉到不同的秒，让乐观锁能区分两次写入）
        other = VaultStore(self.settings, Vault.open(self.settings, password=PASSWORD))
        with other.lock.hold(purpose="test"):
            target = other.vault.find_by_id(detail["id"])
            target.apply_changes({"title": "别人改的"})
            target.updated = "2030-01-01T00:00:00+00:00"
            other.vault.save()

        payload = self.failure(
            "vault_update",
            {"id": detail["id"], "changes": {"title": "我改的"}, "expected_updated": stale_updated},
        )
        self.assertEqual(payload["code"], "record_conflict")
        self.assertEqual(payload["conflict"]["theirs"]["title"], "别人改的")
        self.assertNotIn(support.SENTINEL_PW, json.dumps(payload, ensure_ascii=False))

        reopened = Vault.open(self.settings, password=PASSWORD).find_by_id(detail["id"])
        self.assertEqual(reopened.title, "别人改的", "盘上必须保留别人的版本")
        self.assertEqual(reopened.updated, "2030-01-01T00:00:00+00:00")

    def test_update_unknown_id(self) -> None:
        payload = self.failure(
            "vault_update",
            {"id": "0000000000", "changes": {"title": "x"}, "expected_updated": "2020-01-01T00:00:00+00:00"},
        )
        self.assertEqual(payload["code"], "record_not_found")

    def test_update_rejects_system_fields(self) -> None:
        detail = self._seed()
        for changes in ({"id": "x"}, {"created": "x"}, {"meta": {"origin": "web"}}):
            with self.subTest(changes=changes):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call(
                        "vault_update",
                        {"id": detail["id"], "changes": changes, "expected_updated": detail["updated"]},
                    )

    def test_update_parameter_errors(self) -> None:
        detail = self._seed()
        for bad in (
            {},
            {"id": detail["id"]},
            {"id": detail["id"], "changes": {}, "expected_updated": detail["updated"]},
            {"id": detail["id"], "changes": "nope", "expected_updated": detail["updated"]},
            {"id": detail["id"], "changes": {"title": ["a"]}, "expected_updated": detail["updated"]},
            {"id": detail["id"], "changes": {"title": "x"}, "expected_updated": ""},
        ):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_update", bad)


# ---------------------------------------------------------------- ⑥ 解锁链
class UnlockChainTest(unittest.TestCase):
    def test_locked(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        with self.assertRaises(Locked) as ctx:
            mcp_tools.unlock_chain(fixture.settings, env={})
        self.assertEqual(ctx.exception.code, "locked")

    def test_vault_not_found(self) -> None:
        home = support.make_home(self)
        settings = Settings(vault_path=home / "data.enc", kdf=dict(support.FAST_KDF))
        with self.assertRaises(VaultNotFound) as ctx:
            mcp_tools.unlock_chain(settings, env={})
        self.assertEqual(ctx.exception.code, "vault_not_found")

    def test_vault_corrupt(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        fixture.settings.vault_path.write_text("{ 这不是 JSON", encoding="utf-8")
        with self.assertRaises(CorruptVault) as ctx:
            mcp_tools.unlock_chain(fixture.settings, env={})
        self.assertEqual(ctx.exception.code, "vault_corrupt")

        session = mcp_tools.McpSession(fixture.settings, env={})
        outcome = mcp_tools.call_tool(session, "vault_search", {"query": "淘宝"})
        self.assertTrue(outcome.is_error)
        self.assertEqual(outcome.payload["code"], "vault_corrupt")

    def test_env_still_works(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        vault, how = mcp_tools.unlock_chain(
            fixture.settings, env={mcp_tools.ENV_MASTER_PASSWORD: support.PASSWORD}
        )
        self.assertEqual(how, "env")
        self.assertIsNotNone(vault)


# ---------------------------------------------------------------- ⑦ 空闲自锁
class IdleAutoLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        self.fixture = support.make_vault(self.home)
        self.settings = replace(
            self.fixture.settings, mcp_auto_lock_seconds=SHORT_WINDOW
        )
        self.clock = Clock()
        self.session = mcp_tools.McpSession(
            self.settings,
            vault=self.fixture.vault,
            clock=self.clock,
            env={},
        )

    def test_activity_within_threshold_keeps_dek(self) -> None:
        with mock.patch.object(mcp_tools, "unlock_chain", side_effect=AssertionError("不该解锁")):
            mcp_tools.call_tool(self.session, "vault_search", {"query": "x"})
            self.clock.advance(SHORT_WINDOW / 2)
            mcp_tools.call_tool(self.session, "vault_search", {"query": "x"})
        self.assertEqual(self.session.auto_lock_count, 0)

    def test_idle_past_threshold_relocks_and_unlocks_again(self) -> None:
        """⑦ 推进时钟越过阈值 → 再调一次会重新走解锁链（mock 计数）。"""
        calls: list[float] = []

        def fake_unlock(settings, *, env=None):
            calls.append(self.clock.value)
            return self.fixture.vault, "env"

        with mock.patch.object(mcp_tools, "unlock_chain", side_effect=fake_unlock):
            first = mcp_tools.call_tool(self.session, "vault_search", {"query": "x"})
            self.assertFalse(first.is_error)
            self.assertEqual(calls, [], "进程内已有 DEK 时不该解锁")

            self.clock.advance(SHORT_WINDOW + 0.5)
            second = mcp_tools.call_tool(self.session, "vault_search", {"query": "x"})
            self.assertFalse(second.is_error)
            self.assertEqual(len(calls), 1, "空闲超时后必须重新解锁一次")

            self.clock.advance(SHORT_WINDOW + 0.5)
            mcp_tools.call_tool(self.session, "vault_search", {"query": "x"})
            self.assertEqual(len(calls), 2)

        self.assertEqual(self.session.auto_lock_count, 2)

    def test_auto_lock_reported_by_status(self) -> None:
        payload = mcp_tools.call_tool(self.session, "vault_status", {}).payload
        self.assertEqual(payload["auto_lock_in_seconds"], int(SHORT_WINDOW))
        self.assertTrue(payload["unlocked"])

    def test_zero_window_never_locks(self) -> None:
        settings = replace(self.settings, mcp_auto_lock_seconds=0)
        session = mcp_tools.McpSession(settings, vault=self.fixture.vault, clock=self.clock, env={})
        with mock.patch.object(mcp_tools, "unlock_chain", side_effect=AssertionError("不该解锁")):
            mcp_tools.call_tool(session, "vault_status", {})
            self.clock.advance(3600)
            mcp_tools.call_tool(session, "vault_status", {})
        self.assertEqual(session.auto_lock_count, 0)


# ---------------------------------------------------------------- ⑧ 审计
class AuditTest(Base):
    def setUp(self) -> None:
        super().setUp()
        self.payload(
            "vault_add",
            {
                "record": {
                    "title": "审计哨兵",
                    "username": "audit-user",
                    "password": support.SENTINEL_PW,
                    "notes": support.SENTINEL_NOTE,
                },
                "dry_run": False,
            },
        )
        self.record_id = self.payload("vault_get", {"query": "审计哨兵"})["id"]

    def test_entry_whitelist_is_enforced(self) -> None:
        entry = audit.build_entry(action="copy", record_id="abc", field_name="password", count=1)
        self.assertEqual(set(entry), set(audit.ENTRY_KEYS))
        self.assertEqual(entry["action"], "copy")
        self.assertIn("export", audit.ACTIONS, "导出明文必须是一个可审计的动作（O-1）")
        with self.assertRaises(ValueError):
            audit.build_entry(action="no-such-action")  # 不在白名单
        with self.assertRaises(ValueError):
            audit.build_entry(action="copy", actor="root")

    def test_append_refuses_unknown_action_when_not_strict(self) -> None:
        """`PV_AUDIT_STRICT=0` 时降级：不抛、不写、只在 stderr 留一行。

        默认（严格模式）下未知动作会抛 `RuntimeError`，因为「未知动作」的真实含义是
        「某条高危行为根本没进审计」。降级模式只留给明确不想被审计打断的场景。
        """
        before = len(self.audit_lines())
        with mock.patch.dict(os.environ, {audit.AUDIT_STRICT_ENV: "0"}):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                ok = audit.append(self.settings, action="no-such-action", record_id="x")
        self.assertFalse(ok)
        self.assertIn("审计写入失败", stderr.getvalue())
        self.assertEqual(len(self.audit_lines()), before, "非法动作不该写出任何一行")

    def test_append_raises_on_unknown_action_by_default(self) -> None:
        """严格模式（默认）：枚举写错必须当场炸，不许被 stderr 噪音吞掉。"""
        self.assertTrue(audit.is_strict(), "默认必须是严格模式")
        with self.assertRaises(RuntimeError):
            audit.append(self.settings, action="no-such-action", record_id="x")

    def test_no_sentinel_anywhere_in_audit(self) -> None:
        """⑧ audit.jsonl 全文搜不到任何哨兵；只有 id 与字段名。"""
        # 再多打几次会写审计的动作（Timer 换成不触发的假实现，避免留下真线程）
        token = "clipboard-value-" + support.SENTINEL_PW
        with mock.patch.object(clipboard, "copy_text") as copy_text, mock.patch.object(
            clipboard, "read_text", return_value=token
        ), mock.patch("threading.Timer", SilentTimer):
            self.payload("vault_copy", {"id": self.record_id, "field": "password"})
        self.assertTrue(copy_text.called)

        text = self.audit_text()
        self.assertIn(self.record_id, text, "审计里必须能看到 record id")
        self.assertIn("password", text, "审计里必须能看到字段名")
        for sentinel in (
            support.SENTINEL_PW,
            support.SENTINEL_CUSTOM,
            support.SENTINEL_NOTE,
            "audit-user",
        ):
            self.assertNotIn(sentinel, text, f"审计文件泄露了 {sentinel}")

        rows = self.audit_lines()
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(set(row) <= set(audit.ENTRY_KEYS), row)
        self.assertEqual({row["action"] for row in rows} >= {"add", "copy", "reveal"}, True)

    def test_custom_field_name_is_recorded_not_value(self) -> None:
        secret_field = "*ApiKey"
        self.payload(
            "vault_add",
            {
                "record": {"title": "带密钥字段", secret_field: support.SENTINEL_CUSTOM},
                "dry_run": False,
            },
        )
        detail = self.payload("vault_get", {"query": "带密钥字段"})
        self.payload(
            "vault_update",
            {
                "id": detail["id"],
                "changes": {secret_field: "rotated-value"},
                "expected_updated": detail["updated"],
            },
        )
        text = self.audit_text()
        self.assertIn(secret_field, text, "字段名应该被记下来")
        self.assertNotIn("rotated-value", text, "字段值绝不能被记下来")
        self.assertNotIn(support.SENTINEL_CUSTOM, text)

    def test_write_failure_degrades_to_stderr(self) -> None:
        blocker = Path(self.settings.logs_dir)
        if blocker.exists():  # 让 logs 变成一个普通文件，mkdir 必然失败
            for item in blocker.rglob("*"):
                if item.is_file():
                    item.unlink()
            blocker.rmdir()
        blocker.write_text("我是文件，不是目录", encoding="utf-8")

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            ok = audit.append(self.settings, action="add", record_id="abc", count=1)
            # 主流程不受影响：工具照常工作
            payload = self.payload("vault_staging_list")

        self.assertFalse(ok, "写不进去要如实返回 False")
        self.assertIn("审计写入失败", stderr.getvalue())
        self.assertNotIn(support.SENTINEL_PW, stderr.getvalue())
        self.assertEqual(payload["count"], 0)

    def test_read_recent_returns_oldest_to_newest_and_skips_bad_lines(self) -> None:
        home = support.make_home(self)
        settings = Settings(vault_path=home / "data.enc", kdf=dict(support.FAST_KDF))
        path = audit.audit_path(settings)
        path.parent.mkdir(parents=True, exist_ok=True)
        good = [
            json.dumps({"ts": "2026-01-01T00:00:00+00:00", "actor": "agent", "action": "reveal", "record_id": "aa"}, ensure_ascii=False),
            "{ 这行坏了",
            json.dumps({"ts": "2026-01-01T00:00:01+00:00", "actor": "agent", "action": "copy", "record_id": "bb", "password": "LEAK"}, ensure_ascii=False),
            json.dumps({"ts": "2026-01-01T00:00:02+00:00", "actor": "agent", "action": "add", "record_id": "cc"}, ensure_ascii=False),
        ]
        path.write_text("\n".join(good) + "\n", encoding="utf-8")

        rows = audit.read_recent(settings, 10)
        self.assertEqual([row["action"] for row in rows], ["reveal", "copy", "add"], "坏行跳过、顺序为旧→新")
        for row in rows:
            self.assertNotIn("password", row, "读出口也要过白名单")
        self.assertEqual(audit.read_recent(settings, 1)[0]["action"], "add")
        self.assertEqual(audit.read_recent(settings, 0), [])


# ---------------------------------------------------------------- 剪贴板安全修复
class CopyAutoclearTest(unittest.TestCase):
    """核心：`spawn=False` 不许起子进程；到点清空；被第三方改动则不清空。"""

    def setUp(self) -> None:
        self.board = {"value": ""}
        self.copy_text = mock.patch.object(
            clipboard, "copy_text", side_effect=lambda text: self.board.update(value=text)
        )
        self.read_text = mock.patch.object(clipboard, "read_text", side_effect=lambda: self.board["value"])
        self.copy_text.start()
        self.read_text.start()
        self.addCleanup(self.copy_text.stop)
        self.addCleanup(self.read_text.stop)

    def test_process_mode_never_spawns_subprocess(self) -> None:
        fired = threading.Event()
        with mock.patch("subprocess.Popen") as popen:
            result = clipboard.copy_with_autoclear(
                support.SENTINEL_PW, SHORT_WINDOW, spawn=False, on_fired=fired.set
            )
            self.assertTrue(fired.wait(2.0), "定时器没有在预期时间内触发")
        self.assertTrue(result["auto_clear"])
        self.assertEqual(result["mode"], "process")
        self.assertFalse(result["spawn"])
        self.assertEqual(popen.call_count, 0, "spawn=False 绝不能起子进程（这就是 P0 缺陷）")

    def test_process_mode_clears_clipboard_after_window(self) -> None:
        fired = threading.Event()
        with mock.patch("subprocess.Popen") as popen:
            clipboard.copy_with_autoclear("secret-value", SHORT_WINDOW, spawn=False, on_fired=fired.set)
            self.assertEqual(self.board["value"], "secret-value")
            self.assertTrue(fired.wait(2.0))
        self.assertEqual(self.board["value"], "", "到点后必须清空")
        self.assertEqual(popen.call_count, 0)

    def test_process_mode_keeps_value_changed_by_user(self) -> None:
        fired = threading.Event()
        clipboard.copy_with_autoclear("secret-value", SHORT_WINDOW, spawn=False, on_fired=fired.set)
        self.board["value"] = "用户刚复制的别的东西"
        self.assertTrue(fired.wait(2.0))
        self.assertEqual(
            self.board["value"], "用户刚复制的别的东西", "内容变了就绝不清空（不能误删用户的新复制）"
        )

    def test_spawn_mode_uses_subprocess_watcher(self) -> None:
        with mock.patch.object(clipboard, "spawn_clear_watcher", return_value=True) as watcher:
            result = clipboard.copy_with_autoclear("secret-value", 30, spawn=True)
        self.assertTrue(result["auto_clear"])
        self.assertEqual(result["mode"], "subprocess")
        self.assertEqual(watcher.call_count, 1)
        digest, seconds = watcher.call_args.args
        self.assertEqual(digest, clipboard.digest_of("secret-value"))
        self.assertEqual(seconds, 30)

    def test_uninstallable_timer_is_reported_honestly(self) -> None:
        with mock.patch("threading.Timer", side_effect=RuntimeError("no threads")):
            result = clipboard.copy_with_autoclear("secret-value", 30, spawn=False)
        self.assertFalse(result["auto_clear"])
        self.assertEqual(result["mode"], "none")
        self.assertEqual(result["seconds"], 0.0)

    def test_service_receipt_does_not_lie(self) -> None:
        record = Record(title="淘宝", password=support.SENTINEL_PW)

        SilentTimer.instances.clear()
        with mock.patch("threading.Timer", SilentTimer):
            good = service.copy_field(record, spawn=False, seconds=1)
        self.assertTrue(good["auto_clear"])
        self.assertEqual(good["auto_clear_in"], 1)
        self.assertEqual(good["auto_clear_mode"], "process")
        self.assertNotIn("hint", good)
        self.assertNotIn(support.SENTINEL_PW, json.dumps(good, ensure_ascii=False))
        self.assertEqual(SilentTimer.instances[0].delay, 1.0)
        self.assertTrue(SilentTimer.instances[0].daemon, "定时器必须是 daemon，不能阻塞进程退出")

        with mock.patch("threading.Timer", side_effect=RuntimeError("no threads")):
            bad = service.copy_field(record, spawn=False, seconds=30)
        self.assertFalse(bad["auto_clear"])
        self.assertEqual(bad["auto_clear_in"], 0, "没装上就不能报 30 秒")
        self.assertIn("hint", bad)

    def test_clipboard_result_has_no_plaintext(self) -> None:
        fired = threading.Event()
        result = clipboard.copy_with_autoclear(
            support.SENTINEL_PW, SHORT_WINDOW, spawn=False, on_fired=fired.set
        )
        fired.wait(2.0)
        self.assertNotIn(support.SENTINEL_PW, json.dumps(result, ensure_ascii=False))


class CopyToolHonestyTest(Base):
    """MCP 侧：定时器装不上时，回执必须明说 `auto_clear=false` + hint。"""

    def test_copy_without_timer_reports_failure(self) -> None:
        record = Record(title="京东", username="lisi", password=support.SENTINEL_PW)
        self.vault.records.append(record)
        self.vault.save()
        self.session.adopt(Vault.open(self.settings, password=PASSWORD))

        with mock.patch.object(clipboard, "copy_text"), mock.patch.object(
            clipboard, "read_text", return_value=""
        ), mock.patch("threading.Timer", side_effect=RuntimeError("no threads")):
            payload = self.payload("vault_copy", {"id": record.id})

        self.assertTrue(payload["copied"])
        self.assertFalse(payload["auto_clear"])
        self.assertNotIn("auto_clear_in", payload, "没装上就不能出现 auto_clear_in")
        self.assertIn("hint", payload)
        self.assertNotIn(support.SENTINEL_PW, json.dumps(payload, ensure_ascii=False))

    def test_mcp_copy_passes_spawn_false(self) -> None:
        record = Record(title="淘宝", password=support.SENTINEL_PW)
        self.vault.records.append(record)
        self.vault.save()
        self.session.adopt(Vault.open(self.settings, password=PASSWORD))
        SilentTimer.instances.clear()
        with mock.patch.object(clipboard, "copy_text"), mock.patch.object(
            clipboard, "read_text", return_value=""
        ), mock.patch.object(clipboard, "spawn_clear_watcher") as watcher, mock.patch(
            "threading.Timer", SilentTimer
        ), mock.patch("subprocess.Popen") as popen:
            payload = self.payload("vault_copy", {"id": record.id})

        self.assertEqual(watcher.call_count, 0, "MCP 不该走子进程看门狗")
        self.assertEqual(popen.call_count, 0, "MCP 不该起任何子进程")
        self.assertEqual(len(SilentTimer.instances), 1)
        self.assertEqual(SilentTimer.instances[0].delay, 30)
        self.assertEqual(payload["auto_clear_in"], 30)


# ---------------------------------------------------------------- ⑨ 高危工具
FORBIDDEN_TOOLS = (
    "vault_delete",
    "vault_staging_commit",
    "vault_import_batch",
    "vault_export",
    "vault_change_master_password",
)


class ForbiddenToolsTest(Base):
    def test_call_tool_refuses_each_forbidden_name(self) -> None:
        for name in FORBIDDEN_TOOLS:
            with self.subTest(tool=name):
                with self.assertRaises(mcp_tools.UnknownTool) as ctx:
                    self.call(name, {})
                self.assertIn("Unknown tool", str(ctx.exception))

    def test_server_maps_them_to_invalid_params(self) -> None:
        server = mcp_server.McpServer(
            self.settings,
            transport=mcp_server.StdioTransport(stdin=io.BytesIO(b""), stdout=io.BytesIO()),
            session=self.session,
        )
        for name in FORBIDDEN_TOOLS:
            with self.subTest(tool=name):
                reply = server.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": {}},
                    }
                )
                self.assertIn("error", reply)
                self.assertEqual(reply["error"]["code"], mcp_server.INVALID_PARAMS)
                self.assertIn("Unknown tool", reply["error"]["message"])

    def test_tools_list_has_exactly_ten_tools(self) -> None:
        names = set(mcp_tools.tool_names())
        self.assertEqual(len(names), 10)
        self.assertEqual(
            names,
            {
                "vault_status",
                "vault_search",
                "vault_get",
                "vault_copy",
                "vault_totp",
                "vault_staging_list",
                "vault_staging_claim",
                "vault_staging_submit",
                "vault_add",
                "vault_update",
            },
        )
        for name in FORBIDDEN_TOOLS:
            self.assertNotIn(name, names)

    def test_instructions_mention_staging_and_no_write_permission(self) -> None:
        text = mcp_server.INSTRUCTIONS
        self.assertIn("vault_staging_", text)
        self.assertIn("落库权限", text)


# ---------------------------------------------------------------- 分层约束
# 分层以 `pwdvault/__init__.py` 的声明为准（只允许箭头向下）：
#   1  crypto dpapi models errors config      （无内部依赖的原语）
#   2  vault runtime                           （文件格式 / 运行时探测）
#   3  locks importers clipboard redact audit  （锁 / 解析 / 剪贴板 / 脱敏 / 审计）
#   4  service staging inbox                   （业务规则 / 暂存区 / 监听）
#   5  web mcp_server mcp_tools                （传输层，三者同层）
#   6  cli                                     （控制器）
LAYER: dict[str, int] = {
    "crypto": 1,
    "dpapi": 1,
    "models": 1,
    "errors": 1,
    "config": 1,
    "vault": 2,
    "runtime": 2,
    "locks": 3,
    "importers": 3,
    "clipboard": 3,
    "redact": 3,
    "audit": 3,
    "service": 4,
    "staging": 4,
    "inbox": 4,
    "web": 5,
    "mcp_server": 5,
    "mcp_tools": 5,
    "cli": 6,
}


def _module_level_targets(path: Path) -> list[str]:
    """只收**模块顶层**（`ast.Module.body`）的 import 目标。

    函数体内的延迟导入不算：它发生在调用时，不可能造成模块加载期的环，
    而 `cli.cmd_mcp()` 这类懒加载是**故意**的（`pv add` 不该为协议层付加载成本）。

    返回形如 `".mcp_tools"`（相对）/`"pwdvault.models"`（绝对）的原始目标串。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            dots = "." * (node.level or 0)
            if node.module:
                found.append(dots + node.module)
            else:
                # `from . import service` —— 目标在 names 里，不能漏
                for alias in node.names:
                    found.append(dots + alias.name)
    return found


def _layer_of_owner(path: Path, root: Path) -> int | None:
    """文件归属的层级；`__init__.py` 是包的对外门面，不参与判定。"""
    if path.name == "__init__.py":
        return None
    rel = path.relative_to(root)
    owner = rel.parts[0] if len(rel.parts) > 1 else path.stem
    return LAYER.get(owner)


def _upward_violations(paths: list[Path], root: Path) -> list[str]:
    """找出「向上依赖」的模块级 import（同一层之间互相 import 是合法的）。"""
    offenders: list[str] = []
    for path in paths:
        owner_tier = _layer_of_owner(path, root)
        if owner_tier is None:
            continue
        for target in _module_level_targets(path):
            leaf = target.lstrip(".").split(".")[-1]
            leaf_tier = LAYER.get(leaf)
            if leaf_tier is None or leaf == path.stem:
                continue
            if leaf_tier > owner_tier:
                rel = path.relative_to(root).as_posix()
                offenders.append(f"{rel}（L{owner_tier}）依赖了 L{leaf_tier} 的 {leaf}")
    return offenders


class LayeringTest(unittest.TestCase):
    def test_audit_does_not_import_upper_layers(self) -> None:
        path = support.PROJECT_ROOT / "pwdvault" / "audit.py"
        imports = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        for line in imports:
            for forbidden in ("mcp_tools", "mcp_server", "web"):
                self.assertNotIn(forbidden, line, f"audit.py 不得 import {forbidden}：{line}")

    def test_no_upward_module_level_imports(self) -> None:
        """分层是「只允许箭头向下」：谁都不许依赖比自己更高的层。

        与旧判据（扫顶格行里的子串）相比，AST 版解决三个问题：
          1. 能看见 `from ..mcp_tools import TOOLS` 这种**两点**相对导入
             （字符串里根本没有 `from .mcp_tools` 这个子串，旧判据看不见它）；
          2. 覆盖子包（`pwdvault/web/*.py`）；
          3. 按**层级**判定，`web` 与 `mcp_tools` 同属传输层，互相 import 合法，
             不会被误报成违规。
        """
        root = support.PROJECT_ROOT / "pwdvault"
        offenders = _upward_violations(sorted(root.rglob("*.py")), root)
        self.assertEqual(offenders, [], "存在向上依赖（会拖出 import 环）")

    def test_checker_is_not_vacuous(self) -> None:
        """反向验证判据本身：造一个真违规（models 在模块级 import 协议层），必须被抓到。"""
        root = Path(support.make_home(self)) / "pkg"
        (root).mkdir(parents=True, exist_ok=True)
        bad = root / "models.py"
        bad.write_text("from .mcp_tools import TOOLS\n", encoding="utf-8")
        self.assertTrue(_upward_violations([bad], root), "向上依赖必须被抓到")

        # 两点相对导入（旧判据的盲点）同样必须被抓到
        (root / "errors.py").write_text("from ..mcp_server import main\n", encoding="utf-8")
        self.assertTrue(_upward_violations([root / "errors.py"], root))

        # `from . import staging` 这种「目标在 names 里」的写法也不能漏
        (root / "vault.py").write_text("from . import staging\n", encoding="utf-8")
        self.assertTrue(_upward_violations([root / "vault.py"], root))

    def test_function_body_lazy_import_is_not_flagged(self) -> None:
        """函数体内的延迟导入不算违规（否则 `cli.cmd_mcp()` 的正确写法会被打红）。"""
        root = Path(support.make_home(self)) / "pkg"
        root.mkdir(parents=True, exist_ok=True)
        lazy = root / "cli.py"
        lazy.write_text("def cmd_mcp():\n    from .mcp_server import main\n    return main\n", encoding="utf-8")
        self.assertEqual(_upward_violations([lazy], root), [])

        # 同层互相 import 也不该红（web 与 mcp_tools 同属传输层）
        peer = root / "web.py"
        peer.write_text("from ..mcp_tools import TOOLS\n", encoding="utf-8")
        self.assertEqual(_upward_violations([peer], root), [])

    def test_write_tools_use_redact_exit(self) -> None:
        """新增的写工具同样只能经 redact 出数据。"""
        source = (support.PROJECT_ROOT / "pwdvault" / "mcp_tools.py").read_text(encoding="utf-8")
        self.assertIn("redact_record(", source)
        self.assertNotIn("record.to_dict(", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
