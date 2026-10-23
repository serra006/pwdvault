"""MCP 只读 5 工具测试（T06）。

最关键的两条断言：
  * **哨兵断言**：`SENTINEL_PW` / `SENTINEL_CUSTOM` 在所有工具响应里出现 **0** 次；
    同时 `SENTINEL_NOTE`（备注里的哨兵）必须出现 **> 0** 次 —— 否则测试可能因为
    「什么都没返回」而假绿。
  * **源码级断言**：`mcp_tools.py` 里不允许出现「把记录整条序列化」或「把 password
    属性直接塞进响应」的写法，也不允许绕过 `redact_record`。

剪贴板全部 mock：测试绝不允许真写用户剪贴板（会污染用户环境、也可能把哨兵密码
留在系统里）。时间全部注入：不真 sleep。
"""

from __future__ import annotations

import json
import os
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import clipboard, mcp_tools, service
from pwdvault.errors import Locked
from pwdvault.models import MASK, Record

FIXED_NOW = 1_700_000_000.0  # 2023-11-14T22:13:20Z；% 30 == 20 → 剩余 10 秒
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
SECRET_FIELD = "*AccessKey Secret"


def _seed(vault) -> dict[str, Record]:
    """三条记录：一条带全部敏感字段与备注哨兵，两条同名族（用于制造歧义）。"""
    taobao = Record(
        title="淘宝",
        username="zhangsan",
        password=support.SENTINEL_PW,
        url="https://taobao.com",
        notes=support.SENTINEL_NOTE,
        tags=["购物"],
        totp=TOTP_SECRET,
        fields={SECRET_FIELD: support.SENTINEL_CUSTOM, "绑定手机": "13800138000"},
    )
    union = Record(
        title="淘宝联盟",
        username="zhangsan",
        password="union-pw-DO-NOT-LEAK",
        url="https://union.taobao.com",
        tags=["购物", "推广"],
    )
    jd = Record(
        title="京东",
        username="lisi",
        password="jd-pw-DO-NOT-LEAK",
        url="https://jd.com",
        tags=["购物"],
    )
    vault.records.extend([taobao, union, jd])
    vault.save()
    return {"taobao": taobao, "union": union, "jd": jd}


class ToolTestCase(unittest.TestCase):
    """公共夹具：已解锁的 session（时间注入）、mock 掉的剪贴板。"""

    def setUp(self) -> None:
        home = support.make_home(self)
        self.fixture = support.make_vault(home)
        self.records = _seed(self.fixture.vault)
        self.session = mcp_tools.McpSession(
            self.fixture.settings,
            vault=self.fixture.vault,
            unlocked_by="test",
            clock=lambda: FIXED_NOW,
            env={},
        )

        patcher_copy = mock.patch.object(clipboard, "copy_text")
        self.copy_text = patcher_copy.start()
        self.addCleanup(patcher_copy.stop)

        # T07：MCP 走 `copy_with_autoclear(..., spawn=False)`（进程内定时器）。
        # 这里把它整体替换掉：既记录「被复制的值」，又记录 spawn 标记 ——
        # 后者是「MCP 绝不起子进程」的直接证据，也保证测试不会真去动用户剪贴板。
        self.spawn_flags: list[bool] = []

        def fake_copy(text, seconds=30, *, spawn=True, on_fired=None):
            self.copy_text(text)
            self.spawn_flags.append(bool(spawn))
            return {
                "auto_clear": True,
                "seconds": float(seconds),
                "mode": "subprocess" if spawn else "process",
                "spawn": bool(spawn),
            }

        patcher_watch = mock.patch.object(clipboard, "copy_with_autoclear", side_effect=fake_copy)
        self.watch = patcher_watch.start()
        self.addCleanup(patcher_watch.stop)

    # -------------------------------------------------------------- 便捷
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

    def copied_values(self) -> list[str]:
        return [call.args[0] for call in self.copy_text.call_args_list]


class StatusToolTest(ToolTestCase):
    def test_status_reports_counts(self) -> None:
        payload = self.payload("vault_status")
        self.assertTrue(payload["exists"])
        self.assertTrue(payload["unlocked"])
        self.assertEqual(payload["count"], 3)
        self.assertIsInstance(payload["revision"], int)
        self.assertGreaterEqual(payload["revision"], 1)
        self.assertIn("auto_lock_in_seconds", payload)
        self.assertIn("pending_staging", payload)
        self.assertIn("inbox_pending", payload)
        self.assertIn("last_snapshot_age_days", payload)
        self.assertNotIn("hint", payload)

    def test_status_works_while_locked(self) -> None:
        locked = mcp_tools.McpSession(self.fixture.settings, env={})
        outcome = mcp_tools.call_tool(locked, "vault_status", {})
        self.assertFalse(outcome.is_error, "状态工具在锁着时也必须能回答")
        self.assertFalse(outcome.payload["unlocked"])
        self.assertEqual(outcome.payload["count"], 0)
        self.assertTrue(outcome.payload["exists"])
        self.assertIn("hint", outcome.payload)

    def test_status_parameter_error(self) -> None:
        with self.assertRaises(mcp_tools.InvalidArguments):
            self.call("vault_status", {"unexpected": 1})


class SearchToolTest(ToolTestCase):
    def test_search_by_title(self) -> None:
        payload = self.payload("vault_search", {"query": "京东"})
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["records"][0]["title"], "京东")

    def test_search_by_tag_prefix(self) -> None:
        payload = self.payload("vault_search", {"query": "tag:购物"})
        self.assertEqual(payload["count"], 3)

    def test_search_by_user_prefix(self) -> None:
        payload = self.payload("vault_search", {"query": "user:zhangsan"})
        self.assertEqual(payload["count"], 2)
        self.assertEqual({item["title"] for item in payload["records"]}, {"淘宝", "淘宝联盟"})

    def test_search_record_shape_has_no_secrets(self) -> None:
        payload = self.payload("vault_search", {"query": "淘宝"})
        self.assertEqual(payload["count"], 2)
        taobao = next(item for item in payload["records"] if item["title"] == "淘宝")
        self.assertEqual(set(taobao), set(mcp_tools.SUMMARY_KEYS))
        self.assertNotIn("password", taobao)
        self.assertNotIn("notes", taobao)
        self.assertNotIn("fields", taobao)
        self.assertTrue(taobao["has_password"])
        self.assertTrue(taobao["has_totp"])
        self.assertEqual(taobao["secret_field_names"], [SECRET_FIELD])
        self.assertEqual(taobao["tags"], ["购物"])

    def test_search_respects_limit(self) -> None:
        payload = self.payload("vault_search", {"query": "tag:购物", "limit": 1})
        self.assertEqual(payload["count"], 1)

    def test_search_no_hit_is_not_error(self) -> None:
        payload = self.payload("vault_search", {"query": "根本不存在的站点 zzz"})
        self.assertEqual(payload, {"count": 0, "records": []})

    def test_search_parameter_errors(self) -> None:
        for bad in (
            {},
            {"query": ""},
            {"query": 123},
            {"query": "淘宝", "limit": "ten"},
            {"query": "淘宝", "limit": 0},
            {"query": "淘宝", "limit": 9999},
            {"query": "淘宝", "unknown": True},
        ):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_search", bad)


class GetToolTest(ToolTestCase):
    def test_get_masks_sensitive_values_and_lists_their_names(self) -> None:
        payload = self.payload("vault_get", {"id": self.records["taobao"].id})
        self.assertEqual(payload["title"], "淘宝")
        self.assertEqual(payload["username"], "zhangsan")
        self.assertEqual(payload["url"], "https://taobao.com")

        # 备注属于「看得见」的信息
        self.assertEqual(payload["notes"], support.SENTINEL_NOTE)
        # 非敏感自定义字段给值
        self.assertEqual(payload["fields"]["绑定手机"], "13800138000")
        # 敏感字段只给名字，值恒为掩码
        self.assertEqual(payload["secret_field_names"], [SECRET_FIELD])
        self.assertEqual(payload["fields"][SECRET_FIELD], MASK)
        self.assertEqual(payload["password"], MASK)
        self.assertEqual(payload["totp"], MASK)
        self.assertTrue(payload["has_password"])

    def test_get_is_not_leaking_sentinels(self) -> None:
        payload = self.payload("vault_get", {"id": self.records["taobao"].id})
        body = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(support.SENTINEL_PW, body)
        self.assertNotIn(support.SENTINEL_CUSTOM, body)
        self.assertIn(support.SENTINEL_NOTE, body)

    def test_get_by_query(self) -> None:
        payload = self.payload("vault_get", {"query": "京东"})
        self.assertEqual(payload["title"], "京东")
        self.assertNotIn("note", payload)

    def test_get_prefers_id_and_adds_note(self) -> None:
        payload = self.payload("vault_get", {"id": self.records["jd"].id, "query": "淘宝"})
        self.assertEqual(payload["title"], "京东", "id 必须优先于 query")
        self.assertIn("note", payload)
        self.assertTrue(payload["note"])

    def test_get_not_found(self) -> None:
        payload = self.failure("vault_get", {"id": "0000000000"})
        self.assertEqual(payload["code"], "record_not_found")

    def test_get_ambiguous(self) -> None:
        payload = self.failure("vault_get", {"query": "淘宝"})
        self.assertEqual(payload["code"], "ambiguous_record")
        self.assertEqual(len(payload["candidates"]), 2)

    def test_get_parameter_errors(self) -> None:
        for bad in ({}, {"id": ""}, {"query": ""}, {"id": 5}):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_get", bad)


class CopyToolTest(ToolTestCase):
    def test_copy_receipt_has_exactly_five_keys(self) -> None:
        payload = self.payload("vault_copy", {"id": self.records["taobao"].id})
        # 定时器真的装上时，回执仍是 v1.0 的 5 键契约（不含 auto_clear / hint）
        self.assertEqual(
            set(payload), {"copied", "title", "field", "auto_clear_in", "host"}
        )
        self.assertTrue(set(payload) <= set(mcp_tools.COPY_KEYS), "回执必须是白名单子集")
        self.assertTrue(payload["copied"])
        self.assertEqual(payload["title"], "淘宝")
        self.assertEqual(payload["field"], "password")
        self.assertEqual(payload["auto_clear_in"], 30)
        self.assertEqual(payload["host"], socket.gethostname())

    def test_copy_uses_process_timer_not_subprocess(self) -> None:
        """MCP 是长驻进程：必须传 spawn=False，绝不能起 `_clipwatch` 子进程。"""
        self.payload("vault_copy", {"id": self.records["jd"].id})
        self.assertEqual(self.spawn_flags, [False])

    def test_copy_writes_value_to_clipboard_but_not_to_response(self) -> None:
        payload = self.payload("vault_copy", {"query": "京东"})
        self.assertEqual(self.copied_values(), ["jd-pw-DO-NOT-LEAK"])
        self.assertNotIn("jd-pw-DO-NOT-LEAK", json.dumps(payload, ensure_ascii=False))

    def test_copy_password_by_query_is_not_returned(self) -> None:
        payload = self.payload("vault_copy", {"query": "淘宝", "id": self.records["taobao"].id})
        self.assertEqual(self.copied_values(), [support.SENTINEL_PW])
        self.assertNotIn(support.SENTINEL_PW, json.dumps(payload, ensure_ascii=False))
        self.assertIn("note", payload)  # id 与 query 同时给出时留痕

    def test_copy_other_field(self) -> None:
        payload = self.payload("vault_copy", {"query": "京东", "field": "username"})
        self.assertEqual(payload["field"], "username")
        self.assertEqual(self.copied_values(), ["lisi"])

    def test_copy_ambiguous(self) -> None:
        payload = self.failure("vault_copy", {"query": "淘宝"})
        self.assertEqual(payload["code"], "ambiguous_record")
        candidates = payload["candidates"]
        self.assertEqual(len(candidates), 2)
        for candidate in candidates:
            self.assertEqual(set(candidate), {"id", "title", "username"})
        self.assertNotIn(support.SENTINEL_PW, json.dumps(payload, ensure_ascii=False))
        self.assertEqual(self.copied_values(), [], "歧义时绝不允许复制任何一个")

    def test_copy_not_found(self) -> None:
        payload = self.failure("vault_copy", {"query": "根本没有这个站点 zzz"})
        self.assertEqual(payload["code"], "record_not_found")

    def test_copy_missing_field_value(self) -> None:
        payload = self.failure("vault_copy", {"id": self.records["jd"].id, "field": "notes"})
        self.assertEqual(payload["code"], "invalid_record")
        self.assertNotIn("jd-pw-DO-NOT-LEAK", json.dumps(payload, ensure_ascii=False))

    def test_copy_parameter_errors(self) -> None:
        for bad in ({}, {"id": "abc", "field": 123}, {"query": "淘宝", "field": ""}):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_copy", bad)


class TotpToolTest(ToolTestCase):
    def test_totp_returns_six_digit_code(self) -> None:
        payload = self.payload("vault_totp", {"id": self.records["taobao"].id})
        expected, remaining = service.totp_code(TOTP_SECRET, at=FIXED_NOW)
        self.assertEqual(payload["code"], expected)
        self.assertEqual(len(payload["code"]), 6)
        self.assertTrue(payload["code"].isdigit())
        self.assertEqual(payload["remaining_seconds"], remaining)
        self.assertTrue(1 <= payload["remaining_seconds"] <= 30)
        self.assertEqual(payload["title"], "淘宝")

    def test_totp_changes_with_time(self) -> None:
        taobao_id = self.records["taobao"].id
        code_now = self.payload("vault_totp", {"id": taobao_id})["code"]
        shifted = mcp_tools.McpSession(
            self.fixture.settings,
            vault=self.fixture.vault,
            clock=lambda: FIXED_NOW + 30,
            env={},
        )
        code_next = mcp_tools.call_tool(shifted, "vault_totp", {"id": taobao_id}).payload["code"]
        self.assertNotEqual(code_now, code_next)

    def test_totp_without_seed(self) -> None:
        payload = self.failure("vault_totp", {"id": self.records["jd"].id})
        self.assertEqual(payload["code"], "invalid_record")

    def test_totp_parameter_errors(self) -> None:
        for bad in ({}, {"query": ""}, {"id": 1}):
            with self.subTest(arguments=bad):
                with self.assertRaises(mcp_tools.InvalidArguments):
                    self.call("vault_totp", bad)


class DispatchTest(ToolTestCase):
    def test_unknown_tool(self) -> None:
        with self.assertRaises(mcp_tools.UnknownTool) as ctx:
            self.call("vault_delete", {})
        self.assertEqual(str(ctx.exception), "Unknown tool: vault_delete")

    def test_non_dict_arguments(self) -> None:
        with self.assertRaises(mcp_tools.InvalidArguments):
            mcp_tools.call_tool(self.session, "vault_status", ["nope"])  # type: ignore[arg-type]

    def test_every_tool_has_description_and_schema(self) -> None:
        self.assertEqual(len(mcp_tools.TOOLS), 10)
        for spec in mcp_tools.TOOLS:
            with self.subTest(tool=spec.name):
                self.assertTrue(spec.name.startswith("vault_"))
                self.assertGreater(len(spec.description), 20)
                self.assertEqual(spec.input_schema["type"], "object")
                self.assertIn("properties", spec.input_schema)
                definition = spec.to_mcp()
                self.assertEqual(
                    set(definition), {"name", "title", "description", "inputSchema"}
                )
                json.dumps(definition, ensure_ascii=False)


class UnlockChainTest(unittest.TestCase):
    """未解锁 → locked；环境变量 → env；DPAPI 在位 → dpapi。"""

    def test_locked_when_nothing_available(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        with self.assertRaises(Locked) as ctx:
            mcp_tools.unlock_chain(fixture.settings, env={})
        self.assertEqual(ctx.exception.code, "locked")
        self.assertEqual(ctx.exception.hint, mcp_tools.LOCKED_HINT)
        # hint 必须给出**真的能解开 stdio 这条路**的做法：`pv local-unlock`。
        # 早期版本写的是「去 Web 界面解锁」，那是错的 —— Web 进程的 DEK 在另一个
        # 进程里，stdio 侧的 MCP 拿不到，照着做也还是锁着。
        self.assertIn("local-unlock", ctx.exception.hint)
        self.assertIn("Web", ctx.exception.hint)
        self.assertIn("不会让这里能用", ctx.exception.hint)

    def test_env_password_unlocks(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        vault, how = mcp_tools.unlock_chain(
            fixture.settings, env={mcp_tools.ENV_MASTER_PASSWORD: support.PASSWORD}
        )
        self.assertEqual(how, "env")
        self.assertEqual(len(vault.records), 0)

    def test_wrong_env_password_is_locked_not_crash(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        with self.assertRaises(Locked) as ctx:
            mcp_tools.unlock_chain(
                fixture.settings, env={mcp_tools.ENV_MASTER_PASSWORD: "错的密码"}
            )
        self.assertEqual(ctx.exception.code, "locked")
        self.assertNotIn("错的密码", ctx.exception.message)

    def test_missing_vault_is_not_reported_as_locked(self) -> None:
        """库文件不存在时报 `vault_not_found`：报「锁着」会让用户去解锁一个不存在的东西。"""
        from pwdvault.config import Settings

        home = support.make_home(self)
        settings = Settings(vault_path=home / "data.enc", kdf=dict(support.FAST_KDF))
        session = mcp_tools.McpSession(settings, env={})
        outcome = mcp_tools.call_tool(session, "vault_search", {"query": "淘宝"})
        self.assertTrue(outcome.is_error)
        self.assertEqual(outcome.payload["code"], "vault_not_found")
        # 状态工具仍然正常回答「还没建库」
        status = mcp_tools.call_tool(session, "vault_status", {})
        self.assertFalse(status.is_error)
        self.assertFalse(status.payload["exists"])

    def test_session_require_vault_raises_locked(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        session = mcp_tools.McpSession(fixture.settings, env={})
        with self.assertRaises(Locked):
            session.require_vault()
        self.assertIsNone(session.try_vault())
        self.assertIsNone(session.vault)

    def test_tools_return_locked_code(self) -> None:
        home = support.make_home(self)
        fixture = support.make_vault(home)
        session = mcp_tools.McpSession(fixture.settings, env={})
        for name, arguments in (
            ("vault_search", {"query": "淘宝"}),
            ("vault_get", {"id": "0000000000"}),
            ("vault_copy", {"query": "淘宝"}),
            ("vault_totp", {"query": "淘宝"}),
        ):
            with self.subTest(tool=name):
                outcome = mcp_tools.call_tool(session, name, arguments)
                self.assertTrue(outcome.is_error)
                self.assertEqual(outcome.payload["code"], "locked")
                self.assertIn("hint", outcome.payload)

    @unittest.skipUnless(sys.platform == "win32", "DPAPI 仅 Windows")
    def test_dpapi_unlocks_when_enabled(self) -> None:
        from pwdvault import dpapi

        if not dpapi.is_supported():  # pragma: no cover - 仅异常环境
            self.skipTest("当前环境不支持 DPAPI")
        home = support.make_home(self)
        fixture = support.make_vault(home)
        fixture.vault.enable_local_unlock()
        fixture.vault.save()
        vault, how = mcp_tools.unlock_chain(fixture.settings, env={})
        self.assertEqual(how, "dpapi")
        self.assertEqual(len(vault.records), 0)

    def test_proxy_stub_falls_back_to_local(self) -> None:
        """P1 代理是桩：探测到 runtime.json 也不能让工具挂掉，要落到本地解锁。"""
        from pwdvault import runtime

        home = support.make_home(self)
        fixture = support.make_vault(home)
        runtime.write_runtime(home, port=8765, token="tok", pid=os.getpid())
        vault, how = mcp_tools.unlock_chain(
            fixture.settings, env={mcp_tools.ENV_MASTER_PASSWORD: support.PASSWORD}
        )
        self.assertEqual(how, "env")
        self.assertIsNotNone(vault)


class SentinelTest(ToolTestCase):
    """⑥ 哨兵：所有工具响应里 SENTINEL_PW 出现 0 次，SENTINEL_NOTE 出现 > 0 次。"""

    def _all_bodies(self) -> list[str]:
        taobao_id = self.records["taobao"].id
        calls = [
            ("vault_status", {}),
            ("vault_search", {"query": "淘宝"}),
            ("vault_get", {"id": taobao_id}),
            ("vault_copy", {"id": taobao_id}),
            ("vault_totp", {"id": taobao_id}),
        ]
        bodies: list[str] = []
        for name, arguments in calls:
            with self.subTest(tool=name):
                outcome = self.call(name, arguments)
                bodies.append(json.dumps(outcome.payload, ensure_ascii=False))
        return bodies

    def test_never_leaks_password_sentinel(self) -> None:
        blob = "\n".join(self._all_bodies())
        self.assertEqual(blob.count(support.SENTINEL_PW), 0, "密码哨兵泄露了")
        self.assertEqual(blob.count(support.SENTINEL_CUSTOM), 0, "敏感自定义字段泄露了")

    def test_note_sentinel_is_visible_as_reverse_control(self) -> None:
        blob = "\n".join(self._all_bodies())
        self.assertGreater(
            blob.count(support.SENTINEL_NOTE), 0, "备注哨兵一次都没出现 → 说明断言可能是空转"
        )

    def test_ambiguous_candidates_never_leak(self) -> None:
        bodies = [
            json.dumps(self.failure("vault_copy", {"query": "淘宝"}), ensure_ascii=False),
            json.dumps(self.failure("vault_get", {"query": "淘宝"}), ensure_ascii=False),
        ]
        blob = "\n".join(bodies)
        self.assertEqual(blob.count(support.SENTINEL_PW), 0)
        self.assertEqual(blob.count("union-pw-DO-NOT-LEAK"), 0)


class RedactExitTest(unittest.TestCase):
    """源码级审计：`mcp_tools.py` 只能经 `redact_record` 出数据。"""

    def test_module_source_uses_only_redact_exit(self) -> None:
        source = (support.PROJECT_ROOT / "pwdvault" / "mcp_tools.py").read_text(encoding="utf-8")
        self.assertNotIn("record.to_dict(", source, "禁止把整条记录序列化成 dict")
        self.assertNotIn("record.password", source, "禁止把 password 属性直接塞进响应")
        self.assertIn("redact_record(", source, "必须经 redact 唯一出口")
        self.assertIn('profile="agent"', source)

    def test_summary_and_candidate_are_redacted(self) -> None:
        record = Record(
            title="样例",
            username="u",
            password=support.SENTINEL_PW,
            notes=support.SENTINEL_NOTE,
            fields={SECRET_FIELD: support.SENTINEL_CUSTOM},
        )
        body = json.dumps(
            {"summary": mcp_tools._summary(record), "candidate": mcp_tools._candidate(record)},
            ensure_ascii=False,
        )
        self.assertNotIn(support.SENTINEL_PW, body)
        self.assertNotIn(support.SENTINEL_CUSTOM, body)
        self.assertNotIn(support.SENTINEL_NOTE, body)  # 摘要里连备注都不带
        self.assertEqual(mcp_tools._candidate(record), {"id": record.id, "title": "样例", "username": "u"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
