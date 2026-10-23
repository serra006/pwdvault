"""脱敏出口测试：敏感键判定、掩码、嵌套结构、`*` 前缀、非敏感白名单、哨兵。"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault.models import MASK, Record, is_sensitive_key, mask_value
from pwdvault.redact import (
    ORIGIN_AGENT,
    ORIGIN_LOCAL,
    assert_no_secret,
    normalize_profile,
    public_error,
    record_origin,
    redact_record,
    redact_records,
)
from pwdvault.errors import RecordNotFound

# 哨兵：正常数据里绝不会出现，命中即证明明文漏进了对外结构
SENTINEL_PW = "ZZ-PvProbe-Pw-9f2c1d-DO-NOT-LEAK"
SENTINEL_CUSTOM = "ZZ-PvProbe-Custom-4a7e-DO-NOT-LEAK"
SENTINEL_NOTE = "ZZ-PvProbe-Note-1b3f-VISIBLE-OK"


def make_record() -> Record:
    return Record(
        title="淘宝",
        username="zhangsan",
        password=SENTINEL_PW,
        url="https://taobao.com",
        notes=SENTINEL_NOTE,
        totp="JBSWY3DPEHPK3PXP",
        tags=["购物", "常用"],
        fields={
            "*AccessKey Secret": SENTINEL_CUSTOM,
            "api_key": "sk-live-abc",
            "绑定手机": "13800138000",
            "密保问题": "故乡",
        },
    )


class SensitiveKeyTests(unittest.TestCase):
    def test_known_sensitive_tokens(self):
        for name in (
            "api_key",
            "AccessToken",
            "user_pass",
            "ATM PIN",
            "seed_phrase",
            "私钥",
            "密钥备份",
            "令牌",
            "口令",
            "种子",
        ):
            self.assertTrue(is_sensitive_key(name), f"{name} 应判为敏感")

    def test_star_prefix_forces_sensitive(self):
        self.assertTrue(is_sensitive_key("*AccessKey Secret"))
        self.assertTrue(is_sensitive_key("*随便写的"))

    def test_standard_fields_are_not_sensitive(self):
        for name in ("id", "title", "username", "url", "notes", "tags", "created", "updated", "pw_changed"):
            self.assertFalse(is_sensitive_key(name), f"{name} 不该被判为敏感")

    def test_pw_changed_not_misjudged(self):
        # "pw_changed" 含 "pw"，必须先命中标准非敏感白名单
        self.assertFalse(is_sensitive_key("pw_changed"))

    def test_documented_false_positive(self):
        # 已知误报，按「宁枉勿纵」接受
        self.assertTrue(is_sensitive_key("shipping_address"))

    def test_empty_name(self):
        self.assertFalse(is_sensitive_key(""))


class MaskTests(unittest.TestCase):
    def test_mask_is_fixed_length(self):
        self.assertEqual(mask_value("a"), MASK)
        self.assertEqual(mask_value("a" * 200), MASK)
        self.assertEqual(len(MASK), 4)

    def test_empty_value(self):
        self.assertEqual(mask_value(""), "（空）")
        self.assertEqual(mask_value(None), "（空）")


class RedactRecordTests(unittest.TestCase):
    def setUp(self):
        self.record = make_record()
        self.payload = redact_record(self.record, profile="agent")

    def test_agent_profile_never_exposes_password(self):
        self.assertEqual(self.payload["password"], MASK)
        self.assertNotIn(SENTINEL_PW, json.dumps(self.payload, ensure_ascii=False))

    def test_agent_profile_ignores_reveal_fields(self):
        """即使调用方传了 reveal_fields，agent 档也必须无条件脱敏。"""
        payload = redact_record(self.record, profile="agent", reveal_fields=("password", "totp"))
        self.assertEqual(payload["password"], MASK)
        self.assertEqual(payload["totp"], MASK)

    def test_agent_profile_masks_sensitive_custom_fields(self):
        self.assertEqual(self.payload["fields"]["*AccessKey Secret"], MASK)
        self.assertEqual(self.payload["fields"]["api_key"], MASK)
        assert_no_secret(self.payload, SENTINEL_PW, SENTINEL_CUSTOM)

    def test_secret_field_names_only_names(self):
        self.assertEqual(
            sorted(self.payload["secret_field_names"]), sorted(["*AccessKey Secret", "api_key"])
        )

    def test_non_sensitive_values_kept(self):
        # 反向对照：证明脱敏不是「全删」
        self.assertEqual(self.payload["username"], "zhangsan")
        self.assertEqual(self.payload["notes"], SENTINEL_NOTE)
        self.assertEqual(self.payload["fields"]["密保问题"], "故乡")
        self.assertEqual(self.payload["tags"], ["购物", "常用"])

    def test_has_flags(self):
        self.assertTrue(self.payload["has_password"])
        self.assertTrue(self.payload["has_totp"])

    def test_empty_password_reports_empty(self):
        record = Record(title="空密码")
        payload = redact_record(record)
        self.assertFalse(payload["has_password"])
        self.assertEqual(payload["password"], "（空）")

    def test_web_profile_can_reveal_single_field(self):
        payload = redact_record(self.record, profile="web", reveal_fields=("password",))
        self.assertEqual(payload["password"], SENTINEL_PW)
        # 没被 reveal 的字段仍然掩码
        self.assertEqual(payload["totp"], MASK)
        self.assertEqual(payload["fields"]["api_key"], MASK)

    def test_ui_and_web_are_same_profile(self):
        self.assertEqual(normalize_profile("web"), "ui")
        self.assertEqual(normalize_profile("agent"), "agent")
        self.assertEqual(normalize_profile("随便什么"), "agent")

    def test_key_set_is_stable(self):
        expected = {
            "id",
            "title",
            "username",
            "url",
            "tags",
            "notes",
            "created",
            "updated",
            "pw_changed",
            "origin",
            "has_password",
            "has_totp",
            "password",
            "totp",
            "fields",
            "secret_field_names",
        }
        self.assertEqual(set(self.payload), expected)

    def test_redact_records(self):
        payload = redact_records([self.record, make_record()], profile="agent")
        self.assertEqual(len(payload), 2)
        assert_no_secret(payload, SENTINEL_PW, SENTINEL_CUSTOM)


class OriginTests(unittest.TestCase):
    """`origin` 是「由 Agent 写入」徽标的唯一数据来源。

    值域固定 `local` / `agent`（对齐 DESIGN 的 `Origin = Literal["local","agent"]`）。
    写方在 `Record.meta` 里历史上用过 `origin=agent_written` 与 `written_by=agent`
    两种写法，这里统一归一化；任何认不出来的值都降级成 `local`。
    """

    def _with_meta(self, **meta: str) -> dict:
        record = Record(title="演示", password=SENTINEL_PW, meta=dict(meta))
        return redact_record(record, profile="web")

    def test_default_is_local(self):
        payload = redact_record(Record(title="手工建的"), profile="web")
        self.assertEqual(payload["origin"], ORIGIN_LOCAL)

    def test_agent_written_maps_to_agent(self):
        self.assertEqual(self._with_meta(origin="agent_written")["origin"], ORIGIN_AGENT)

    def test_plain_agent_maps_to_agent(self):
        self.assertEqual(self._with_meta(origin="agent")["origin"], ORIGIN_AGENT)

    def test_written_by_agent_maps_to_agent(self):
        self.assertEqual(self._with_meta(written_by="agent")["origin"], ORIGIN_AGENT)

    def test_case_and_space_tolerated(self):
        self.assertEqual(self._with_meta(origin=" Agent_Written ")["origin"], ORIGIN_AGENT)

    def test_unknown_value_fails_closed_to_local(self):
        """被伪造 / 未来新增的标记一律降级成 local：不让写方决定 UI 上出现什么字。"""
        for value in ("web", "admin", "agent_written_by_admin", "本地", "<script>"):
            with self.subTest(value=value):
                self.assertEqual(self._with_meta(origin=value)["origin"], ORIGIN_LOCAL)

    def test_written_by_unknown_is_local(self):
        self.assertEqual(self._with_meta(written_by="web")["origin"], ORIGIN_LOCAL)

    def test_origin_never_carries_payload(self):
        """origin 只是两值枚举，既不含明文，也不把整个 meta 吐出去。"""
        payload = redact_record(
            Record(title="演示", password=SENTINEL_PW, meta={"origin": "agent_written", "note": SENTINEL_NOTE}),
            profile="web",
        )
        assert_no_secret(payload, SENTINEL_PW)
        self.assertNotIn("meta", payload)
        self.assertNotIn("note", payload)

    def test_record_origin_matches_payload(self):
        record = Record(title="x", meta={"origin": "agent_written"})
        self.assertEqual(record_origin(record), redact_record(record)["origin"])

    def test_agent_profile_also_carries_origin(self):
        """Agent 侧也需要知道来源（避免自己重复写标记）。"""
        payload = redact_record(Record(title="x", meta={"origin": "agent_written"}), profile="agent")
        self.assertEqual(payload["origin"], ORIGIN_AGENT)


class PublicErrorTests(unittest.TestCase):
    def test_no_traceback_in_error(self):
        exc = RecordNotFound("淘宝")
        payload = public_error(exc)
        self.assertEqual(payload["code"], "record_not_found")
        self.assertIn("hint", payload)
        self.assertNotIn("traceback", json.dumps(payload))

    def test_candidates_pass_through(self):
        exc = RecordNotFound("淘宝")
        payload = public_error(exc, candidates=[{"id": "a1", "title": "淘宝"}])
        self.assertEqual(payload["candidates"][0]["title"], "淘宝")


class SentinelTests(unittest.TestCase):
    def test_assert_no_secret_detects_leak(self):
        with self.assertRaises(AssertionError):
            assert_no_secret({"a": {"b": [SENTINEL_PW]}}, SENTINEL_PW)

    def test_assert_no_secret_passes_clean_payload(self):
        assert_no_secret({"notes": SENTINEL_NOTE}, SENTINEL_PW, SENTINEL_CUSTOM)


if __name__ == "__main__":
    unittest.main()
