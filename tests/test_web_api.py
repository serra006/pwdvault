"""Web 业务 API（T09）测试：17 条路由的 happy path + 脱敏/乐观锁/审计/暂存区/上传/接入配置。

设计原则与 T08 的 `test_web.py` 一致，但有两条更硬的规矩：

1. **哨兵断言**：`SENTINEL_PW` 只应该出现在两个地方 —— 加密后的 `data.enc` 与
   显式 `?reveal=` 的单值响应里。其余所有响应（列表/详情/暂存区/体检/冲突结构）
   拼起来都搜不到它。`SENTINEL_NOTE` 是反向对照（备注本来就该明文返回），
   用来证明哨兵断言不是空转。
2. **冲突的关键断言是「盘上没被覆盖」**，而不是「返回了 409」。只看 409 的话，
   一个先写盘再报错的实现也能骗过测试，所以这里会重新打开库读一次明文比对。

剪贴板一律打桩（设计 §9.5）：`copy_text` 换成记录器、`process_clear_watcher`
换成返回 True，顺带钉住 `spawn=False`（CLI 的子进程方式在长驻 Web 进程里会静默失效）。
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import audit
from pwdvault.models import MASK, Record
from pwdvault.web.server import TOKEN_HEADER, WebServer

SENTINEL_PW = support.SENTINEL_PW
SENTINEL_CUSTOM = support.SENTINEL_CUSTOM
SENTINEL_NOTE = support.SENTINEL_NOTE

TOKEN = "test-session-token-0123456789"


class ApiFixture:
    """起一个真 `WebServer`（临时端口 + 临时库），默认已解锁。"""

    def __init__(
        self,
        case: unittest.TestCase,
        *,
        unlock: bool = True,
        clipboard_seconds: int = 30,
    ) -> None:
        self.home = support.make_home(case)
        fixture = support.make_vault(self.home, snapshot_keep=2)
        # inbox 轮询拉长到 60s：测试里由用例自己显式建批次，避免后台线程插进来
        # 让「批次数量」这类断言偶发失败（真线程仍然在跑，只是不会在用例期间醒来）。
        self.settings = replace(
            fixture.settings,
            inbox_interval_seconds=60.0,
            clipboard_seconds=clipboard_seconds,
            lock_timeout_seconds=20.0,
        )
        self.httpd = WebServer(
            self.settings,
            port=0,
            open_browser=False,
            quiet=True,
            token=TOKEN,
            auto_lock_seconds=0,
            poll_seconds=60.0,
            idle_check_seconds=60.0,
        )
        self.httpd.start()
        self._thread = self.httpd.start_in_thread()
        case.addCleanup(self._join)
        case.addCleanup(self.httpd.stop)
        if unlock:
            self.httpd.state.unlock(password=fixture.password)

    def _join(self) -> None:
        self._thread.join(timeout=5.0)

    # ---- 便捷
    @property
    def port(self) -> int:
        return self.httpd.port

    @property
    def state(self):
        return self.httpd.state

    @property
    def staging(self):
        return self.httpd.state.staging

    def request(
        self,
        method: str,
        path: str,
        *,
        body: object = None,
        headers: dict | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        sent: dict[str, str] = {TOKEN_HEADER: TOKEN}
        if headers:
            sent.update({str(k): str(v) for k, v in headers.items()})
        payload: bytes | None = None
        if raw_body is not None:
            payload = raw_body
        elif body is not None:
            payload = json.dumps(body).encode("utf-8")
            sent.setdefault("Content-Type", "application/json")
        try:
            conn.request(method, path, body=payload, headers=sent)
            response = conn.getresponse()
            data = response.read()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            conn.close()

    def json(self, method: str, path: str, **kwargs: object) -> tuple[int, dict]:
        status, _, data = self.request(method, path, **kwargs)
        try:
            return status, json.loads(data.decode("utf-8")) if data else {}
        except json.JSONDecodeError:  # pragma: no cover - 失败时给出可读信息
            raise AssertionError(f"{method} {path} 返回的不是 JSON：{data[:200]!r}")

    # ---- 数据准备
    def create(
        self,
        title: str,
        *,
        username: str = "someone",
        password: str = "",
        url: str = "",
        notes: str = "",
        totp: str = "",
        tags: list[str] | None = None,
        fields: dict | None = None,
    ) -> str:
        payload: dict = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "totp": totp,
            "tags": tags or [],
            "fields": fields or {},
        }
        status, data = self.json("POST", "/api/records", body=payload)
        assert status == 200, f"建记录失败 {status} {data}"
        return str(data["id"])

    def updated_of(self, record_id: str) -> str:
        status, data = self.json("GET", f"/api/records/{record_id}")
        assert status == 200, data
        return str(data["updated"])

    def make_batch(self, *, title: str = "站点 A", password: str = SENTINEL_PW) -> str:
        drafts = [
            Record(
                title=title,
                username="user-a",
                password=password,
                url="https://a.example",
                notes="草稿备注",
            )
        ]
        batch = self.staging.create_from_file(
            path=Path("待整理 站点.txt"),
            text="站点 A user-a 密码",
            drafts=drafts,
            origin="local",
        )
        return batch.batch_id


# ---------------------------------------------------------------- 会话 + 记录读
class RecordReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = ApiFixture(self)

    def test_session_endpoint_ok(self) -> None:
        status, data = self.web.json("GET", "/api/session")
        self.assertEqual(200, status)
        for key in (
            "unlocked",
            "revision",
            "count",
            "auto_lock_seconds",
            "auto_lock_in_seconds",
            "agent",
            "port",
            "vault_exists",
            "label",
            "methods",
            "inbox",
            "staging_pending",
        ):
            self.assertIn(key, data)
        self.assertTrue(data["unlocked"])

    def test_records_list_is_summary_only(self) -> None:
        self.web.create(
            "邮箱",
            username="me@example.com",
            password=SENTINEL_PW,
            notes=SENTINEL_NOTE,
            fields={"API Key": SENTINEL_CUSTOM},
            tags=["工作"],
        )
        status, data = self.web.json("GET", "/api/records")
        self.assertEqual(200, status)
        self.assertEqual(1, data["count"])
        self.assertEqual(1, data["total"])
        row = data["records"][0]
        self.assertEqual(
            {
                "id",
                "title",
                "username",
                "url",
                "tags",
                "has_password",
                "has_totp",
                "secret_field_names",
                "updated",
                "origin",
            },
            set(row),
            "列表项的键必须与冻结契约完全一致（多一个 password 就是泄露）",
        )
        self.assertTrue(row["has_password"])
        self.assertEqual(["API Key"], row["secret_field_names"])
        self.assertIn("工作", row["tags"])
        self.assertNotIn(SENTINEL_PW, json.dumps(data, ensure_ascii=False))
        self.assertNotIn(SENTINEL_CUSTOM, json.dumps(data, ensure_ascii=False))

    def test_records_search_tag_and_paging(self) -> None:
        self.web.create("GitHub", username="dev", password="p1", tags=["工作", "代码"])
        self.web.create("GitLab", username="dev2", password="p2", tags=["工作"])
        self.web.create("Steam", username="gamer", password="p3", tags=["娱乐"])

        _, data = self.web.json("GET", "/api/records?q=git")
        self.assertEqual(2, data["total"])

        _, data = self.web.json("GET", "/api/records?tag=" + urllib.parse.quote("娱乐"))
        self.assertEqual(1, data["total"])
        self.assertEqual("Steam", data["records"][0]["title"])

        _, data = self.web.json("GET", "/api/records?limit=2&offset=1")
        self.assertEqual(2, data["count"])
        self.assertEqual(3, data["total"])

    def test_record_detail_masks_and_reveal_writes_audit(self) -> None:
        record_id = self.web.create(
            "邮箱",
            username="me@example.com",
            password=SENTINEL_PW,
            notes=SENTINEL_NOTE,
            fields={"API Key": SENTINEL_CUSTOM},
        )
        status, detail = self.web.json("GET", f"/api/records/{record_id}")
        self.assertEqual(200, status)
        self.assertEqual(MASK, detail["password"])
        self.assertTrue(detail["password_hidden"])
        self.assertEqual(MASK, detail["fields"]["API Key"])
        self.assertEqual(SENTINEL_NOTE, detail["notes"], "备注本来就该明文（反向对照）")
        text = json.dumps(detail, ensure_ascii=False)
        self.assertNotIn(SENTINEL_PW, text)
        self.assertNotIn(SENTINEL_CUSTOM, text)

        # 显式 reveal 才给明文
        status, revealed = self.web.json("GET", f"/api/records/{record_id}?reveal=password")
        self.assertEqual(200, status)
        self.assertEqual(SENTINEL_PW, revealed["value"])
        self.assertEqual("password", revealed["revealed"])
        self.assertIn("15", revealed["warning"])

        quoted = urllib.parse.quote("API Key")
        status, custom = self.web.json("GET", f"/api/records/{record_id}?reveal={quoted}")
        self.assertEqual(200, status)
        self.assertEqual(SENTINEL_CUSTOM, custom["value"])

        # 审计里必须有一条 reveal，且**不含任何值**
        log_text = audit.audit_path(self.web.settings).read_text(encoding="utf-8")
        entries = [json.loads(line) for line in log_text.splitlines() if line.strip()]
        reveals = [row for row in entries if row.get("action") == "reveal"]
        self.assertGreaterEqual(len(reveals), 2)
        self.assertEqual({"password", "API Key"}, {row["field_name"] for row in reveals})
        self.assertEqual({record_id}, {row["record_id"] for row in reveals})
        self.assertNotIn(SENTINEL_PW, log_text)
        self.assertNotIn(SENTINEL_CUSTOM, log_text)

    def test_unknown_record_and_unknown_field(self) -> None:
        status, data = self.web.json("GET", "/api/records/deadbeef00")
        self.assertEqual(404, status)
        self.assertEqual("record_not_found", data["code"])

        record_id = self.web.create("只有标题")
        status, data = self.web.json("GET", f"/api/records/{record_id}?reveal=nope")
        self.assertEqual(404, status)
        self.assertEqual("field_not_found", data["code"])

    def test_origin_is_two_valued_and_comes_from_redact(self) -> None:
        """`origin` 只有 local/agent 两档，且**绝不把 meta 整包透出去**。"""
        from pwdvault.locks import Operation, VaultStore

        web_id = self.web.create("网页建的", password="p")
        # Agent 写过的记录：`mcp_tools` 打的是 meta.origin=agent_written
        agent_record = Record(title="Agent 建的", password="p", meta={"origin": "agent_written"})
        store: VaultStore = self.web.state.store
        store.commit([Operation.add(agent_record)])

        _, listing = self.web.json("GET", "/api/records")
        origins = {row["title"]: row["origin"] for row in listing["records"]}
        self.assertEqual("local", origins["网页建的"])
        self.assertEqual("agent", origins["Agent 建的"])

        _, detail = self.web.json("GET", f"/api/records/{web_id}")
        self.assertEqual("local", detail["origin"])
        self.assertNotIn("meta", detail, "meta 是内部标记层，绝不进对外结构")
        self.assertNotIn("meta", json.dumps(listing, ensure_ascii=False))


# ---------------------------------------------------------------- 记录写
class RecordWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = ApiFixture(self)

    def test_create_record(self) -> None:
        status, data = self.web.json(
            "POST",
            "/api/records",
            body={
                "title": "新站点",
                "username": "u1",
                "password": SENTINEL_PW,
                "url": "https://new.example",
                "notes": "备注",
                "totp": "JBSWY3DPEHPK3PXP",
                "tags": "工作,重要",
                "fields": {"密保问题": "母亲的名字"},
            },
        )
        self.assertEqual(200, status)
        self.assertIn("id", data)
        self.assertIsInstance(data["revision"], int)

        _, detail = self.web.json("GET", f"/api/records/{data['id']}")
        self.assertEqual("新站点", detail["title"])
        self.assertEqual(["工作", "重要"], detail["tags"])
        self.assertEqual("母亲的名字", detail["fields"]["密保问题"])
        self.assertTrue(detail["has_totp"])
        self.assertEqual(MASK, detail["totp"])
        self.assertNotIn(SENTINEL_PW, json.dumps(detail, ensure_ascii=False))

    def test_create_requires_title(self) -> None:
        status, data = self.web.json("POST", "/api/records", body={"username": "u"})
        self.assertEqual(400, status)
        self.assertEqual("invalid_record", data["code"])

    def test_patch_record_ok(self) -> None:
        record_id = self.web.create("待改", password="old")
        expected = self.web.updated_of(record_id)
        status, data = self.web.json(
            "PATCH",
            f"/api/records/{record_id}",
            body={
                "changes": {
                    "password": "new-secret",
                    "notes": "改过",
                    # 前端习惯把标签传成数组；apply_changes 只认逗号串，必须在这里归一
                    "tags": ["工作", "重要"],
                },
                "expected_updated": expected,
            },
        )
        self.assertEqual(200, status)
        self.assertTrue(data["updated"])
        self.assertEqual(record_id, data["id"])

        # 盘上真的改了（不走 API，直接看内存视图，它来自落盘 reload）
        record = self.web.state.store.vault.find_by_id(record_id)
        self.assertEqual("new-secret", record.password)
        self.assertEqual("改过", record.notes)
        self.assertEqual(["工作", "重要"], record.tags, "标签数组不该被拼成 \"['工作']\"")

        # 改 id / created 这类键必须被忽略（不能让客户端改主键或伪造时间戳）
        refreshed = self.web.updated_of(record_id)
        status, _ = self.web.json(
            "PATCH",
            f"/api/records/{record_id}",
            body={"changes": {"id": "forged", "created": "1999"}, "expected_updated": refreshed},
        )
        self.assertEqual(400, status, "只有受保护键时应当拒绝（没有可改的字段）")
        self.assertEqual(record_id, self.web.state.store.vault.records[0].id)

    def test_patch_conflict_does_not_touch_disk(self) -> None:
        record_id = self.web.create("冲突", password=SENTINEL_PW)
        stale = "2000-01-01T00:00:00.000000+00:00"
        status, data = self.web.json(
            "PATCH",
            f"/api/records/{record_id}",
            body={"changes": {"password": "attacker"}, "expected_updated": stale},
        )
        self.assertEqual(409, status)
        self.assertEqual("record_conflict", data["code"])
        conflict = data["conflict"]
        self.assertEqual(record_id, conflict["record_id"])
        self.assertEqual("stale", conflict["kind"])
        self.assertEqual(MASK, conflict["mine"]["password"], "冲突结构里 myself 只能是掩码")
        self.assertEqual(MASK, conflict["theirs"]["password"])

        # 关键断言：盘上未被覆盖
        reloaded = self.web.state.store.vault.find_by_id(record_id)
        self.assertEqual(SENTINEL_PW, reloaded.password)
        self.assertNotIn("attacker", json.dumps(data, ensure_ascii=False))

    def test_patch_requires_expected_updated(self) -> None:
        record_id = self.web.create("无锁")
        status, data = self.web.json(
            "PATCH", f"/api/records/{record_id}", body={"changes": {"url": "https://x"}}
        )
        self.assertEqual(400, status)
        self.assertEqual("missing_expected_updated", data["code"])

    def test_delete_needs_matching_title(self) -> None:
        record_id = self.web.create("要删的站点")

        status, data = self.web.json("DELETE", f"/api/records/{record_id}", body={})
        self.assertEqual(400, status)
        self.assertEqual("confirm_mismatch", data["code"])

        status, data = self.web.json(
            "DELETE", f"/api/records/{record_id}", body={"confirm_title": "别的标题"}
        )
        self.assertEqual(400, status)
        self.assertEqual("confirm_mismatch", data["code"])

        # 两次失败后记录仍在
        status, _ = self.web.json("GET", f"/api/records/{record_id}")
        self.assertEqual(200, status)

        status, data = self.web.json(
            "DELETE", f"/api/records/{record_id}", body={"confirm_title": "要删的站点"}
        )
        self.assertEqual(200, status)
        self.assertTrue(data["deleted"])

        status, data = self.web.json("GET", f"/api/records/{record_id}")
        self.assertEqual(404, status)
        self.assertEqual("record_not_found", data["code"])

    def test_copy_uses_in_process_timer(self) -> None:
        from unittest import mock

        record_id = self.web.create("要复制的", password=SENTINEL_PW)
        copied: list[str] = []

        def fake_copy(text: str) -> None:
            copied.append(text)

        with mock.patch("pwdvault.clipboard.copy_text", side_effect=fake_copy), mock.patch(
            "pwdvault.clipboard.process_clear_watcher", return_value=True
        ) as timer, mock.patch("pwdvault.clipboard.spawn_clear_watcher") as spawn:
            status, receipt = self.web.json(
                "POST", f"/api/records/{record_id}/copy", body={"field": "password"}
            )

        self.assertEqual(200, status)
        self.assertTrue(receipt["copied"])
        self.assertEqual("password", receipt["field"])
        self.assertEqual("要复制的", receipt["title"])
        self.assertTrue(receipt["auto_clear"])
        self.assertEqual(30, receipt["auto_clear_in"])
        self.assertEqual("process", receipt["auto_clear_mode"])
        self.assertEqual([SENTINEL_PW], copied, "复制时确实把明文交给了剪贴板")
        timer.assert_called_once()
        spawn.assert_not_called()
        self.assertNotIn(SENTINEL_PW, json.dumps(receipt, ensure_ascii=False))

    def test_tags_endpoint(self) -> None:
        self.web.create("A", username="a", password="p", tags=["工作", "邮箱"])
        self.web.create("B", username="b", password="p", tags=["工作"])
        status, data = self.web.json("GET", "/api/tags")
        self.assertEqual(200, status)
        self.assertEqual("工作", data["tags"][0]["name"])
        self.assertEqual(2, data["tags"][0]["count"])
        self.assertEqual(2, data["count"])


# ---------------------------------------------------------------- 复制的语义
class CopySemanticsTests(unittest.TestCase):
    """`copy_field` 的两个历史坑：位置参数、`seconds=0` 的倒计时谎报。"""

    def setUp(self) -> None:
        self.web = ApiFixture(self)

    def test_seconds_zero_disables_autoclear(self) -> None:
        """`clipboard_seconds=0` → 不装定时器，回执绝不出现「0 秒后清空」。"""
        from unittest import mock

        web = ApiFixture(self, clipboard_seconds=0)
        record_id = web.create("零秒", password=SENTINEL_PW)
        copied: list[str] = []

        with mock.patch("pwdvault.clipboard.copy_text", side_effect=copied.append), mock.patch(
            "pwdvault.clipboard.process_clear_watcher", return_value=True
        ) as timer, mock.patch("pwdvault.clipboard.spawn_clear_watcher") as spawn:
            status, receipt = web.json(
                "POST", f"/api/records/{record_id}/copy", body={"field": "password"}
            )

        self.assertEqual(200, status)
        self.assertEqual([SENTINEL_PW], copied, "0 秒也要真的把内容放进剪贴板")
        self.assertFalse(receipt["auto_clear"], "没装定时器就必须如实说 false")
        self.assertEqual(0, receipt["auto_clear_in"])
        self.assertNotEqual("process", receipt["auto_clear_mode"], "压根没装，不能说自己是 process")
        self.assertIn("手动", receipt["hint"], "关掉自动清空时必须提示用户自己覆盖")
        timer.assert_not_called()
        spawn.assert_not_called()
        self.assertNotIn(SENTINEL_PW, json.dumps(receipt, ensure_ascii=False))

    def test_copy_field_keyword_and_positional_contract(self) -> None:
        """钉死位置参数坑：`field` 与 `record` 撞车时必须明确报错，不能静默错位。"""
        from pwdvault import service
        from pwdvault.errors import InvalidRecord

        record = Record(title="钉死", password="pw-value")

        # ① 契约写法：关键字，永远正确
        receipt = service.copy_field(record, field="password", seconds=0, spawn=False)
        self.assertEqual("password", receipt["field"])

        # ② 第二个位置参数 + 显式 field 同时出现 → 歧义，必须报 invalid_record，
        #    而不是「按其中一个静默执行」（静默错位会让用户复制到别的字段）。
        with self.assertRaises(InvalidRecord) as ctx:
            service.copy_field(record, "password", field="url")
        self.assertEqual("invalid_record", ctx.exception.code)

        # ③ 只传第二个位置参数：service 里做了显式纠偏（视作 field），这条也钉住，
        #    避免以后有人把纠偏删掉却没人发现。
        body = service.copy_field(record, "password", seconds=0, spawn=False)
        self.assertEqual("password", body["field"])

    def test_api_uses_keyword_arguments_only(self) -> None:
        """源码级守卫：`web/api.py` 里禁止出现 `copy_field(record, "field")` 这种位置写法。"""
        source = (Path(__file__).resolve().parent.parent / "pwdvault" / "web" / "api.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("service.copy_field(", source)
        self.assertIn("field=field", source)
        self.assertIn("spawn=False", source)
        # 允许换行，但不允许「第二个参数直接是字符串字面量」的位置写法
        self.assertNotIn('copy_field(record, "', source)
        self.assertNotIn("copy_field(record, field)", source)


# ---------------------------------------------------------------- 暂存区
class StagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = ApiFixture(self)

    def test_staging_list_shape(self) -> None:
        batch_id = self.web.make_batch()
        status, data = self.web.json("GET", "/api/staging")
        self.assertEqual(200, status)
        self.assertEqual(1, data["count"])
        row = data["batches"][0]
        for key in ("id", "source_file", "status", "item_count", "origin", "age_seconds"):
            self.assertIn(key, row)
        self.assertEqual(batch_id, row["id"])
        self.assertEqual("drafted", row["status"])
        self.assertEqual("local", row["origin"])
        self.assertNotIn(SENTINEL_PW, json.dumps(data, ensure_ascii=False))

    def test_staging_detail_masks_draft_and_reveals_one(self) -> None:
        batch_id = self.web.make_batch()
        status, data = self.web.json("GET", f"/api/staging/{batch_id}")
        self.assertEqual(200, status)
        self.assertEqual(batch_id, data["batch"]["id"])
        self.assertEqual(1, len(data["items"]))
        item = data["items"][0]
        self.assertEqual(0, item["index"])
        self.assertEqual(
            {"title", "username", "password", "url", "notes", "totp", "tags", "fields"},
            set(item["draft"]),
        )
        self.assertEqual(MASK, item["draft"]["password"])
        self.assertNotIn(SENTINEL_PW, json.dumps(data, ensure_ascii=False))

        # 单取一条：?reveal=password&index=0
        status, revealed = self.web.json(
            "GET", f"/api/staging/{batch_id}?reveal=password&index=0"
        )
        self.assertEqual(200, status)
        self.assertEqual(SENTINEL_PW, revealed["value"])
        self.assertEqual(0, revealed["index"])
        log_text = audit.audit_path(self.web.settings).read_text(encoding="utf-8")
        self.assertIn("reveal", log_text)
        self.assertNotIn(SENTINEL_PW, log_text)

    def test_staging_edit_begin_end(self) -> None:
        batch_id = self.web.make_batch()
        status, data = self.web.json(
            "POST", f"/api/staging/{batch_id}/edit", body={"action": "begin"}
        )
        self.assertEqual(200, status)
        self.assertFalse(data["taken_over"], "第一次进入编辑不算接管")
        self.assertEqual("reviewing", data["status"])

        status, data = self.web.json(
            "POST", f"/api/staging/{batch_id}/edit", body={"action": "end"}
        )
        self.assertEqual(200, status)
        self.assertEqual("review", data["status"])

        # editor_id 也可以只放在头里
        status, data = self.web.json(
            "POST",
            f"/api/staging/{batch_id}/edit",
            body={"action": "begin"},
            headers={"X-PV-Editor-Id": "tab-42"},
        )
        self.assertEqual(200, status)
        self.assertEqual("tab-42", data["editor"])

    def test_staging_items_patch(self) -> None:
        batch_id = self.web.make_batch()
        status, data = self.web.json(
            "PATCH",
            f"/api/staging/{batch_id}/items",
            body={
                "editor_id": "tab-1",
                "items": [
                    {
                        "index": 0,
                        "draft": {"title": "改过的标题", "username": "user-b", "password": "新密码"},
                        "accepted": True,
                    }
                ],
            },
        )
        self.assertEqual(200, status)
        self.assertEqual(1, data["item_count"])
        self.assertEqual(1, data["accepted_count"])

        _, detail = self.web.json("GET", f"/api/staging/{batch_id}")
        item = detail["items"][0]
        self.assertEqual("改过的标题", item["draft"]["title"])
        self.assertEqual("user-b", item["draft"]["username"])
        self.assertTrue(item["edited"])
        self.assertEqual(MASK, item["draft"]["password"])
        self.assertNotIn("新密码", json.dumps(detail, ensure_ascii=False))

    def test_staging_commit_then_rollback(self) -> None:
        batch_id = self.web.make_batch(title="入库站点")
        before = self.web.state.count

        status, data = self.web.json(
            "POST", f"/api/staging/{batch_id}/commit", body={"editor_id": "tab-1"}
        )
        self.assertEqual(200, status)
        self.assertEqual(1, data["committed"])
        self.assertEqual(1, len(data["ids"]))
        self.assertEqual("committed", data["status"])
        self.assertEqual(before + 1, self.web.state.count, "库里记录数必须 +1")

        record_id = data["ids"][0]
        _, detail = self.web.json("GET", f"/api/records/{record_id}")
        self.assertEqual("入库站点", detail["title"])

        _, staging_detail = self.web.json("GET", f"/api/staging/{batch_id}")
        self.assertEqual("committed", staging_detail["batch"]["status"])

        status, data = self.web.json("POST", f"/api/staging/{batch_id}/rollback", body={})
        self.assertEqual(200, status)
        self.assertEqual(1, data["rolled_back"])
        self.assertEqual(before, self.web.state.count, "撤销后记录数必须回到提交前")

        _, staging_detail = self.web.json("GET", f"/api/staging/{batch_id}")
        self.assertEqual("rolled_back", staging_detail["batch"]["status"])

    def test_staging_discard(self) -> None:
        batch_id = self.web.make_batch(title="要丢弃的")
        status, data = self.web.json("POST", f"/api/staging/{batch_id}/discard", body={})
        self.assertEqual(200, status)
        self.assertTrue(data["discarded"])

        _, detail = self.web.json("GET", f"/api/staging/{batch_id}")
        self.assertEqual("discarded", detail["batch"]["status"])

    def test_staging_commit_twice_is_idempotent(self) -> None:
        batch_id = self.web.make_batch(title="只入一次")
        status, first = self.web.json("POST", f"/api/staging/{batch_id}/commit", body={})
        self.assertEqual(200, status)
        self.assertEqual(1, first["committed"])
        count_after_first = self.web.state.count

        status, second = self.web.json("POST", f"/api/staging/{batch_id}/commit", body={})
        self.assertEqual(200, status)
        self.assertEqual(0, second["committed"])
        self.assertTrue(second.get("already_committed"))
        self.assertEqual(count_after_first, self.web.state.count, "重复提交不许插出第二条")


# ---------------------------------------------------------------- inbox 上传
class UploadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = ApiFixture(self)

    def test_upload_sanitizes_filename(self) -> None:
        name = "../..\\补丁 密码.txt"
        status, data = self.web.json(
            "POST",
            "/api/inbox/upload",
            raw_body="账号 密码\n".encode("utf-8"),
            headers={
                "Content-Type": "application/octet-stream",
                "X-Filename": urllib.parse.quote(name),
            },
        )
        self.assertEqual(200, status)
        self.assertTrue(data["pending"])

        inbox = self.web.settings.inbox_path
        files = [path for path in inbox.iterdir() if path.is_file()]
        self.assertEqual(1, len(files), f"inbox 里应该有且只有一个文件：{files}")
        saved = files[0]
        self.assertEqual("补丁 密码.txt", saved.name)
        self.assertNotIn("..", saved.name)
        self.assertNotIn("/", saved.name)
        self.assertNotIn("\\", saved.name)
        self.assertEqual("账号 密码\n", saved.read_text(encoding="utf-8"))

    def test_upload_same_name_does_not_overwrite(self) -> None:
        body = b"a b c\n"
        for _ in range(2):
            status, _ = self.web.json(
                "POST",
                "/api/inbox/upload",
                raw_body=body,
                headers={"X-Filename": "same.txt"},
            )
            self.assertEqual(200, status)
        names = sorted(path.name for path in self.web.settings.inbox_path.iterdir() if path.is_file())
        self.assertEqual(2, len(names), names)
        self.assertIn("same.txt", names)
        self.assertIn("same-1.txt", names)

    def test_upload_rejects_empty_body(self) -> None:
        status, data = self.web.json(
            "POST", "/api/inbox/upload", raw_body=b"", headers={"X-Filename": "x.txt"}
        )
        self.assertEqual(400, status)
        self.assertEqual("empty_upload", data["code"])


# ---------------------------------------------------------------- 体检
class HealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = ApiFixture(self)

    def test_health_groups_titles_only(self) -> None:
        self.web.create("复用一", username="a", password=SENTINEL_PW)
        self.web.create("复用二", username="b", password=SENTINEL_PW)
        self.web.create("弱口令", username="c", password="123456")
        self.web.create("没有密码", username="d", password="")

        status, data = self.web.json("GET", "/api/health")
        self.assertEqual(200, status)
        for key in ("weak", "reused_groups", "stale", "no_password", "snapshot"):
            self.assertIn(key, data)

        groups = data["reused_groups"]
        self.assertEqual(1, len(groups))
        self.assertEqual(2, groups[0]["count"])
        self.assertEqual({"复用一", "复用二"}, set(groups[0]["titles"]))
        self.assertEqual({"titles", "count"}, set(groups[0]), "复用组只给标题")

        self.assertEqual(["没有密码"], [row["title"] for row in data["no_password"]])
        self.assertIn("弱口令", [row["title"] for row in data["weak"]])
        self.assertIn("last_days", data["snapshot"])
        self.assertIn("looks_synced", data["snapshot"])

        text = json.dumps(data, ensure_ascii=False)
        self.assertNotIn(SENTINEL_PW, text, "体检结果里绝不允许出现密码")
        self.assertNotIn("123456", text)


# ---------------------------------------------------------------- 未解锁
class LockedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = ApiFixture(self)
        self.record_id = self.web.create("锁前建的", password="pw")
        self.batch_id = self.web.make_batch()
        self.web.state.lock()

    def test_every_endpoint_requires_unlock(self) -> None:
        cases = [
            ("GET", "/api/records", None),
            ("POST", "/api/records", {"title": "x"}),
            ("GET", f"/api/records/{self.record_id}", None),
            (
                "PATCH",
                f"/api/records/{self.record_id}",
                {"changes": {"url": "u"}, "expected_updated": "2026-01-01T00:00:00+00:00"},
            ),
            ("DELETE", f"/api/records/{self.record_id}", {"confirm_title": "锁前建的"}),
            ("POST", f"/api/records/{self.record_id}/copy", {"field": "password"}),
            ("GET", "/api/tags", None),
            ("GET", f"/api/staging/{self.batch_id}", None),
            ("POST", f"/api/staging/{self.batch_id}/edit", {"action": "begin", "editor_id": "t"}),
            ("PATCH", f"/api/staging/{self.batch_id}/items", {"editor_id": "t", "items": [{"index": 0}]}),
            ("POST", f"/api/staging/{self.batch_id}/commit", {"editor_id": "t"}),
            ("POST", f"/api/staging/{self.batch_id}/rollback", {}),
            ("POST", "/api/inbox/upload", None),
            ("GET", "/api/health", None),
        ]
        for method, path, body in cases:
            kwargs: dict = {}
            if body is not None:
                kwargs["body"] = body
            if path == "/api/inbox/upload":
                kwargs["raw_body"] = b"x"
                kwargs["headers"] = {"X-Filename": "x.txt"}
            status, data = self.web.json(method, path, **kwargs)
            self.assertEqual(401, status, f"{method} {path} 未解锁时必须 401")
            self.assertEqual("locked", data["code"], f"{method} {path} 的 code 必须是 locked")

    def test_staging_list_works_while_locked(self) -> None:
        """暂存区列表只读外层元数据，锁着也能看（未解锁也能知道「有几批等着」）。"""
        status, data = self.web.json("GET", "/api/staging")
        self.assertEqual(200, status)
        self.assertEqual(1, data["count"])


# ---------------------------------------------------------------- MCP 接入配置
class McpConfigTests(unittest.TestCase):
    """`GET /api/mcp-config`：形状、真路径、工具清单动态一致、不含主密码。

    这里的核心断言不是「返回了 JSON」，而是「返回的配置**真的能启动 MCP 进程**」——
    `test_config_actually_launches_mcp_process` 会照抄响应里的 command/args/env
    起一个真子进程、发 `initialize` 与 `tools/list`，握手成功才算通过。
    只断言字段齐全的话，一个把 `args` 写成 `["mcp"]`（子命令还不存在）的实现
    也能骗过测试，而用户粘贴后看到的是「连接器里一个工具都没有」。
    """

    def setUp(self) -> None:
        self.web = ApiFixture(self)

    # ---- 便捷
    def config(self) -> dict:
        status, data = self.web.json("GET", "/api/mcp-config")
        self.assertEqual(200, status, data)
        return data

    @staticmethod
    def entry_of(data: dict, client: str) -> dict:
        """按客户端取那一份 `{command, args, env}`（两个客户端的包装层级不同）。"""
        if client == "workbuddy":
            return data["workbuddy"]["config"]["pwdvault"]
        return data["deepseek_harness"]["config"]["mcpServers"]["pwdvault"]

    def _roundtrip(self, proc, payload: dict, *, timeout: float = 25.0) -> dict:
        """往子进程写一帧、读一帧（读操作放进线程，进程卡死时不会把整个测试挂住）。"""
        proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        proc.stdin.flush()
        box: dict = {}

        def reader() -> None:
            box["line"] = proc.stdout.readline()

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        thread.join(timeout)
        self.assertFalse(thread.is_alive(), f"MCP 进程 {timeout} 秒内没有响应 {payload['method']}")
        raw = box.get("line") or b""
        self.assertTrue(raw, f"MCP 进程对 {payload['method']} 一个字都没输出（多半是启动就崩了）")
        return json.loads(raw.decode("utf-8"))

    # ---- 形状与路径
    def test_paths_are_absolute_and_real(self) -> None:
        data = self.config()
        self.assertTrue(data["python"], "python 不该是 null：sys.executable 是真实解释器")
        python = Path(data["python"])
        self.assertTrue(python.is_absolute(), data["python"])
        self.assertTrue(python.is_file(), f"{data['python']} 不是真实文件")

        self.assertTrue(data["entry"], "entry 不该是 null：pv.py 就在项目根")
        entry = Path(data["entry"])
        self.assertTrue(entry.is_absolute(), data["entry"])
        self.assertTrue(entry.is_file(), f"{data['entry']} 不是真实文件")
        self.assertEqual("pv.py", entry.name)

        self.assertEqual(
            str(Path(self.web.settings.vault_path).resolve()),
            data["vault"],
        )
        self.assertTrue(Path(data["vault"]).is_absolute())

    def test_server_entry_is_pasteable(self) -> None:
        data = self.config()
        for client in ("workbuddy", "deepseek_harness"):
            entry = self.entry_of(data, client)
            self.assertEqual(data["python"], entry["command"], client)
            args = [str(item) for item in entry["args"]]
            self.assertTrue(args, f"{client} 的 args 不能为空")
            joined = " ".join([str(entry["command"]), *args])
            self.assertIn("mcp", joined, f"{client} 的启动命令里必须真的跑 mcp：{joined}")
            self.assertEqual(data["vault"], entry["env"]["PV_VAULT"], client)
            # 正常配置走 `[<pv.py 绝对路径>, "mcp"]`：args[0] 必须是 pv.py 本体，
            # 这样脚本会把自己的目录插进 sys.path，**不需要 PYTHONPATH**。
            self.assertEqual(data["entry"], args[0], f"{client} 的 args[0] 必须是 pv.py 的绝对路径")
            self.assertEqual("mcp", args[1], client)
            self.assertNotIn(
                "PYTHONPATH",
                entry["env"],
                f"{client} 不该再带 PYTHONPATH（pv.py 自己会处理 sys.path）",
            )
            # 主密码绝不能出现在客户端配置里（键和值都不行）
            self.assertNotIn("PV_MASTER_PASSWORD", entry["env"], client)
            self.assertNotIn("PV_MASTER_PASSWORD", json.dumps(entry, ensure_ascii=False), client)

    def test_hints_mention_restart_and_trust(self) -> None:
        data = self.config()
        self.assertIn("重启", data["workbuddy"]["hint"])
        self.assertIn("mcpServers", data["workbuddy"]["hint"])
        self.assertIn("stdio", data["deepseek_harness"]["hint"])
        notes = "\n".join(data["notes"])
        for keyword in ("PV_MASTER_PASSWORD", "local-unlock", "重启", "locked"):
            self.assertIn(keyword, notes, f"notes 里缺少「{keyword}」这条关键说明")

    # ---- 工具清单：必须与注册表动态一致
    def test_tools_match_registry(self) -> None:
        from pwdvault.mcp_tools import TOOLS  # 延迟导入：只在需要时依赖 L4

        expected = [spec.name for spec in TOOLS]
        self.assertEqual(expected, self.config()["tools"])
        # 反向对照：证明不是「什么都没返回」也能过
        self.assertIn("vault_copy", expected)
        self.assertIn("vault_status", expected)
        # 这四个工具**故意不存在**（删除/主密码/批量落库只允许人在界面上做）
        for missing in (
            "vault_delete",
            "vault_staging_commit",
            "vault_import_batch",
            "vault_change_master_password",
        ):
            self.assertNotIn(missing, expected)

    # ---- 不含任何记录数据
    def test_no_vault_secrets_in_response(self) -> None:
        self.web.create("MCP 哨兵", username="probe", password=SENTINEL_PW)
        blob = json.dumps(self.config(), ensure_ascii=False)
        self.assertNotIn(SENTINEL_PW, blob)
        self.assertNotIn("MCP 哨兵", blob)

    # ---- 真进程握手：配置可用性的最终证明
    def test_config_actually_launches_mcp_process(self) -> None:
        data = self.config()
        entry = self.entry_of(data, "deepseek_harness")
        command = [str(entry["command"]), *[str(item) for item in entry["args"]]]
        environ = os.environ.copy()
        environ.update({str(key): str(value) for key, value in entry["env"].items()})

        # cwd 故意用临时目录：证明这份配置不依赖「在项目目录下启动」
        proc = subprocess.Popen(
            command,
            cwd=tempfile.gettempdir(),
            env=environ,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            hello = self._roundtrip(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test_web_api", "version": "0"},
                    },
                },
            )
            self.assertEqual("pwdvault", hello["result"]["serverInfo"]["name"])
            listing = self._roundtrip(
                proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            )
            listed = [tool["name"] for tool in listing["result"]["tools"]]
            # 配置里报的工具清单必须与真进程报的一致（否则文档/UI 在骗人）
            self.assertEqual(data["tools"], listed)
        finally:
            proc.kill()
            proc.communicate(timeout=15)


class McpConfigAccessTests(unittest.TestCase):
    """接入配置「不需要解锁」，但仍然需要 token（它暴露本机绝对路径）。"""

    def test_works_while_locked(self) -> None:
        web = ApiFixture(self, unlock=False)
        status, data = web.json("GET", "/api/mcp-config")
        self.assertEqual(200, status, data)
        self.assertTrue(data["python"])
        self.assertTrue(data["tools"])

    def test_requires_session_token(self) -> None:
        web = ApiFixture(self)
        status, _, _ = web.request(
            "GET", "/api/mcp-config", headers={TOKEN_HEADER: "definitely-not-the-token"}
        )
        self.assertEqual(401, status)


# ---------------------------------------------------------------- 全局哨兵
class GlobalSentinelTests(unittest.TestCase):
    def test_no_sentinel_in_any_response(self) -> None:
        web = ApiFixture(self)
        record_id = web.create(
            "哨兵",
            username="probe",
            password=SENTINEL_PW,
            notes=SENTINEL_NOTE,
            fields={"API Key": SENTINEL_CUSTOM},
        )
        batch_id = web.make_batch()

        probes = [
            ("GET", "/api/session"),
            ("GET", "/api/records"),
            ("GET", "/api/records?q=" + urllib.parse.quote("哨兵")),
            ("GET", f"/api/records/{record_id}"),
            ("GET", "/api/tags"),
            ("GET", "/api/staging"),
            ("GET", f"/api/staging/{batch_id}"),
            ("GET", "/api/health"),
            ("GET", "/api/mcp-config"),
        ]
        blob: list[str] = []
        for method, path in probes:
            status, _, data = web.request(method, path)
            self.assertEqual(200, status, f"{method} {path} 应该成功")
            blob.append(data.decode("utf-8"))
        joined = "\n".join(blob)
        self.assertNotIn(SENTINEL_PW, joined)
        self.assertNotIn(SENTINEL_CUSTOM, joined)
        # 反向对照：备注本来就该明文（证明上面的断言不是「什么都没返回」）
        self.assertIn(SENTINEL_NOTE, joined)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
