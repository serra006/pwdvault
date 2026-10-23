"""库级维护的 Web 接口（T13）：建库 / 改主密码 / 恢复码 / 本机免密 / 导出明文。

这五个能力原本只有 CLI（`pv init` / `pv passwd` / `pv recovery` / `pv local-unlock` /
`pv export`），本轮补的是**同一套能力的 HTTP 后端**。除了覆盖 happy path，这里钉住
三件容易被写错的事：

1. **`POST /api/setup` 必须挂在会话层**：`api.py` 的路由全被 `_guard_locked()` 包住，
   而建库时库还不存在、必然未解锁 —— 挂过去会被一律挡成 401 + `locked`。
2. **恢复码只在响应里出现一次**：断言它能在响应里拿到、且**搜不到**任何落盘/日志痕迹
   （库文件与审计文件里都不出现该字符串）。
3. **导出明文先审计再输出**：断言 `audit.jsonl` 里多了一条 `action="export"`，
   且 `?confirm=1` 缺失时 400（这是本产品最高危的动作）。

其余 4 个接口在**未解锁**时必须 401 + `code == "locked"`（`_guard_locked` 的唯一
翻译点生效）。

harness 直接沿用 `test_web_api.ApiFixture` 的构造方式（临时 home + 真 `WebServer`
+ token 头），不另起一套。
"""

from __future__ import annotations

import http.client
import json
import sys
import unittest
import urllib.parse
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault import audit, importers
from pwdvault.config import Settings
from pwdvault.errors import VaultError
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record
from pwdvault.vault import Vault
from pwdvault.web.server import TOKEN_HEADER, WebServer

TOKEN = "test-vault-admin-token-0123456789"

#: 6 个随机词 ≈ 77 bit（`score_secret` 的词表算法），过 55 bit 门槛。
STRONG = "橘子 铁路 钢琴 沙漠 灯塔 折纸"
STRONG2 = "海豚 蜡烛 信封 河流 手套 姜茶"
#: 3 个小写字母 ≈ 14 bit，稳稳落在「弱」。
WEAK = "abc"


class AdminFixture:
    """起一个真 `WebServer`（临时端口 + 临时库）。

    `vault=False` → 只准备 home 与 settings，**不建库**，用来测 `/api/setup`。
    """

    def __init__(self, case: unittest.TestCase, *, vault: bool = True) -> None:
        self.home = support.make_home(case)
        self.settings = replace(
            Settings(
                vault_path=self.home / "data.enc",
                snapshot_keep=2,
                kdf=dict(support.FAST_KDF),
            ),
            inbox_interval_seconds=60.0,
            lock_timeout_seconds=20.0,
        )
        self.password = support.PASSWORD
        self.recovery = ""
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
        if vault:
            fixture = support.make_vault(self.home, snapshot_keep=2)
            self.password = fixture.password
            self.recovery = fixture.recovery
            self.httpd.state.unlock(password=self.password)

    def _join(self) -> None:
        self._thread.join(timeout=5.0)

    @property
    def port(self) -> int:
        return self.httpd.port

    @property
    def state(self):
        return self.httpd.state

    @property
    def store(self) -> VaultStore:
        return self.httpd.state.require_unlocked()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: object = None,
        headers: dict | None = None,
    ) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        sent: dict[str, str] = {TOKEN_HEADER: TOKEN}
        if headers:
            sent.update({str(k): str(v) for k, v in headers.items()})
        payload: bytes | None = None
        if body is not None:
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

    def add_records(self, *titles: str) -> None:
        """直接走 `VaultStore.commit` 塞几条记录（本文件不测 CRUD，那是 T09 的活）。"""
        self.store.commit(
            [
                Operation.add(
                    Record(title=title, username="someone", password=support.SENTINEL_PW)
                )
                for title in titles
            ]
        )


# ---------------------------------------------------------------- 建库
class SetupTests(unittest.TestCase):
    def _empty(self) -> AdminFixture:
        return AdminFixture(self, vault=False)

    def test_setup_creates_vault_and_unlocks_session(self) -> None:
        web = self._empty()
        self.assertFalse(web.settings.vault_path.exists())

        status, payload = web.json(
            "POST",
            "/api/setup",
            body={"password": STRONG, "confirm": STRONG, "local_unlock": False, "label": "测试库"},
        )
        self.assertEqual(200, status, payload)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["session"]["unlocked"])
        self.assertTrue(payload["session"]["vault_exists"])
        self.assertFalse(payload["local_unlock"])
        self.assertEqual(str(web.settings.vault_path), payload["vault"])

        code = payload["recovery_code"]
        # 恢复码形如 XXXX-XXXX-...（32 字节 base32，13 组 4 字符）
        self.assertRegex(code, r"^[A-Z2-7]{4}(-[A-Z2-7]{4})+$")
        self.assertEqual(13, len(code.split("-")))
        self.assertTrue(web.settings.vault_path.exists())
        # 新库能用主密码打开，也能用恢复码打开
        self.assertTrue(Vault.open(web.settings, password=STRONG).has_method("password"))
        Vault.open(web.settings, recovery_code=code)

    def test_recovery_code_never_lands_on_disk(self) -> None:
        """恢复码只在这一次响应里出现：库文件与审计文件里都不许有它。"""
        web = self._empty()
        status, payload = web.json(
            "POST", "/api/setup", body={"password": STRONG, "confirm": STRONG}
        )
        self.assertEqual(200, status, payload)
        code = payload["recovery_code"]

        self.assertNotIn(code, web.settings.vault_path.read_text(encoding="utf-8"))
        audit_file = audit.audit_path(web.settings)
        if audit_file.is_file():
            self.assertNotIn(code, audit_file.read_text(encoding="utf-8"))

    def test_setup_rejects_existing_vault(self) -> None:
        web = AdminFixture(self)
        status, payload = web.json(
            "POST", "/api/setup", body={"password": STRONG, "confirm": STRONG}
        )
        self.assertEqual(409, status)
        self.assertEqual("already_exists", payload["code"])

    def test_setup_rejects_mismatch_and_empty(self) -> None:
        web = self._empty()
        status, payload = web.json(
            "POST", "/api/setup", body={"password": STRONG, "confirm": STRONG2}
        )
        self.assertEqual(400, status)
        self.assertEqual("password_mismatch", payload["code"])

        status, payload = web.json("POST", "/api/setup", body={"password": "", "confirm": ""})
        self.assertEqual(400, status)
        self.assertEqual("missing_password", payload["code"])
        self.assertFalse(web.settings.vault_path.exists(), "失败时不能留下半个库")

    def test_setup_rejects_weak_password(self) -> None:
        web = self._empty()
        status, payload = web.json("POST", "/api/setup", body={"password": WEAK, "confirm": WEAK})
        self.assertEqual(422, status)
        self.assertEqual("weak_password", payload["code"])
        self.assertIn("entropy", payload)
        self.assertIn("level", payload)
        self.assertLess(payload["entropy"], 55)
        self.assertFalse(web.settings.vault_path.exists())

    def test_setup_force_accepts_weak_password(self) -> None:
        web = self._empty()
        status, payload = web.json(
            "POST",
            "/api/setup",
            body={"password": WEAK, "confirm": WEAK, "force": True, "local_unlock": False},
        )
        self.assertEqual(200, status, payload)
        self.assertTrue(payload["ok"])
        Vault.open(web.settings, password=WEAK)


# ---------------------------------------------------------------- 改主密码
class PasswordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = AdminFixture(self)

    def test_change_password_works_with_new_password(self) -> None:
        status, payload = self.web.json(
            "POST",
            "/api/vault/password",
            body={"current": self.web.password, "new": STRONG, "confirm": STRONG},
        )
        self.assertEqual(200, status, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(0, payload["records"])

        # 新密码能开，旧密码不能开
        Vault.open(self.web.settings, password=STRONG)
        with self.assertRaises(VaultError):
            Vault.open(self.web.settings, password=self.web.password)

    def test_change_password_keeps_recovery_code(self) -> None:
        """改主密码只重包 DEK，恢复码必须仍然有效（CLI 也是这个语义）。"""
        self.web.add_records("改密后仍在")
        status, _ = self.web.json(
            "POST",
            "/api/vault/password",
            body={"current": self.web.password, "new": STRONG, "confirm": STRONG},
        )
        self.assertEqual(200, status)
        opened = Vault.open(self.web.settings, recovery_code=self.web.recovery)
        self.assertEqual(1, len(opened.records))

    def test_change_password_needs_no_current_when_unlocked_by_recovery(self) -> None:
        """用恢复码进来的人手上没有旧主密码，不该被 `current` 卡住。"""
        web = AdminFixture(self, vault=False)
        fixture = support.make_vault(web.home, snapshot_keep=2)
        web.state.unlock(recovery_code=fixture.recovery)
        self.assertEqual("recovery", web.state.vault.unlocked_by)

        status, payload = web.json(
            "POST", "/api/vault/password", body={"new": STRONG, "confirm": STRONG}
        )
        self.assertEqual(200, status, payload)
        Vault.open(web.settings, password=STRONG)

    def test_change_password_rejects_mismatch_and_weak(self) -> None:
        status, payload = self.web.json(
            "POST",
            "/api/vault/password",
            body={"current": self.web.password, "new": STRONG, "confirm": STRONG2},
        )
        self.assertEqual(400, status)
        self.assertEqual("password_mismatch", payload["code"])

        status, payload = self.web.json(
            "POST",
            "/api/vault/password",
            body={"current": self.web.password, "new": WEAK, "confirm": WEAK},
        )
        self.assertEqual(422, status)
        self.assertEqual("weak_password", payload["code"])
        self.assertIn("entropy", payload)

        # force 可以绕过强度门槛
        status, payload = self.web.json(
            "POST",
            "/api/vault/password",
            body={"current": self.web.password, "new": WEAK, "confirm": WEAK, "force": True},
        )
        self.assertEqual(200, status, payload)

    def test_change_password_rejects_wrong_current(self) -> None:
        status, payload = self.web.json(
            "POST",
            "/api/vault/password",
            body={"current": "不是这个密码", "new": STRONG, "confirm": STRONG},
        )
        self.assertEqual(403, status)
        self.assertEqual("bad_current_password", payload["code"])
        # 失败了就没改：旧密码仍然有效
        Vault.open(self.web.settings, password=self.web.password)

    def test_change_password_requires_current_when_unlocked_by_password(self) -> None:
        status, payload = self.web.json(
            "POST", "/api/vault/password", body={"new": STRONG, "confirm": STRONG}
        )
        self.assertEqual(400, status)
        self.assertEqual("missing_current_password", payload["code"])


# ---------------------------------------------------------------- 恢复码
class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = AdminFixture(self)

    def test_reset_recovery_invalidates_old_code(self) -> None:
        old = self.web.recovery
        status, payload = self.web.json("POST", "/api/vault/recovery", body={"confirm": True})
        self.assertEqual(200, status, payload)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["old_invalidated"])
        new = payload["recovery_code"]
        self.assertTrue(new)
        self.assertNotEqual(old, new)

        Vault.open(self.web.settings, recovery_code=new)
        with self.assertRaises(VaultError):
            Vault.open(self.web.settings, recovery_code=old)

    def test_reset_recovery_needs_confirm(self) -> None:
        status, payload = self.web.json("POST", "/api/vault/recovery", body={})
        self.assertEqual(400, status)
        self.assertEqual("need_confirm", payload["code"])
        # 没确认就没重置：旧码仍然有效
        Vault.open(self.web.settings, recovery_code=self.web.recovery)


# ---------------------------------------------------------------- 本机免密
class LocalUnlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = AdminFixture(self)

    @unittest.skipUnless(sys.platform == "win32", "DPAPI 只在 Windows 上可用")
    def test_enable_then_disable(self) -> None:
        status, payload = self.web.json(
            "POST", "/api/vault/local-unlock", body={"enabled": True}
        )
        self.assertEqual(200, status, payload)
        self.assertTrue(payload["enabled"])
        self.assertTrue(Vault.open(self.web.settings, password=self.web.password).has_method("dpapi"))

        status, payload = self.web.json(
            "POST", "/api/vault/local-unlock", body={"enabled": False}
        )
        self.assertEqual(200, status, payload)
        self.assertFalse(payload["enabled"])
        self.assertFalse(Vault.open(self.web.settings, password=self.web.password).has_method("dpapi"))

    @unittest.skipIf(sys.platform == "win32", "非 Windows 分支")
    def test_rejected_on_non_windows(self) -> None:
        status, payload = self.web.json(
            "POST", "/api/vault/local-unlock", body={"enabled": True}
        )
        self.assertEqual(400, status)
        self.assertEqual("dpapi_unavailable", payload["code"])

    def test_missing_enabled(self) -> None:
        status, payload = self.web.json("POST", "/api/vault/local-unlock", body={})
        self.assertEqual(400, status)
        self.assertEqual("missing_enabled", payload["code"])


# ---------------------------------------------------------------- 导出明文
class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = AdminFixture(self)
        self.web.add_records("导出甲", "导出乙", "别的记录")
        self.audit_file = audit.audit_path(self.web.settings)

    def _audit_rows(self) -> list[dict]:
        if not self.audit_file.is_file():
            return []
        return [
            json.loads(line)
            for line in self.audit_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_export_needs_confirm(self) -> None:
        status, payload = self.web.json("GET", "/api/export")
        self.assertEqual(400, status)
        self.assertEqual("need_confirm", payload["code"])
        self.assertIn("明文", payload["message"])

    def test_export_rejects_bad_format(self) -> None:
        status, payload = self.web.json("GET", "/api/export?confirm=1&format=xml")
        self.assertEqual(400, status)
        self.assertEqual("bad_format", payload["code"])

    def test_export_json(self) -> None:
        status, headers, body = self.web.request("GET", "/api/export?confirm=1&format=json")
        self.assertEqual(200, status)
        self.assertIn("application/json", headers["content-type"])
        self.assertTrue(headers["content-disposition"].startswith("attachment;"))
        self.assertIn("pwdvault-export-", headers["content-disposition"])
        self.assertIn(".json", headers["content-disposition"])

        records = importers.parse_json(body.decode("utf-8"))
        self.assertEqual(3, len(records))
        self.assertEqual({r.title for r in records}, {"导出甲", "导出乙", "别的记录"})
        # 导出是明文：哨兵密码必须原样在（这里不脱敏，脱敏了就没有导出意义）
        self.assertIn(support.SENTINEL_PW, body.decode("utf-8"))

    def test_export_csv(self) -> None:
        status, headers, body = self.web.request("GET", "/api/export?confirm=1&format=csv")
        self.assertEqual(200, status)
        self.assertIn("text/csv", headers["content-type"])
        self.assertIn(".csv", headers["content-disposition"])
        records = importers.parse_csv(body.decode("utf-8"))
        self.assertEqual(3, len(records))

    def test_export_filters_by_query(self) -> None:
        # 中文查询词必须 URL 编码：`http.client` 的请求行只吃 ASCII
        status, headers, body = self.web.request(
            "GET", "/api/export?confirm=1&q=" + urllib.parse.quote("导出")
        )
        self.assertEqual(200, status)
        records = importers.parse_json(body.decode("utf-8"))
        self.assertEqual(2, len(records))

    def test_export_writes_audit_entry(self) -> None:
        before = len(self._audit_rows())
        status, _, _ = self.web.request("GET", "/api/export?confirm=1&format=csv")
        self.assertEqual(200, status)
        rows = self._audit_rows()
        self.assertEqual(before + 1, len(rows))
        entry = rows[-1]
        self.assertEqual("export", entry["action"])
        self.assertEqual("web", entry["actor"])
        self.assertEqual("csv", entry["field_name"])
        self.assertEqual(3, entry["count"])
        # 审计里绝不能出现任何值
        self.assertNotIn(support.SENTINEL_PW, json.dumps(entry, ensure_ascii=False))


# ---------------------------------------------------------------- 未解锁
class LockedGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = AdminFixture(self, vault=True)
        self.web.state.lock()
        self.assertFalse(self.web.state.unlocked)

    def test_all_four_endpoints_return_locked(self) -> None:
        cases = [
            (
                "POST",
                "/api/vault/password",
                {"current": self.web.password, "new": STRONG, "confirm": STRONG},
            ),
            ("POST", "/api/vault/recovery", {"confirm": True}),
            ("POST", "/api/vault/local-unlock", {"enabled": True}),
        ]
        for method, path, body in cases:
            with self.subTest(path=path):
                status, payload = self.web.json(method, path, body=body)
                self.assertEqual(401, status)
                self.assertEqual("locked", payload["code"])

        with self.subTest(path="/api/export"):
            status, payload = self.web.json("GET", "/api/export?confirm=1")
            self.assertEqual(401, status)
            self.assertEqual("locked", payload["code"])

    def test_locked_beats_input_validation(self) -> None:
        """锁着时，**参数不合法**也必须是 401，不能是 400/422。

        `_guard_locked` 只翻译 `Locked`，不主动查锁 —— 所以 handler 必须把
        `_store(req)` 放在参数校验**之前**。否则锁着时会先被参数校验挡下来，
        既违反 api.py 顶部「未解锁一律 401 + locked」的纪律，也等于把
        「密码强度校验器」暴露成了一个不需要任何凭据的探针。
        """
        bad_cases = [
            # 弱密码：不先查锁的话会走到 weak_password_response → 422
            ("POST", "/api/vault/password", {"new": "x", "confirm": "x"}),
            # 两次不一致：不先查锁的话 → 400 password_mismatch
            ("POST", "/api/vault/password", {"new": STRONG, "confirm": "不一样"}),
            # 缺 confirm：不先查锁的话 → 400 need_confirm
            ("POST", "/api/vault/recovery", {}),
            # 缺 enabled：不先查锁的话 → 400 missing_enabled
            ("POST", "/api/vault/local-unlock", {}),
            # 缺 confirm=1：不先查锁的话 → 400 need_confirm
            ("GET", "/api/export", None),
        ]
        for method, path, body in bad_cases:
            with self.subTest(path=path, body=body):
                status, payload = self.web.json(method, path, body=body)
                self.assertEqual(401, status, f"期望 401 locked，实得 {status} {payload}")
                self.assertEqual("locked", payload["code"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
