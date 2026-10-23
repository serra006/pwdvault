"""导出明文的审计闭环 + `Record.__repr__` 不泄密（O-1 / O-3 的回归钉子）。

## 为什么导出必须被审计

`pv export` 是这个产品里**唯一**一个「一次性把全部密码吐到不加密文件里」的命令。
它绕过密文、绕过掩码、绕过剪贴板 30 秒回掩，所以它是审计里最该有记录的动作。
修复前的事实：`audit.ACTIONS` 白名单里没有 `export`，`cmd_export` 也从来没调用
`audit.append` —— 也就是说**导出明文完全不留痕迹**，连一行 WARNING 都不会有。
（比「打了 WARNING 但没写进文件」更糟：连出事的迹象都没有。）

## 为什么 `__repr__` 要单独钉

`Record` 是 dataclass，默认 `__repr__` 会把 `password` / `totp` / 敏感自定义字段的
明文全部打出来。当前所有日志路径都没这么写过（QA 已 grep 验证），但「谁写一句
`f"{record}"` 就泄密」这种地雷，只能靠显式 `__repr__` + 这条用例按住。

## 注意

导出**必须**是明文，否则这个命令没有存在意义。所以这里的断言是「审计与提示到位」，
而不是「导出被脱敏」—— 顺手把导出改成掩码会是一个比原缺陷更糟的「假安全」。
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support
from pwdvault import audit, cli
from pwdvault.config import load_settings
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record, is_sensitive_key


class ExportAuditTests(unittest.TestCase):
    """`pv export --yes` 必须留下「谁、什么时候、多少条」，且不含任何值。"""

    def setUp(self) -> None:
        self.home = support.make_home(self)
        support.write_config(self.home, self.home / "data.enc")
        # 用 load_settings 而不是夹具里的 Settings：`pv` 子进程读的是 config.toml，
        # 父进程必须读同一份，否则「配置是否生效」的断言会变成假绿（夹具陷阱，见 _support）。
        with mock.patch.dict(os.environ, {"PV_HOME": str(self.home)}):
            self.settings = load_settings()
        from pwdvault.vault import Vault

        vault, self.recovery = Vault.create(self.settings, support.PASSWORD)
        store = VaultStore(self.settings, vault)
        store.commit(
            [
                Operation.add(
                    Record(
                        title="导出哨兵",
                        username="audit-user",
                        password=support.SENTINEL_PW,
                        notes=support.SENTINEL_NOTE,
                        fields={"密保问题": support.SENTINEL_CUSTOM},
                    )
                )
            ]
        )
        self.audit_file = audit.audit_path(self.settings)

    def _export(self, *extra: str) -> support.subprocess.CompletedProcess:
        return support.run_py(
            ["export", "--yes", *extra],
            home=self.home,
            env={"PV_MASTER_PASSWORD": support.PASSWORD},
        )

    def _audit_rows(self) -> list[dict]:
        if not self.audit_file.is_file():
            return []
        text = self.audit_file.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def test_export_to_file_writes_one_audit_entry(self) -> None:
        out = self.home / "plain.json"
        result = self._export("--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out.is_file(), "导出文件没生成")

        rows = [row for row in self._audit_rows() if row["action"] == "export"]
        self.assertEqual(len(rows), 1, f"导出没有被审计：{self._audit_rows()}")
        row = rows[0]
        self.assertEqual(row["actor"], "cli")
        self.assertEqual(row["count"], 1, "条数必须记下来")
        self.assertEqual(row["ok"], True)
        # 键集合必须仍是那 7 个：审计行里不许出现任何字段值
        self.assertTrue(set(row) <= set(audit.ENTRY_KEYS), row)

    def test_export_to_stdout_is_also_audited(self) -> None:
        """默认 `--out -` 也要审计：明文的去向是终端/管道，同样不安全。"""
        result = self._export()
        self.assertEqual(result.returncode, 0, result.stderr)
        actions = [row["action"] for row in self._audit_rows()]
        self.assertIn("export", actions)

    def test_export_audit_row_contains_no_field_values(self) -> None:
        out = self.home / "plain.json"
        self._export("--out", str(out))
        text = self.audit_file.read_text(encoding="utf-8")
        for sentinel in (support.SENTINEL_PW, support.SENTINEL_CUSTOM, support.SENTINEL_NOTE, "audit-user"):
            self.assertNotIn(sentinel, text, f"审计文件泄露了 {sentinel}")

    def test_export_file_is_still_plaintext(self) -> None:
        """导出**必须**是明文，否则这个命令就没有意义（不许「顺手脱敏」）。"""
        out = self.home / "plain.json"
        self._export("--out", str(out))
        body = out.read_text(encoding="utf-8")
        self.assertIn(support.SENTINEL_PW, body, "导出必须是明文")

    def test_export_warns_on_stderr_not_stdout(self) -> None:
        """警示必须走 stderr：`--json` 时 stdout 会被下游当 JSON 解析。"""
        out = self.home / "plain.json"
        result = self._export("--out", str(out), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("明文", result.stderr, "stderr 没有警示")
        json.loads(result.stdout)  # --json 的 stdout 必须仍是合法 JSON
        self.assertNotIn("明文", result.stdout, "警示污染了 stdout")


class AuditStrictModeTests(unittest.TestCase):
    """未知动作 = 编程错误：默认必须炸，只有 PV_AUDIT_STRICT=0 才降级。"""

    def setUp(self) -> None:
        self.home = support.make_home(self)
        self.settings = support.make_vault(self.home).settings

    def test_default_is_strict(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(audit.AUDIT_STRICT_ENV, None)
            self.assertTrue(audit.is_strict())

    def test_unknown_action_raises_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(audit.AUDIT_STRICT_ENV, None)
            with self.assertRaises(RuntimeError):
                audit.append(self.settings, action="definitely-not-an-action")

    def test_unknown_action_degrades_when_strict_disabled(self) -> None:
        with mock.patch.dict(os.environ, {audit.AUDIT_STRICT_ENV: "0"}):
            self.assertFalse(audit.is_strict())
            self.assertFalse(audit.append(self.settings, action="definitely-not-an-action"))

    def test_io_failure_never_raises_even_in_strict_mode(self) -> None:
        """I/O 失败（磁盘/权限）必须永远降级：审计不能把用户的操作打断。"""
        blocker = Path(self.settings.logs_dir)
        if blocker.exists():
            for item in blocker.rglob("*"):
                if item.is_file():
                    item.unlink()
            blocker.rmdir()
        blocker.write_text("我是文件，不是目录", encoding="utf-8")
        self.assertFalse(audit.append(self.settings, action="add", record_id="abc", count=1))

    def test_export_is_in_the_whitelist(self) -> None:
        self.assertIn("export", audit.ACTIONS)
        entry = audit.build_entry(action="export", actor="cli", count=3)
        self.assertEqual(entry["action"], "export")
        self.assertEqual(set(entry), set(audit.ENTRY_KEYS))


class RecordReprTests(unittest.TestCase):
    """O-3：记录**不可能**因为「顺手打印一下」而泄密。

    ## 为什么是 5 条断言而不是 1 条

    `__repr__` 只挡住「把 Record 对象本身格式化」这一条路径，而这条路径有 5 种写法，
    任何一个没被 `__repr__` 覆盖到（例如将来有人给 `Record` 加 `__format__` 或
    `__str__` 覆盖）就等于没修：

        repr(rec) / str(rec) / f"{rec}" / "%s" % rec / "{}".format(rec)

    Python 里后三种都会落到 `__format__` → `__str__` → `__repr__` 这条链上，
    但**链路是会变的**，所以逐条钉住。

    ## 已知会吐明文、但**故意不断言其安全**的两个出口

    - `rec.fields` —— 直接打印 dict 必然带明文（它就是数据本身）；
    - `rec.to_dict()` —— 默认 `mask_secrets=False`，是落盘/传输形态，不是给人看的口子。

    这两个是**程序内部数据通路**，要求它们脱敏等于要求「加密前先脱敏」，会把功能废掉。
    这条用例只负责证明「没有日志调用点把它们直接送出去」。核对方式：
    `log_event()`（config.py:324）白名单只允许 event/code/id/field/count/revision/ms/
    purpose/state 十个字段，`frozenset` 之外的值没有出口；全仓库 `log_event(` 调用点
    grep 过一遍，没有任何一处传 `record` / `record.fields` / `to_dict()`。
    """

    def _record(self) -> Record:
        return Record(
            title="淘宝",
            username="zhangsan",
            password=support.SENTINEL_PW,
            totp="JBSWY3DPEHPK3PXP",
            notes=support.SENTINEL_NOTE,
            fields={"密保问题": support.SENTINEL_CUSTOM, "*ApiKey": "AKIA-secret-value"},
        )

    def test_five_formatting_paths_never_leak(self) -> None:
        """5 条格式化路径逐条断言（`__repr__` / `__str__` / f-string / `%` / `format`）。"""
        record = self._record()
        rendered = {
            "repr(rec)": repr(record),
            "str(rec)": str(record),
            'f"{rec}"': f"{record}",
            '"%s" % rec': "%s" % record,
            '"{}".format(rec)': "{}".format(record),
        }
        for how, text in rendered.items():
            with self.subTest(path=how):
                self.assertNotIn(support.SENTINEL_PW, text, f"{how} 带出了密码")
                self.assertNotIn("JBSWY3DPEHPK3PXP", text, f"{how} 带出了 TOTP 种子")
                self.assertNotIn(support.SENTINEL_CUSTOM, text, f"{how} 带出了自定义字段值")
                self.assertNotIn("AKIA-secret-value", text, f"{how} 带出了 *ApiKey 的值")

    def test_container_repr_is_also_clean(self) -> None:
        """容器里也不行 —— 日志最常见的就是 `log.info("%s", items)` 这种写法。"""
        record = self._record()
        for text in (repr([record]), repr({"k": record}), repr((record,))):
            self.assertNotIn(support.SENTINEL_PW, text)

    def test_repr_still_useful_for_debugging(self) -> None:
        """不泄密的代价不能是「什么都看不到」，否则排查问题时只能去赌。"""
        record = self._record()
        for text in (repr(record), str(record), f"{record}"):
            self.assertIn(record.id, text)
            self.assertIn("淘宝", text)
            self.assertIn("has_password=True", text)

    def test_repr_reports_field_count_not_names(self) -> None:
        """自定义字段**连键名都不报**：键名本身可能是隐私（「小明的生日」）。"""
        record = self._record()
        text = repr(record)
        self.assertIn("fields=2", text)
        for name in record.fields:
            self.assertNotIn(name, text, f"repr 里出现了字段名 {name}")

    def test_empty_record_reports_false_flags(self) -> None:
        """空记录也要能一眼看出「没有密码」，而不是靠字段缺席去猜。"""
        text = repr(Record(title="空记录"))
        self.assertIn("has_password=False", text)
        self.assertIn("has_totp=False", text)
        self.assertIn("fields=0", text)

    def test_sensitive_key_guard_is_the_shared_rule(self) -> None:
        """确认我们复用的是 `models.is_sensitive_key` 这套规则（不是另起一套）。"""
        self.assertTrue(is_sensitive_key("*ApiKey"))
        self.assertTrue(is_sensitive_key("password"))
        self.assertFalse(is_sensitive_key("title"))


if __name__ == "__main__":
    unittest.main()
