"""明文泄漏的全面搜索 + `apply_changes` 的真实等价性 + pw_changed 回读。

`test_staging.py` 只做了一条 `assertNotIn(SENTINEL, sb_xxx.enc 字节)`，
`test_locks.py` 只检查了冲突结构里的 `MASK`。这不够：泄漏可能出现在
`tombstones.json`、`commit.before` 快照、stderr 日志、异常 traceback、以及
`staging` 外层明文 JSON 里。本文件把**落盘面全扫一遍**，而不是只看一个响应体。

第二部分（C）用**另一条独立路径**复核 `apply_changes` 与 v1.0 `service.update` 等价：
工程师是「抄一份 legacy 实现逐字段比对」，这里改成「CLI 真实 `pv edit` 十次」对
「直接调 `apply_changes` 十次」，比对 `data.enc` 解密后的最终 payload。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _qa_runner as qa
import _support as support

from pwdvault.config import load_settings
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record
from pwdvault.staging import StagingStore
from pwdvault.vault import Vault

RUNNER = Path(__file__).resolve().parent / "_qa_runner.py"
PASSWORD = support.PASSWORD

PW = support.SENTINEL_PW
NOTE = support.SENTINEL_NOTE
CUSTOM = support.SENTINEL_CUSTOM
SECOND_PW = support.SENTINEL_PW + "-2"
SENTINELS = (PW, NOTE, CUSTOM, SECOND_PW)


class SecurityBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(self.home, self.home / "data.enc", lock_timeout=10.0, lock_poll=0.01)
        fixture = support.make_vault(self.home, snapshot_keep=2)
        previous_home = os.environ.get("PV_HOME")
        os.environ["PV_HOME"] = str(self.home)
        self.addCleanup(
            lambda: os.environ.pop("PV_HOME", None)
            if previous_home is None
            else os.environ.__setitem__("PV_HOME", previous_home)
        )
        self.settings = load_settings()
        self.vault = fixture.vault
        self.store = VaultStore(self.settings, self.vault)
        self.inbox = self.settings.inbox_path
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.staging = StagingStore(self.settings, lambda: self.vault.dek)

    # ------------------------------------------------------------ 工具
    def sentinel_record(self, title: str = "淘宝") -> Record:
        return Record(
            title=title,
            username="zhangsan",
            password=PW,
            notes=NOTE,
            url="https://taobao.com",
            tags=["购物"],
            fields={"API密钥": CUSTOM, "密保问题": "母亲的姓氏"},
        )

    def scan_disk(self, *, skip_inbox: bool = True) -> dict[str, list[str]]:
        """扫 home 下所有文件，返回 {相对路径: [命中的哨兵]}。"""
        hits: dict[str, list[str]] = {}
        for path in sorted(self.home.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self.home).as_posix()
            if skip_inbox and rel.startswith("inbox/"):
                # inbox 与 inbox/processed 是**用户自己的明文源文件**，按设计不加密
                continue
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            text = blob.decode("utf-8", errors="replace")
            found = [probe for probe in SENTINELS if probe in text]
            if found:
                hits[rel] = found
        return hits


class PlaintextLeakTests(SecurityBase):
    def test_no_plaintext_anywhere_on_disk_after_full_staging_flow(self):
        """走完「建批 → review → 覆盖提交（产生 before 快照）→ 撤销」全流程，
        然后逐个文件扫明文。允许的明文区只有 inbox/ 里用户自己的源文件。"""
        # 库里先有一条同标题记录，让「覆盖提交」产生 before 快照
        self.store.commit([Operation.add(self.sentinel_record())])

        path = self.inbox / "泄漏检查.txt"
        path.write_text("占位\n", encoding="utf-8")
        batch = self.staging.create_from_file(
            path=path,
            text="",
            drafts=[self.sentinel_record("淘宝")],
            origin="local",
        )
        self.staging.transition(batch.batch_id, "review")
        committed = self.staging.commit(batch.batch_id, store=self.store, mode="overwrite")
        self.assertEqual(committed["status"], "committed")

        loaded = self.staging.get(batch.batch_id)
        self.assertIsNotNone(loaded.items[0].before, "覆盖提交必须留下 before 快照用于撤销")
        self.assertEqual(loaded.items[0].before["password"], PW)

        self.staging.rollback(batch.batch_id, store=self.store)

        hits = self.scan_disk()
        self.assertEqual(hits, {}, f"以下文件里出现了明文哨兵：{hits}")

    def test_outer_json_has_no_field_values(self):
        """`sb_*.enc` 的外层明文只允许标识/状态/时间，不允许字段值。"""
        path = self.inbox / "外层检查.txt"
        path.write_text("占位\n", encoding="utf-8")
        batch = self.staging.create_from_file(
            path=path, text="", drafts=[self.sentinel_record()], origin="local"
        )
        outer = json.loads((self.settings.staging_dir / f"{batch.batch_id}.enc").read_text(encoding="utf-8"))
        blob = json.dumps(outer, ensure_ascii=False)
        for probe in (PW, NOTE, CUSTOM):
            self.assertNotIn(probe, blob, f"外层明文中出现字段值：{probe[:20]}…")
        self.assertEqual(outer["source"]["file_name"], "外层检查.txt")
        self.assertIn("sealed", outer)

    def test_tombstones_contain_no_field_values(self):
        """`tombstones.json` 是**明文**存储（DESIGN §4.4 明确推翻 PRD 的加密清单），
        所以更要确认它只有指纹/文件名/时间。"""
        path = self.inbox / "墓碑检查.txt"
        path.write_text("占位\n", encoding="utf-8")
        batch = self.staging.create_from_file(
            path=path, text="", drafts=[self.sentinel_record()], origin="local"
        )
        self.staging.discard(batch.batch_id)
        text = self.settings.tombstones_path.read_text(encoding="utf-8")
        for probe in (PW, NOTE, CUSTOM):
            self.assertNotIn(probe, text)
        self.assertIn("墓碑检查.txt", text)

    def test_cli_stderr_and_masked_stdout_have_no_password(self):
        """真实 CLI 流程：**stderr（日志通道）任何情况下都不能出现字段值**；
        stdout 里 `show` / `add` / `doctor` 按设计是掩码或不含密码，也一并断言。

        `list --json` / `find --json` 会输出明文密码（v1.0 既有行为，见下一条用例），
        所以这两个命令在这里只检查 stderr。
        """
        env = {"PV_MASTER_PASSWORD": PASSWORD}
        steps = [
            ["add", "--json", "-t", "命令行走一遍", "-u", "u1", "-p", PW, "-n", NOTE,
             "-f", f"API密钥={CUSTOM}"],
            ["list", "--json"],
            ["find", "命令行走一遍", "--json"],
            ["doctor", "--json"],
            ["show", "命令行走一遍", "--json"],
        ]
        for args in steps:
            result = support.run_py(args, home=self.home, env=env)
            self.assertEqual(result.returncode, 0, f"{args[0]} 失败：{result.stderr[-800:]}")
            for probe in (PW, CUSTOM):
                self.assertNotIn(probe, result.stderr, f"{args[0]} 的 stderr 里出现了字段值")
        for args in (steps[0], steps[3], steps[4]):
            result = support.run_py(args, home=self.home, env=env)
            self.assertNotIn(PW, result.stdout, f"{args[0]} 的 stdout 里出现了密码")

    def test_cli_list_json_masks_passwords_by_default(self):
        """O-1 已加固：`pv list --json` / `pv find --json` 默认掩码，`--reveal` 才给明文。

        原观察项：`cmd_list` / `cmd_find` 直接用 `record.to_dict()`，`--json` 输出里
        密码、TOTP、敏感自定义字段全是明文，而同一份 CLI 里 `cmd_show` 却默认掩码。
        任何把 `pv list --json` 的 stdout 落盘 / 转给模型 / 进 CI 日志的脚本都会明文外泄。
        现在两条路径统一为 `to_dict(mask_secrets=True)`，只有 `--reveal` 才解开。
        """
        env = {"PV_MASTER_PASSWORD": PASSWORD}
        support.run_py(
            ["add", "--json", "-t", "列表掩码", "-p", PW], home=self.home, env=env
        )
        result = support.run_py(["list", "--json"], home=self.home, env=env)
        self.assertNotIn(PW, result.stdout, "list --json 默认必须掩码")
        self.assertIn("\u2022\u2022\u2022\u2022", result.stdout, "掩码必须是恒定四个点")

        found = support.run_py(["find", "列表掩码", "--json"], home=self.home, env=env)
        self.assertNotIn(PW, found.stdout, "find --json 默认必须掩码")

        revealed = support.run_py(["list", "--json", "--reveal"], home=self.home, env=env)
        self.assertIn(PW, revealed.stdout, "--reveal 必须给回明文")

        show = support.run_py(["show", "列表掩码", "--json"], home=self.home, env=env)
        self.assertNotIn(PW, show.stdout, "show 默认必须掩码")

    def test_unexpected_traceback_has_no_record_values(self):
        """未捕获异常会打出裸 traceback（`cli.main` 只兜 `VaultError`）。
        确认这条通道上不会带上记录内容。"""
        self.store.commit([Operation.add(self.sentinel_record())])
        # 把头部 revision 改成非数字 → read_revision 抛 ValueError（不是 VaultError）
        header = json.loads(self.settings.vault_path.read_text(encoding="utf-8"))
        header["meta"]["revision"] = "not-a-number"
        self.settings.vault_path.write_text(json.dumps(header, ensure_ascii=False), encoding="utf-8")

        result = support.run_py(
            ["add", "-t", "x", "-p", "y"], home=self.home, env={"PV_MASTER_PASSWORD": PASSWORD}
        )
        self.assertNotEqual(result.returncode, 0, "坏头部应导致失败")
        combined = (result.stdout or "") + (result.stderr or "")
        for probe in (PW, NOTE, CUSTOM):
            self.assertNotIn(probe, combined, f"traceback 里带出了记录内容：{probe[:20]}…")

    def test_agent_summary_is_scrubbed_before_landing_in_outer_json(self):
        """O-2 回归：Agent 的一句话总结里出现字段值 → 落盘前整条替换。

        原先这条用例是 characterization：DESIGN §5.4 只靠 prompt 约束「notes 不得
        包含任何字段值」，代码只做 200 字符截断，所以 Agent 一旦把密码写进总结，
        它就以**明文**落进 `sb_*.enc` 外层 JSON —— 正好是 staging.py 顶部注释
        "外层 JSON … 没有任何字段值" 承诺的相反面。（原用例的留在原地的注释是
        「如果这里失败说明已加校验，应改写本用例」，即本次改写。）
        """
        path = self.inbox / "总结泄漏.txt"
        path.write_text("占位\n", encoding="utf-8")
        batch = self.staging.create_from_file(
            path=path, text="", drafts=[Record(title="淘宝", username="u1")], origin="local"
        )
        self.staging.claim(batch.batch_id, holder="agent")
        summary = f"已整理 1 条，其中淘宝密码是 {PW}"
        self.staging.submit(batch.batch_id, [Record(title="淘宝", username="u1", password=PW)],
                            holder="agent", summary=summary)

        outer = json.loads((self.settings.staging_dir / f"{batch.batch_id}.enc").read_text(encoding="utf-8"))
        self.assertNotIn(PW, json.dumps(outer, ensure_ascii=False), "总结里的密码仍然以明文落盘")
        self.assertEqual(outer["notes"], "（已隐去，疑似含敏感内容）")
        self.assertTrue(outer["notes_redacted"], "替换必须留痕，UI 才能提示「总结被隐去」")
        self.assertEqual(outer["status"], "review")

    def test_record_repr_contains_password_so_never_log_a_record(self):
        """风险钉子：`Record` 是 dataclass，默认 `__repr__` **带明文密码**。

        ⚠️ **本用例的断言方向已被 O-3 反转，反转是修复的一部分，不是放宽。**

        原断言是 `assertIn(PW, repr(record))` —— 把「repr 会打出明文」当成已知事实钉住。
        O-3 修好之后这条断言会继续通过**当且仅当**缺陷还在，也就是说它从「风险记录」
        变成了「把漏洞写进测试」。留着它，下一个维护者为了让套件变绿只有一条路：
        把 `Record.__repr__` 改回默认实现 —— 那正是我们要防的事。

        所以这里改成断言「修好之后的样子」：repr / f-string / 容器里的 repr 都不许带出
        任何敏感值，同时保留可排查性（id / title / has_password）。校验值本身的规则
        仍是 `models.is_sensitive_key`，没有第二套。
        """
        record = self.sentinel_record()
        self.assertNotIn(PW, repr(record), "O-3：repr 不许带出密码")
        self.assertNotIn(PW, f"{record}", "O-3：f-string 不许带出密码")
        # totp / 敏感自定义字段同样不许出现
        for secret in (record.totp, *record.fields.values()):
            if secret:
                self.assertNotIn(secret, repr(record), "O-3：repr 不许带出敏感字段值")
        # 不泄密的代价不能是「什么都看不到」
        self.assertIn(record.id, repr(record))
        self.assertIn("has_password=True", repr(record))


class PwChangedRoundTripTests(SecurityBase):
    """独立复核工程师「顺手修的 v1.0 潜伏 bug」：`Record.from_dict` 恢复 meta 时未归一化键名，
    导致 `pw_changed` 永远读不回来。"""

    def test_pw_changed_survives_save_and_reopen(self):
        record = Record(title="改过密码", username="u1", password="pw-old")
        record.pw_changed = "2021-05-05T00:00:00+00:00"
        record.created = "2020-01-01T00:00:00+00:00"
        record.updated = "2021-05-05T00:00:00+00:00"
        self.store.commit([Operation.add(record)])

        fresh = Vault.open(self.settings, password=PASSWORD)
        got = fresh.find_by_id(record.id)
        self.assertIsNotNone(got)
        self.assertEqual(got.pw_changed, "2021-05-05T00:00:00+00:00", "pw_changed 没能从盘上回读")
        # 修 bug 时不能把 created / updated 弄坏
        self.assertEqual(got.created, "2020-01-01T00:00:00+00:00")
        self.assertEqual(got.updated, "2021-05-05T00:00:00+00:00")
        self.assertEqual(got.password, "pw-old")

    def test_meta_key_normalisation_variants(self):
        """三种写法都要能回读：`pw_changed` / `pwChanged` / `pw-changed`。
        `normalize_key` 会把它们统一成 `pwchanged`，v1.0 的 bug 正是取键时没归一化。"""
        common = {
            "title": "变体",
            "username": "u",
            "created": "2020-01-01T00:00:00+00:00",
            "updated": "2020-06-01T00:00:00+00:00",
        }
        for key in ("pw_changed", "pwChanged", "pw-changed"):
            raw = dict(common, **{key: "2022-02-02T00:00:00+00:00"})
            record = Record.from_dict(raw)
            self.assertEqual(
                record.pw_changed,
                "2022-02-02T00:00:00+00:00",
                f"键名 {key} 没能回读 pw_changed",
            )
            self.assertEqual(record.created, "2020-01-01T00:00:00+00:00")
            self.assertEqual(record.updated, "2020-06-01T00:00:00+00:00")

    def test_password_change_refreshes_pw_changed(self):
        record = Record(title="改密码", username="u", password="old")
        record.pw_changed = "2020-01-01T00:00:00+00:00"
        self.store.commit([Operation.add(record)])
        self.store.commit([Operation.update(record.id, {"password": "new"})])
        fresh = Vault.open(self.settings, password=PASSWORD).find_by_id(record.id)
        self.assertNotEqual(fresh.pw_changed, "2020-01-01T00:00:00+00:00", "改了密码却没刷 pw_changed")
        self.assertEqual(fresh.pw_changed, fresh.updated, "pw_changed 应等于本次 updated")


class ApplyChangesEquivalenceTests(unittest.TestCase):
    """C：同一个初始库、同样 10 组改动，`pv edit`（CLI）与直接 `apply_changes` 的最终 payload 必须一致。

    工程师的做法是「抄一份 v1.0 legacy 实现逐字段比对」；这里换成**两条真实运行路径**比对，
    任何一层（argparse → `_collect_fields` → `service.update` → `apply_changes` → 序列化）
    的语义漂移都会暴露出来。
    """

    # (CLI 参数, 直接给 apply_changes 的 dict)
    CHANGES: list[tuple[list[str], dict]] = [
        (["--notes", "新备注"], {"notes": "新备注"}),
        (["--password", "Brand#New1"], {"password": "Brand#New1"}),
        (["--url", "https://example.com/login"], {"url": "https://example.com/login"}),
        (["--tag", "工作", "--tag", "重要"], {"tags": "工作,重要"}),
        (["--tag", ""], {"tags": ""}),
        (["--field", "密保问题=故乡"], {"密保问题": "故乡"}),
        (["--field", "备用邮箱="], {"备用邮箱": ""}),
        (["--username", "  u2  "], {"username": "  u2  "}),
        (["--field", "Title=大写键名"], {"Title": "大写键名"}),
        (["--totp", "JBSWY3DPEHPK3PXP"], {"totp": "JBSWY3DPEHPK3PXP"}),
    ]

    def setUp(self) -> None:
        self.home_cli = support.make_home(self)
        fixture = support.make_vault(self.home_cli, snapshot_keep=0)
        self.settings = fixture.settings
        self.vault = fixture.vault
        store = VaultStore(self.settings, self.vault)
        self.records = [
            Record(title="淘宝", username="u1", password="pw1", notes="旧备注", tags=["购物"],
                   fields={"密保问题": "旧答案", "留空": ""}),
            Record(title="京东", username="u2", password="pw2"),
        ]
        store.commit([Operation.add(record) for record in self.records])
        self.target_id = self.records[0].id

        # 第二份**完全相同的库**（直接拷 data.enc，vault_id / DEK / id 全一致）
        self.home_direct = support.make_home(self)
        qa.write_config(self.home_direct, self.home_direct / "data.enc")
        shutil.copy2(self.settings.vault_path, self.home_direct / "data.enc")

    def test_cli_edit_and_apply_changes_produce_identical_payload(self):
        env = {"PV_MASTER_PASSWORD": PASSWORD}

        # ---- 路径 1：真实的 CLI `pv edit`（argparse → _collect_fields → service.update）
        for args, _changes in self.CHANGES:
            result = support.run_py(["edit", self.target_id, *args], home=self.home_cli, env=env)
            self.assertEqual(result.returncode, 0, f"pv edit {args} 失败：{result.stderr[-800:]}")

        # ---- 路径 2：直接调 Record.apply_changes（另开一个进程，绕开 CLI 与 service.update）
        changes_dir = self.home_direct / "changes"
        changes_dir.mkdir()
        for index, (_args, changes) in enumerate(self.CHANGES):
            path = changes_dir / f"{index:02d}.json"
            path.write_text(json.dumps(changes, ensure_ascii=False), encoding="utf-8")
            proc = subprocess.run(
                [support.PYTHON, str(RUNNER), "apply-changes", "淘宝", str(path)],
                cwd=str(support.PROJECT_ROOT),
                env=qa.child_env(self.home_direct, PASSWORD),
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode, 0, f"直接路径第 {index} 步（{changes}）失败：{proc.stderr[-800:]}"
            )

        # ---- 两边各自解密落一份 payload 快照（时间戳抹平，键集合保持原样）
        snapshots = {}
        for label, home in (("cli", self.home_cli), ("direct", self.home_direct)):
            out = home / f"payload-{label}.json"
            proc = subprocess.run(
                [support.PYTHON, str(RUNNER), "dump", str(home), str(out), "--normalize"],
                cwd=str(support.PROJECT_ROOT),
                env=qa.child_env(home, PASSWORD),
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"dump {label} 失败：{proc.stderr[-800:]}")
            snapshots[label] = json.loads(out.read_text(encoding="utf-8"))

        left, right = snapshots["cli"], snapshots["direct"]
        self.assertEqual(len(left), 2, "快照里的记录数不对")
        self.assertEqual(
            left,
            right,
            "CLI `pv edit` 与直接 `apply_changes` 的最终 payload 不一致：\n"
            f"CLI={json.dumps(left, ensure_ascii=False, indent=2)}\n"
            f"direct={json.dumps(right, ensure_ascii=False, indent=2)}",
        )


if __name__ == "__main__":
    unittest.main()
