"""第二轮回归：确认 6 个缺陷**真的修好了**，而不是把测试改松了。

`test_qa_security.py` 已经覆盖了「落盘无明文 / `list --json` 掩码 / `repr` 不带值 /
summary 是设计豁免」这几条。本文件故意用**另一种角度**再打一遍，因为「测试被改松」
最典型的形态就是：同一个断言改成了它的反面、或者断言范围被悄悄缩小。

这里补的四个新角度：

* R1 `--json` 写在**子命令前面**（`pv --json list`）。`cli._add_common_args` 为了
  防止子 parser 的 `default=False` 冲掉父 parser 的 `True`，专门用了
  `argparse.SUPPRESS` —— 这个技巧一旦被改回普通默认值，`pv --json list` 就会
  静默变成人读输出，而 `pv list --json` 仍然正常。只测后者测不出来。
* R2 `repr` 之外的三条格式化通道：`"%s" % record`、`str(record)`、容器里的 `repr`。
* R3 一个**正常的本地流程**（不是 Agent 塞话）里，`sb_*.enc` 外层明文 JSON 的每个
  字符串值都不能含字段值 —— 并且确认除了设计豁免的 `notes` / `file_name` 之外，
  没有别的地方带内容。
* R4 `_iso()` 的毫秒精度与「1 秒编辑锁」在真实墙钟下是否可用（Q-04 的行为面）。

R5 / R6 是跨进程的两条：默认 holder 抢编辑权，以及 20 轮「两个进程同时第一次创建
锁文件」是否还会冒出 `PermissionError` 裸 traceback（Q-01）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _qa_runner as qa
import _support as support

from pwdvault import staging as staging_module
from pwdvault.config import load_settings
from pwdvault.errors import StagingBusy
from pwdvault.inbox import InboxWatcher
from pwdvault.locks import Operation, VaultStore
from pwdvault.models import Record
from pwdvault.staging import StagingStore

PASSWORD = support.PASSWORD
RUNNER = Path(__file__).resolve().parent / "_qa_runner.py"
SENTINEL_PW = "ZZ-R2-Pw-77aa11-DO-NOT-LEAK"
SENTINEL_CUSTOM = "ZZ-R2-Custom-33bb22-DO-NOT-LEAK"


class RegressBase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = support.make_home(self)
        qa.write_config(self.home, self.home / "data.enc", lock_timeout=20.0, lock_poll=0.01)
        fixture = support.make_vault(self.home, snapshot_keep=0)
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

    def outer_json_texts(self) -> list[str]:
        return [
            path.read_text(encoding="utf-8")
            for path in self.settings.staging_dir.glob("sb_*.enc")
        ]

    def make_batch(self, name: str = "回归.txt"):
        path = self.inbox / name
        path.write_text(f"{name}-正文\n", encoding="utf-8")
        return self.staging.create_from_file(
            path=path,
            text=f"{name}-正文\n",
            drafts=[
                Record(
                    title=f"记录-{name}",
                    username="u-r2",
                    password=SENTINEL_PW,
                    notes="备注不是敏感值但也别乱跑",
                    fields={"API密钥": SENTINEL_CUSTOM},
                )
            ],
        )


# =====================================================================  R1
class JsonFlagOrderTests(RegressBase):
    """R1：`--json` 放在子命令**前面**也必须生效（argparse SUPPRESS 那一套）。"""

    def setUp(self) -> None:
        super().setUp()
        self.store.commit(
            [
                Operation.add(
                    Record(
                        title="告警通道",
                        username="r2",
                        password=SENTINEL_PW,
                        fields={"API密钥": SENTINEL_CUSTOM},
                    )
                )
            ]
        )
        self.env = {"PV_MASTER_PASSWORD": PASSWORD}

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return support.run_py(args, home=self.home, env=self.env)

    def test_global_json_flag_before_subcommand(self) -> None:
        result = self._run(["--json", "list"])
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        payload = json.loads(result.stdout)
        self.assertIn("records", payload, "--json 写在子命令前面时也必须输出 JSON")
        self.assertNotIn(SENTINEL_PW, result.stdout, "默认必须掩码")
        self.assertNotIn(SENTINEL_CUSTOM, result.stdout, "敏感自定义字段默认也必须掩码")

    def test_global_json_flag_before_find(self) -> None:
        result = self._run(["--json", "find", "告警通道"])
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        json.loads(result.stdout)
        self.assertNotIn(SENTINEL_PW, result.stdout)

    def test_reveal_gives_plaintext_back(self) -> None:
        """反向对照：`--reveal` 必须真的解开，否则上面的「掩码通过」毫无意义。"""
        result = self._run(["--json", "list", "--reveal"])
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertIn(SENTINEL_PW, result.stdout, "--reveal 必须给回明文")

    def test_stderr_never_carries_values(self) -> None:
        for args in (["--json", "list"], ["--json", "find", "告警通道"], ["--json", "doctor"]):
            result = self._run(args)
            self.assertNotIn(SENTINEL_PW, result.stderr, f"{args} 的 stderr 带出了密码")
            self.assertNotIn(SENTINEL_CUSTOM, result.stderr, f"{args} 的 stderr 带出了字段值")


# =====================================================================  R2
class ReprFormattingTests(RegressBase):
    """R2：`repr` 之外的三条格式化通道同样不能带出值。"""

    def test_all_formatting_channels(self) -> None:
        record = Record(
            title="格式化",
            username="u",
            password=SENTINEL_PW,
            notes="备注原文-R2",
            fields={"API密钥": SENTINEL_CUSTOM},
        )
        channels = {
            "repr": repr(record),
            "str": str(record),
            "percent-s": "%s" % record,
            "f-string": f"{record}",
            "container": repr([record]),
            "dict-value": repr({"record": record}),
            "exception-message": None,
        }
        try:
            raise RuntimeError(f"处理 {record} 时失败")
        except RuntimeError as exc:
            channels["exception-message"] = str(exc)
        for name, text in channels.items():
            self.assertIsNotNone(text)
            for probe in (SENTINEL_PW, SENTINEL_CUSTOM, "备注原文-R2"):
                self.assertNotIn(probe, text, f"{name} 通道带出了敏感值")


# =====================================================================  R3
class StagingOuterJsonTests(RegressBase):
    """R3：正常本地流程下，`sb_*.enc` 外层明文 JSON 不含任何字段值。"""

    def test_outer_json_has_no_field_values_after_full_flow(self) -> None:
        batch = self.make_batch()
        self.staging.transition(batch.batch_id, "review")
        self.staging.save_items(batch.batch_id, self.staging.get(batch.batch_id).items)
        self.staging.begin_edit(batch.batch_id, holder="win-1")
        self.staging.end_edit(batch.batch_id)
        self.staging.commit(batch.batch_id, store=self.store)

        texts = self.outer_json_texts()
        self.assertTrue(texts, "至少应该有一个批次文件")
        for text in texts:
            for probe in (SENTINEL_PW, SENTINEL_CUSTOM, "u-r2"):
                self.assertNotIn(probe, text, f"外层明文 JSON 里出现了 {probe[:18]}…")
            self.assertIn("pwdvault-staging", text, "外层格式标记应存在（确认真的读到了文件）")

    def test_only_documented_fields_carry_user_text(self) -> None:
        """外层明文里有用户文本的字段只能是设计豁免的那几个。

        这条比「搜不到哨兵」更强：即使将来有人在 `source` 里多塞一个字段，
        只要它属于「用户可控文本」就会被这里点名。
        """
        batch = self.make_batch()
        outer = json.loads(
            (self.settings.staging_dir / f"{batch.batch_id}.enc").read_text(encoding="utf-8")
        )
        allowed_top = {
            "format", "version", "vault_id", "batch_id", "status", "origin", "item_count",
            "notes", "created", "updated", "source", "lease", "editor", "commit", "sealed",
        }
        self.assertTrue(set(outer).issubset(allowed_top), f"外层多了字段：{set(outer) - allowed_top}")
        allowed_source = {
            "file_name", "sha256", "size", "inbox_rel_path", "moved_to", "detected_at", "format",
        }
        self.assertTrue(
            set(outer.get("source") or {}).issubset(allowed_source),
            f"source 里多了字段：{set(outer.get('source') or {}) - allowed_source}",
        )
        self.assertEqual(outer.get("notes"), "", "本地流程不该往 notes 里写内容")


# =====================================================================  R4
class TimestampPrecisionTests(RegressBase):
    """R4：`_iso()` 的精度，以及 1 秒编辑锁在真实墙钟下能不能用。"""

    def test_iso_keeps_milliseconds(self) -> None:
        moment = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)
        text = staging_module._iso(moment)
        self.assertTrue(text.endswith(".123+00:00"), f"必须是毫秒精度，实际是 {text!r}")
        back = staging_module._parse_iso(text)
        self.assertIsNotNone(back)
        drift = abs((back - moment).total_seconds())
        self.assertLess(drift, 0.002, f"毫秒精度下回读误差应 < 2ms，实际 {drift:.4f}s")

    def test_one_second_editor_lock_is_usable(self) -> None:
        """Q-04 的行为面：把编辑锁设成 1 秒，0.2 秒内绝不能接管、1.2 秒必须能接管。

        秒级截断时 `now - since` 会被放大约 1 秒 —— 于是 0.2 秒就会被判成「已过期」，
        第二个窗口直接接管，两个窗口同时编辑同一批。
        """
        batch = self.make_batch("秒级锁.txt")
        self.staging.transition(batch.batch_id, "review")
        with mock.patch.object(staging_module, "EDITOR_LOCK_SECONDS", 1):
            self.staging.begin_edit(batch.batch_id, holder="win-A")
            time.sleep(0.2)
            with self.assertRaises(StagingBusy, msg="1 秒锁在 0.2 秒时仍然有效"):
                self.staging.begin_edit(batch.batch_id, holder="win-B")
            time.sleep(1.1)
            taken = self.staging.begin_edit(batch.batch_id, holder="win-B")
            self.assertTrue(
                (taken.editor or {}).get("taken_over"),
                "过期接管必须在 editor.taken_over 上留痕",
            )
            self.assertEqual((taken.editor or {}).get("holder"), "win-B")


# =====================================================================  R5
class DefaultHolderRaceTests(RegressBase):
    """R5：两个**真进程**都用默认 holder 抢同一批次编辑权 → 恰好一个成功（Q-03）。"""

    def spawn_begin_edit(self, batch_id: str, start_at: float):
        return subprocess.Popen(
            [support.PYTHON, str(RUNNER), "staging", "begin-edit", batch_id,
             f"--start-at={start_at}"],
            cwd=str(support.PROJECT_ROOT),
            env=qa.child_env(self.home, PASSWORD),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_exactly_one_wins_with_default_holder(self) -> None:
        outcome = {"wins": 0, "busy": 0, "other": []}
        for _ in range(3):
            batch = self.make_batch(f"默认holder-{time.time_ns()}.txt")
            self.staging.transition(batch.batch_id, "review")
            start = time.time() + 1.2
            procs = [self.spawn_begin_edit(batch.batch_id, start) for _ in range(2)]
            results = [qa.collect_payload(proc) for proc in procs]
            ok = [item for item in results if item.get("ok")]
            self.assertEqual(
                len(ok), 1,
                f"默认 holder 下必须恰好一个成功，实际 {len(ok)} 个：{results}",
            )
            outcome["wins"] += 1
            for item in results:
                if item.get("ok"):
                    continue
                if item.get("code") == "staging_busy":
                    outcome["busy"] += 1
                else:
                    outcome["other"].append(item)
        self.assertEqual(outcome["other"], [], f"失败的那个应该是 staging_busy：{outcome['other']}")


# =====================================================================  R6
class FirstLockCreationRaceTests(RegressBase):
    """R6：20 轮「两个进程同一瞬间第一次创建锁文件」——零 PermissionError（Q-01）。"""

    ROUNDS = 20

    def spawn_probe(self, start_at: float):
        return subprocess.Popen(
            [support.PYTHON, str(RUNNER), "probe-lock", "20", f"--start-at={start_at}"],
            cwd=str(support.PROJECT_ROOT),
            env=qa.child_env(self.home, PASSWORD),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_no_bare_permission_error_on_first_creation(self) -> None:
        lock_path = self.settings.lock_path
        events = []
        for round_no in range(self.ROUNDS):
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
            start = time.time() + 1.0
            procs = [self.spawn_probe(start) for _ in range(2)]
            for proc in procs:
                out, err = proc.communicate(timeout=120)
                payload = qa.parse_payload(out) or {}
                events.append(
                    {
                        "round": round_no,
                        "ok": bool(payload.get("ok")),
                        "error": str(payload.get("error") or ""),
                        "stderr": err or "",
                    }
                )
                self.assertNotIn(
                    "Traceback", err or "",
                    f"第 {round_no} 轮出现了裸 traceback：{err[-400:]}",
                )
                self.assertNotIn("PermissionError", err or "", f"第 {round_no} 轮 PermissionError")
        failures = [event for event in events if not event["ok"]]
        self.assertEqual(
            failures, [],
            f"{self.ROUNDS} 轮 × 2 进程共 {len(events)} 次并发建锁，失败 {len(failures)} 次："
            f"{failures[:3]}",
        )
