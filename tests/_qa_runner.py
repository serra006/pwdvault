"""QA 侧的子进程执行器（**故意不叫 `test_*.py`**，discover 不会收集）。

为什么另起一份而不复用工程师的 `_locker.py`：
  - `_locker.py` 只覆盖「拿锁/放锁」这一件事，而 QA 要打的是**异常路径、真跨进程
    竞态、暂存区状态机、inbox 并发扫描**，需要一套能「在指定时刻同时开跑」的入口；
  - 不改工程师的夹具，避免并行开发时互相踩。

用法（全部通过 `PV_HOME` + `config.toml` 定位同一个库）：

    python _qa_runner.py hold-lock <home> <hold_seconds>
    python _qa_runner.py inbox-scan <home> [--start-at <epoch>] [--rounds N]
    python _qa_runner.py staging <home> <action> <batch_id> [选项]
    python _qa_runner.py apply-changes <home> <record_title> <changes.json>
    python _qa_runner.py dump <home> <out.json> [--normalize]

所有命令成功时向 stdout 打一行 JSON（`{"ok": true, ...}`），失败时打
`{"ok": false, "error": ..., "code": ...}` 并以 3 退出 —— 父进程只解析 JSON。
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PYTHON = sys.executable


# ---------------------------------------------------------------- 父进程侧工具
def write_config(
    home: Path,
    vault_path: Path,
    *,
    lock_timeout: float = 20.0,
    lock_poll: float = 0.01,
    staging_extra: str = "",
    extra: str = "",
) -> Path:
    """写一份 config.toml（比 `_support.write_config` 多出 lock/staging 可调项）。

    `_support.write_config` 已经把 `[lock]` 段写死了，TOML 不允许重复表，
    所以 QA 侧自己写一份，**只改配置文件、不改源码默认值**。
    """
    home.mkdir(parents=True, exist_ok=True)
    text = (
        "[vault]\n"
        f'path = "{Path(vault_path).as_posix()}"\n'
        "snapshots = 3\n"
        "\n"
        "[kdf]\n"
        'algo = "argon2id"\n'
        "time_cost = 1\n"
        "memory_cost = 8192\n"
        "parallelism = 1\n"
        "\n"
        "[lock]\n"
        f"timeout_seconds = {lock_timeout}\n"
        f"poll_seconds = {lock_poll}\n"
    )
    if staging_extra:
        text += "\n[staging]\n" + staging_extra.strip() + "\n"
    if extra:
        text += "\n" + extra.strip() + "\n"
    path = home / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def child_env(home: Path, password: str) -> dict:
    environ = os.environ.copy()
    environ["PV_HOME"] = str(home)
    environ["PV_MASTER_PASSWORD"] = password
    environ.pop("PV_VAULT", None)
    environ.pop("PV_RECOVERY_CODE", None)
    return environ


def wait_for_start(epoch: float | None) -> None:
    """忙等到指定时刻（比 sleep 精确，方便制造裸竞态窗口）。"""
    if epoch is None:
        return
    while time.time() < epoch:
        pass


def emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def parse_payload(text: str | None) -> dict | None:
    """子进程 stdout 的最后一行 JSON（子进程可能先打日志再打结果行）。"""
    lines = [line for line in (text or "").strip().splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def collect_payload(proc, *, timeout: float = 180.0) -> dict:
    """等子进程结束并取回结果行；失败时给一个可读的兜底结构。"""
    out, err = proc.communicate(timeout=timeout)
    payload = parse_payload(out)
    if payload is None:
        return {
            "ok": False,
            "error": f"no-json (exit={proc.returncode})",
            "code": "",
            "stderr": (err or "")[-500:],
        }
    payload.setdefault("stderr", (err or "")[-500:])
    payload.setdefault("exit", proc.returncode)
    return payload


# ---------------------------------------------------------------- 子进程侧实现
def _settings():
    from pwdvault.config import load_settings

    return load_settings()


def _password() -> str:
    value = os.environ.get("PV_MASTER_PASSWORD")
    if not value:
        raise RuntimeError("PV_MASTER_PASSWORD 未设置")
    return value


def _open_vault(settings):
    from pwdvault.vault import Vault

    return Vault.open(settings, password=_password())


def _staging(settings, vault):
    from pwdvault.staging import StagingStore

    return StagingStore(settings, lambda: vault.dek)


def cmd_hold_lock(args: list[str]) -> int:
    from pwdvault.locks import LockManager

    settings = _settings()
    hold_seconds = float(args[0]) if args else 30.0
    manager = LockManager(settings.lock_path, default_timeout=20.0, poll_seconds=0.005)
    with manager.hold(purpose="qa-hold"):
        emit({"ok": True, "event": "held", "pid": os.getpid()})
        time.sleep(hold_seconds)
    emit({"ok": True, "event": "released"})
    return 0


def cmd_probe_lock(args: list[str]) -> int:
    """从**另一个进程**探一次锁：能拿到 → 说明父进程没有残留 fd / 文件锁。"""
    from pwdvault.locks import LockManager

    settings = _settings()
    timeout = float(args[0]) if args else 1.0
    purpose = str(args[1]) if len(args) > 1 and not str(args[1]).startswith("--") else ""
    manager = LockManager(settings.staging_lock_path if purpose == "staging" else settings.lock_path,
                          default_timeout=timeout, poll_seconds=0.005)
    # 让多个进程在同一时刻撞 `os.open(O_CREAT)` —— Q-01 的窗口只在这里
    wait_for_start(_opts(args).get("start_at"))
    start = time.monotonic()
    try:
        with manager.hold(timeout=timeout, purpose="qa-probe"):
            elapsed = time.monotonic() - start
            emit({"ok": True, "elapsed": round(elapsed, 4), "pid": os.getpid()})
            return 0
    except Exception as exc:  # noqa: BLE001
        emit(
            {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "code": getattr(exc, "code", ""),
                "elapsed": round(time.monotonic() - start, 4),
            }
        )
        return 3


def cmd_inbox_scan(args: list[str]) -> int:
    opts = _opts(args)
    wait_for_start(opts.get("start_at"))
    settings = _settings()
    vault = _open_vault(settings)
    staging = _staging(settings, vault)
    from pwdvault.inbox import InboxWatcher

    watcher = InboxWatcher(settings, staging, interval=float(opts.get("interval", 2.0)))
    rounds = int(opts.get("rounds", 1))
    created: list[str] = []
    for _ in range(max(1, rounds)):
        created.extend(watcher.scan_once())
    batch_files = sorted(p.name for p in settings.staging_dir.glob("sb_*.enc"))
    emit({"ok": True, "created": created, "batch_files": batch_files, "pid": os.getpid()})
    return 0


def cmd_staging(args: list[str]) -> int:
    opts = _opts(args)
    if len(args) < 2:
        emit({"ok": False, "error": "staging 需要 action 与 batch_id"})
        return 3
    action, batch_id = args[0], args[1]
    wait_for_start(opts.get("start_at"))

    settings = _settings()
    vault = _open_vault(settings)
    staging = _staging(settings, vault)
    from pwdvault.locks import VaultStore

    store = VaultStore(settings, vault)
    # `--holder` 缺省时**不要**塞一个常量：Q-03 的默认值是 "ui"，
    # 两个进程都拿到 "ui" 时是否真的互斥，正是要走 `begin_edit` 的默认路径来验。
    holder = str(opts["holder"]) if "holder" in opts else None
    result: object
    try:
        if action == "claim":
            batch = staging.claim(
                batch_id,
                holder=holder or "agent",
                lease_seconds=int(opts["lease"]) if "lease" in opts else None,
            )
            result = {"status": batch.status, "lease": batch.lease}
        elif action == "begin-edit":
            batch = staging.begin_edit(batch_id, holder=holder)
            result = {"status": batch.status, "editor": batch.editor}
        elif action == "end-edit":
            batch = staging.end_edit(batch_id)
            result = {"status": batch.status}
        elif action == "commit":
            result = staging.commit(batch_id, store=store, mode=str(opts.get("mode", "skip")))
        elif action == "rollback":
            result = staging.rollback(batch_id, store=store)
        elif action == "get":
            batch = staging.get(batch_id)
            result = batch.to_public(include_items=False)
        elif action.startswith("transition:"):
            batch = staging.transition(batch_id, action.split(":", 1)[1])
            result = {"status": batch.status}
        else:
            emit({"ok": False, "error": f"未知 action：{action}"})
            return 3
    except Exception as exc:  # noqa: BLE001 - 把业务异常交回父进程判断
        emit(
            {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "code": getattr(exc, "code", ""),
                "pid": os.getpid(),
            }
        )
        return 3
    emit({"ok": True, "action": action, "result": result, "pid": os.getpid()})
    return 0


def cmd_apply_changes(args: list[str]) -> int:
    """**独立于 CLI 的第二条路径**：直接对 Record.apply_changes 施加同一组改动。"""
    if len(args) < 2:
        emit({"ok": False, "error": "用法：apply-changes <home> <title> <changes.json>"})
        return 3
    title, changes_path = args[0], args[1]
    changes = json.loads(Path(changes_path).read_text(encoding="utf-8"))

    settings = _settings()
    vault = _open_vault(settings)
    from pwdvault.locks import VaultStore

    store = VaultStore(settings, vault)
    box: dict = {}

    def _apply(fresh) -> bool:
        target = None
        for record in fresh.records:
            if record.title == title:
                target = record
                break
        if target is None:
            raise RuntimeError(f"找不到记录：{title}")
        touched = target.apply_changes(changes)
        box["touched_password"] = bool(touched)
        return True

    store.mutate(_apply)
    emit({"ok": True, **box})
    return 0


def cmd_dump(args: list[str]) -> int:
    """解密 `data.enc` 并落一份 payload 快照，供两条路径逐字节/逐字段比对。"""
    if len(args) < 2:
        emit({"ok": False, "error": "用法：dump <home> <out.json> [--normalize]"})
        return 3
    out_path = Path(args[1])
    normalize = "--normalize" in args
    settings = _settings()
    vault = _open_vault(settings)
    rows = []
    for record in vault.records:
        item = record.to_dict()
        if normalize:
            # 时间戳天然不同（两条路径的墙钟不同），比对结构时统一抹平
            for key in ("created", "updated", "pw_changed"):
                if key in item:
                    item[key] = "<ts>"
        rows.append(item)
    rows.sort(key=lambda item: item["title"])
    out_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    emit({"ok": True, "records": len(rows), "out": str(out_path)})
    return 0


def _opts(args: list[str]) -> dict:
    out: dict = {}
    for arg in args:
        if not arg.startswith("--"):
            continue
        body = arg[2:]
        if "=" in body:
            key, _, value = body.partition("=")
            out[key.replace("-", "_")] = value
        else:
            out[body.replace("-", "_")] = True
    if "start_at" in out and out["start_at"] is not True:
        out["start_at"] = float(out["start_at"])
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    command, rest = argv[0], argv[1:]
    handlers = {
        "hold-lock": cmd_hold_lock,
        "probe-lock": cmd_probe_lock,
        "inbox-scan": cmd_inbox_scan,
        "staging": cmd_staging,
        "apply-changes": cmd_apply_changes,
        "dump": cmd_dump,
    }
    handler = handlers.get(command)
    if handler is None:
        print(f"未知命令：{command}", file=sys.stderr)
        return 2
    return handler(rest)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
