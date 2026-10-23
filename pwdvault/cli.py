"""命令行界面 —— 控制器层。

职责边界：解析参数、调用业务层、格式化输出。不写业务规则，不碰加密原语。
所有命令都支持 --json，输出结构化结果，供 agent 或脚本调用。
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import unicodedata
from pathlib import Path

from . import audit, clipboard, dpapi, importers, service
from .config import load_settings
from .errors import (
    AuthenticationFailed,
    CorruptVault,
    InvalidRecord,
    RecordConflict,
    Refused,
    StaleWrite,
    VaultError,
    WeakMasterPassword,
)
from .locks import Operation, VaultStore
from .models import Record, score_secret
from .redact import redact_record
from .vault import Vault, inspect, read_revision

ENV_PASSWORD = "PV_MASTER_PASSWORD"
ENV_RECOVERY = "PV_RECOVERY_CODE"
SYNC_HINTS = ("onedrive", "dropbox", "坚果云", "nutstore", "google drive", "googledrive",
              "icloud", "百度网盘", "baidunetdisk", "阿里云盘", "aliyundrive", "微云",
              "weiyun", "syncthing", "nextcloud", "megasync")


# --------------------------------------------------------------------- 输出
def dwidth(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def dpad(text: str, width: int) -> str:
    text = str(text)
    if dwidth(text) > width:
        out = ""
        for ch in text:
            if dwidth(out + ch) > width - 1:
                break
            out += ch
        text = out + "…"
    return text + " " * max(0, width - dwidth(text))


def print_table(headers: list[str], rows: list[list[str]], widths: list[int]) -> None:
    print("  " + "  ".join(dpad(h, w) for h, w in zip(headers, widths)))
    print("  " + "  ".join("─" * w for w in widths))
    for row in rows:
        print("  " + "  ".join(dpad(cell, w) for cell, w in zip(row, widths)))


def out(args, data: dict) -> None:
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))


def emit(args, text: str) -> None:
    if not args.json:
        print(text)


# --------------------------------------------------------------------- 解锁
def read_stdin_password() -> str:
    data = sys.stdin.read()
    return data.rstrip("\r\n")


def prompt_password(label: str = "主密码") -> str:
    if not sys.stdin.isatty():
        return read_stdin_password()
    return getpass.getpass(f"{label}: ")


def unlock(args, settings) -> Vault:
    """优先用显式口令（管道/环境变量），否则尝试本机免密，最后交互输入。"""
    recovery = os.environ.get(ENV_RECOVERY)
    explicit: str | None = None
    if getattr(args, "password_stdin", False):
        explicit = read_stdin_password()
    elif os.environ.get(ENV_PASSWORD):
        explicit = os.environ[ENV_PASSWORD]

    if explicit is not None:
        if not explicit:
            raise AuthenticationFailed("读到的口令为空")
        return Vault.open(settings, password=explicit)

    if recovery:
        # 恢复码走环境变量，不占用 stdin，才能和 --password-stdin 共存
        return Vault.open(settings, recovery_code=recovery)

    if not getattr(args, "no_dpapi", False):
        try:
            return Vault.open(settings, allow_dpapi=True)
        except (AuthenticationFailed, CorruptVault):
            raise
        except Exception:  # noqa: BLE001 - 本机免密不可用则回落到口令
            pass

    if not sys.stdin.isatty():
        # 非交互环境绝不能去读 stdin：stdin 可能是打开但无数据的管道，会永久挂死
        raise Refused(
            "非交互环境无法提示输入主密码。请用 --password-stdin 从管道提供，"
            "或先用 pv local-unlock on 启用本机免密。"
        )

    last: Exception | None = None
    for attempt in range(3):
        secret = prompt_password()
        if not secret:
            continue
        try:
            return Vault.open(settings, password=secret)
        except AuthenticationFailed as exc:
            last = exc
            if attempt < 2:
                print("口令不正确，请重试。", file=sys.stderr)
    raise last or AuthenticationFailed()


def save_or_fail(vault: Vault, apply=None, *, timeout: float | None = None):
    """所有写盘都走「跨进程锁 + revision 校验」的唯一入口（`VaultStore`）。

    - `apply=None`：只做防御性校验后写盘（保留给「内存里已经改好了」的旧式调用）。
      盘上 revision 与内存不一致时抛 `StaleWrite`，**拒绝静默覆盖**。
    - `apply` 可调用对象：走「锁内 reload → 改最新数据 → 写盘」，天然 rebase，
      并发写入不会互相吞掉。返回 `CommitResult`。
    """
    store = VaultStore(vault.settings, vault)
    if apply is None:
        with store.lock.hold(timeout=timeout, purpose="save"):
            disk = read_revision(vault.settings.vault_path)
            if disk != vault.revision:
                raise StaleWrite(
                    f"文件修订已是 {disk}，这次保存基于 {vault.revision}，已放弃写入。"
                )
            vault.save(expected_revision=disk)
        return None
    return store.mutate(apply, timeout=timeout)


# --------------------------------------------------------------------- init
def cmd_init(args, settings) -> int:
    if settings.vault_path.exists():
        raise VaultError(f"vault 已存在：{settings.vault_path}", hint="如需重建请先移走旧文件。")

    explicit = read_stdin_password() if args.password_stdin else os.environ.get(ENV_PASSWORD)
    if explicit:
        password = explicit
    else:
        if not sys.stdin.isatty():
            raise Refused("非交互环境下请用 --password-stdin 提供主密码")
        print("设置主密码。建议 5 个以上随机单词（例如：橘子 铁路 钢琴 沙漠 灯塔）。")
        print("这个密码不会存在任何地方，忘记后只能用恢复码。")
        password = getpass.getpass("主密码: ")
        again = getpass.getpass("再输一次: ")
        if password != again:
            raise Refused("两次输入不一致")

    if not password:
        raise Refused("主密码不能为空")

    entropy, level = score_secret(password)
    if entropy < 55 and not args.force:
        raise WeakMasterPassword(
            f"估算强度 {entropy} bit（{level}）。文件可能被放到网盘，攻击者可离线爆破。"
            "确认仍要使用请加 --force。"
        )

    enable_local = args.local_unlock
    if enable_local is None and sys.stdin.isatty() and not args.json:
        answer = input("是否启用「本机免密」（在这台电脑上不用输主密码）？[Y/n]: ").strip().lower()
        enable_local = answer not in ("n", "no")
    enable_local = bool(enable_local)

    vault, recovery = Vault.create(
        settings, password, enable_dpapi=enable_local, label=args.label or ""
    )

    payload = {
        "vault": str(vault.path),
        "records": 0,
        "local_unlock": vault.has_method("dpapi"),
        "recovery_code": recovery,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print()
    print("=" * 62)
    print("  初始化完成。下面是恢复码，只显示这一次。")
    print("=" * 62)
    print()
    print(f"    {recovery}")
    print()
    print("  ⚠ 请立刻用纸抄下来，或存到这个网盘之外的地方。")
    print("  ⚠ 忘了主密码时，它是唯一能打开数据的东西。")
    print("  ⚠ 不要把它和 vault 文件放在同一个网盘里。")
    print("=" * 62)
    print()
    print(f"文件位置：{vault.path}")
    print(f"本机免密：{'已启用' if vault.has_method('dpapi') else '未启用'}")
    print()
    print("下一步：")
    print("  把这个文件放进网盘同步目录（或直接用 --vault 指过去）")
    print("  pv add        新增一条")
    print("  pv import f.txt --dry-run   先看导入效果再落库")
    return 0


# --------------------------------------------------------------------- add
def _collect_fields(args) -> dict:
    changes: dict = {}
    for name in ("title", "username", "password", "url", "notes", "totp"):
        value = getattr(args, name, None)
        if value is not None:
            changes[name] = value
    if args.tag:
        changes["tags"] = ",".join(args.tag)
    return changes


def cmd_add(args, settings) -> int:
    vault = unlock(args, settings)

    if args.from_json:
        raw = sys.stdin.read() if args.from_json == "-" else Path(args.from_json).read_text(encoding="utf-8")
        records = importers.parse_json(raw)
        box: dict = {}

        def _apply(fresh: Vault) -> bool:
            report = service.merge_import(fresh, records, mode=args.mode)
            box["report"] = report
            return bool(report["added"] or report["updated"])

        save_or_fail(vault, _apply)
        report = box.get("report") or {
            "added": 0,
            "updated": 0,
            "skipped": len(records),
            "details": [],
        }
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(f"已写入：新增 {report['added']}，更新 {report['updated']}，跳过 {report['skipped']}")
        return 0

    changes = _collect_fields(args)
    for item in args.field or []:
        if "=" not in item:
            raise InvalidRecord(f"自定义字段格式应为 键=值：{item}")
        key, _, value = item.partition("=")
        changes[key.strip()] = value

    if not changes and sys.stdin.isatty():
        print("逐项填写，直接回车跳过（标题必填）：")
        for key, label in (
            ("title", "标题"),
            ("username", "账号"),
            ("password", "密码"),
            ("url", "网址"),
            ("notes", "备注"),
            ("totp", "TOTP 种子"),
            ("tags", "标签（逗号分隔）"),
        ):
            value = input(f"  {label}: ").strip()
            if value:
                changes[key] = value
        while True:
            extra = input("  其他字段（键=值，空行结束）: ").strip()
            if not extra:
                break
            if "=" in extra:
                key, _, value = extra.partition("=")
                changes[key.strip()] = value.strip()

    record = Record.from_dict(
        {
            "title": changes.pop("title", ""),
            "username": changes.pop("username", ""),
            "password": changes.pop("password", ""),
            "url": changes.pop("url", ""),
            "notes": changes.pop("notes", ""),
            "totp": changes.pop("totp", ""),
            "tags": changes.pop("tags", ""),
            **changes,
        }
    )
    if not record.title.strip():
        raise InvalidRecord("标题不能为空")
    if args.dry_run:
        emit(args, f"[预演] 将新增：{record.title}")
        return 0

    # 单条新增走标准的记录级 add 操作：rebase 时不与别人的写入互相覆盖
    store = VaultStore(settings, vault)
    store.commit([Operation.add(record)])

    if args.json:
        print(json.dumps({"id": record.id, "title": record.title, "saved": True}, ensure_ascii=False))
    else:
        print(f"已保存：{record.title}  (id {record.id})")
    return 0


# --------------------------------------------------------------------- 查询
def _records_json(records, reveal: bool) -> list[dict]:
    """`--json` 的记录列表形态。

    默认 `to_dict(mask_secrets=True)`：password / totp / 敏感自定义字段的值一律掩码；
    只有 `--reveal` 才给明文 —— 与 `pv show` 同一套开关语义（O-1）。

    为什么默认要掩码：`pv list --json` 的 stdout 极其容易被重定向进日志、CI 输出、
    或直接喂给模型。明文密码一旦进了这些地方就收不回来，而「想看明文」的用户
    加一个 `--reveal` 只是一秒钟的事。
    """
    if reveal:
        return [record.to_dict() for record in records]
    return [record.to_dict(mask_secrets=True) for record in records]


def cmd_find(args, settings) -> int:
    vault = unlock(args, settings)
    results = service.search(vault, " ".join(args.query), limit=args.limit)
    if args.json:
        print(
            json.dumps(
                {
                    "count": len(results),
                    "records": _records_json(results, getattr(args, "reveal", False)),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if not results:
        print("没有匹配的记录。")
        return 0
    rows = [[r.id, r.title, r.username or "—", ",".join(r.tags) or "—"] for r in results]
    print_table(["ID", "标题", "账号", "标签"], rows, [10, 26, 24, 16])
    print(f"\n共 {len(results)} 条。用 pv show <id> 查看，pv copy <id> 复制密码。")
    return 0


def cmd_list(args, settings) -> int:
    vault = unlock(args, settings)
    records = vault.records
    if args.json:
        print(
            json.dumps(
                {
                    "count": len(records),
                    "records": _records_json(records, getattr(args, "reveal", False)),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if not records:
        print("还没有任何记录。用 pv add 新增，或 pv import 批量导入。")
        return 0
    rows = [[r.id, r.title, r.username or "—", ",".join(r.tags) or "—"] for r in records]
    print_table(["ID", "标题", "账号", "标签"], rows, [10, 26, 24, 16])
    print(f"\n共 {len(records)} 条。")
    return 0


def _record_payload(record: Record, reveal: bool) -> dict:
    data = record.to_dict()
    if not reveal and record.password:
        data["password"] = record.masked_password()
        data["password_hidden"] = True
    return data


def cmd_show(args, settings) -> int:
    vault = unlock(args, settings)
    record = service.resolve(vault, args.ref)

    code = ""
    if record.totp:
        try:
            code, remain = service.totp_code(record.totp)
            code = f"{code}（剩 {remain} 秒）"
        except InvalidRecord as exc:
            code = f"（种子异常：{exc.message}）"

    if args.json:
        print(json.dumps(_record_payload(record, args.reveal), ensure_ascii=False, indent=2))
        return 0

    password = record.password if args.reveal else record.masked_password()
    lines = [
        ("标题", record.title),
        ("ID", record.id),
        ("账号", record.username or "—"),
        ("密码", password + ("" if args.reveal else "   (加 --reveal 显示明文)")),
        ("网址", record.url or "—"),
    ]
    if record.totp:
        lines.append(("动态码", code))
    if record.tags:
        lines.append(("标签", ", ".join(record.tags)))
    if record.notes:
        lines.append(("备注", record.notes))
    if record.fields:
        rendered = "\n".join(f"           {k} = {v}" for k, v in record.fields.items())
        lines.append(("其他字段", "\n" + rendered))
    lines.append(("创建", record.created))
    lines.append(("更新", record.updated))

    for label, value in lines:
        print(f"{dpad(label, 10)} {value}")
    return 0


def cmd_copy(args, settings) -> int:
    vault = unlock(args, settings)
    record = service.resolve(vault, args.ref)

    if args.totp:
        value, remain = service.totp_code(record.totp)
        label = f"动态码（剩 {remain} 秒）"
    elif args.field:
        if args.field in ("username", "user"):
            value = record.username
        elif args.field in ("url", "notes", "title"):
            value = getattr(record, args.field)
        else:
            value = record.fields.get(args.field, "")
        label = f"{args.field}"
    else:
        value = record.password
        label = "密码"

    if not value:
        raise InvalidRecord(f"{record.title} 没有{label}")

    clipboard.copy_text(value)
    watcher = clipboard.spawn_clear_watcher(clipboard.digest_of(value), settings.clipboard_seconds)

    if args.json:
        print(
            json.dumps(
                {
                    "copied": True,
                    "field": args.field or ("totp" if args.totp else "password"),
                    "title": record.title,
                    "auto_clear_seconds": settings.clipboard_seconds if watcher else 0,
                },
                ensure_ascii=False,
            )
        )
        return 0

    print(f"已复制 {record.title} 的{label}到剪贴板。")
    if watcher:
        print(f"{settings.clipboard_seconds} 秒后自动清空。")
    else:
        print("（自动清空未生效，请手动清理剪贴板。）")
    return 0


def cmd_totp(args, settings) -> int:
    vault = unlock(args, settings)
    record = service.resolve(vault, args.ref)
    if not record.totp:
        raise InvalidRecord(f"{record.title} 没有保存 TOTP 种子")
    code, remain = service.totp_code(record.totp, at=args.at)
    if args.json:
        print(json.dumps({"code": code, "remain": remain, "title": record.title}, ensure_ascii=False))
    else:
        print(f"{code}   （{record.title}，剩 {remain} 秒）")
    return 0


# --------------------------------------------------------------------- 修改
def cmd_edit(args, settings) -> int:
    vault = unlock(args, settings)
    record = service.resolve(vault, args.ref)

    changes = _collect_fields(args)
    for item in args.field or []:
        if "=" not in item:
            raise InvalidRecord(f"自定义字段格式应为 键=值：{item}")
        key, _, value = item.partition("=")
        changes[key.strip()] = value
    unset = list(args.unset or [])

    if not changes and not unset:
        raise Refused("没有指定要修改的内容，用 --password / --username / --field 等参数")

    if args.dry_run:
        touched = list(changes) + unset
        emit(args, f"[预演] 将修改：{record.title} → {', '.join(touched)}")
        return 0

    record_id = record.id
    seen_updated = record.updated
    box: dict = {}

    def _apply(fresh: Vault) -> bool:
        target = fresh.find_by_id(record_id)
        if target is None:
            raise RecordConflict(record_id, kind="deleted")
        if target.updated != seen_updated:
            # 别的窗口改过同一条：拒绝静默覆盖，把冲突回给调用方
            raise RecordConflict(
                record_id,
                kind="stale",
                theirs=redact_record(target, profile="web"),
            )
        for key in unset:
            if key in target.fields:
                target.fields.pop(key, None)
            elif hasattr(target, key):
                setattr(target, key, "")
        service.update(fresh, target, changes)
        box["title"] = target.title
        return True

    save_or_fail(vault, _apply)
    title = box.get("title", record.title)
    if args.json:
        print(json.dumps({"updated": True, "id": record_id, "changes": list(changes)}, ensure_ascii=False))
    else:
        print(f"已更新：{title}（{', '.join(changes)} 已保存）")
    return 0


def cmd_rm(args, settings) -> int:
    vault = unlock(args, settings)
    record = service.resolve(vault, args.ref)
    if not args.yes:
        if args.json or not sys.stdin.isatty():
            raise Refused("删除需要显式加 --yes")
        answer = input(f"确认删除「{record.title}」？[y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("已取消。")
            return 0

    record_id = record.id
    seen_updated = record.updated
    title = record.title

    def _apply(fresh: Vault) -> bool:
        target = fresh.find_by_id(record_id)
        if target is None:
            return False
        if target.updated != seen_updated:
            raise RecordConflict(
                record_id,
                kind="stale",
                theirs=redact_record(target, profile="web"),
            )
        service.delete(fresh, target)
        return True

    save_or_fail(vault, _apply)
    if args.json:
        print(json.dumps({"deleted": True, "id": record_id, "title": title}, ensure_ascii=False))
    else:
        print(f"已删除：{title}")
    return 0


def cmd_passwd(args, settings) -> int:
    lines: list[str] | None = None
    if args.password_stdin:
        lines = sys.stdin.read().splitlines()

    # 先用「不需要旧密码」的方式尝试解锁：恢复码或本机免密
    vault: Vault | None = None
    if os.environ.get(ENV_RECOVERY):
        vault = Vault.open(settings, recovery_code=os.environ[ENV_RECOVERY])
    elif not args.no_dpapi:
        try:
            vault = Vault.open(settings, allow_dpapi=True)
        except Exception:  # noqa: BLE001
            vault = None

    if vault is not None:
        # 已经解锁：stdin 只需一行新密码
        if lines is not None:
            if not lines:
                raise Refused("没有从管道读到新密码")
            new_password = lines[0]
        else:
            if not sys.stdin.isatty():
                raise Refused("非交互环境请用 --password-stdin 提供新密码（一行）")
            new_password = getpass.getpass("新主密码: ")
            if new_password != getpass.getpass("再输一次: "):
                raise Refused("两次输入不一致")
    else:
        # 需要旧密码：stdin 两行（当前密码 + 新密码）
        if lines is not None:
            if len(lines) < 2:
                raise Refused("需要两行：第一行当前主密码，第二行新主密码")
            vault = Vault.open(settings, password=lines[0])
            new_password = lines[1]
        else:
            if not sys.stdin.isatty():
                raise Refused("非交互环境请用 --password-stdin 提供两行（当前密码 + 新密码）")
            vault = unlock(args, settings)
            new_password = getpass.getpass("新主密码: ")
            if new_password != getpass.getpass("再输一次: "):
                raise Refused("两次输入不一致")

    if not new_password.strip():
        raise Refused("新主密码不能为空")

    entropy, level = score_secret(new_password)
    if entropy < 55 and not args.force:
        raise WeakMasterPassword(f"新密码估算强度 {entropy} bit（{level}），确认请加 --force。")

    def _apply_passwd(fresh: Vault) -> bool:
        fresh.rewrap_password(new_password)
        return True

    store = VaultStore(settings, vault)
    store.mutate(_apply_passwd, purpose="passwd")
    fresh = store.vault
    if args.json:
        print(json.dumps({"changed": True, "records": len(fresh.records),
                          "unlocked_by": vault.unlocked_by}, ensure_ascii=False))
    else:
        print("主密码已更换。恢复码仍然有效，数据没有重新加密（只重包了一次密钥）。")
    return 0


def cmd_recovery(args, settings) -> int:
    vault = unlock(args, settings)
    if not args.reset:
        if args.json:
            print(json.dumps({"has_recovery": vault.has_method("recovery")}, ensure_ascii=False))
        else:
            print(f"恢复码：{'已设置' if vault.has_method('recovery') else '未设置'}")
            print("恢复码本身不存盘（只存它的包裹结果），无法取回明文。")
            print("如需重置换新码：pv recovery --reset")
        return 0

    box: dict = {}

    def _apply_recovery(fresh: Vault) -> bool:
        box["code"] = fresh.reset_recovery()
        return True

    save_or_fail(vault, _apply_recovery)
    code = box.get("code", "")
    if args.json:
        print(json.dumps({"recovery_code": code, "old_invalidated": True}, ensure_ascii=False))
        return 0
    print("新的恢复码（旧码已失效，只显示这一次）：")
    print()
    print(f"    {code}")
    print()
    print("请立刻抄写保存到网盘之外的地方。")
    return 0


def cmd_local_unlock(args, settings) -> int:
    vault = unlock(args, settings)
    if args.action == "on":

        def _enable(fresh: Vault) -> bool:
            fresh.enable_local_unlock()
            return True

        save_or_fail(vault, _enable)
        msg = "已启用本机免密。" if args.json else (
            "已启用本机免密：之后在这台电脑上打开 vault 不用输主密码。\n"
            "注意：本机任何以你账户运行的程序也能解密，请权衡。"
        )
    elif args.action == "off":

        def _disable(fresh: Vault) -> bool:
            fresh.disable_local_unlock()
            return True

        save_or_fail(vault, _disable)
        msg = "已关闭本机免密，之后每次都需要主密码。"
    else:
        status = vault.has_method("dpapi")
        if args.json:
            print(json.dumps({"enabled": status, "machine": dpapi.machine_fingerprint()}, ensure_ascii=False))
            return 0
        msg = f"本机免密：{'已启用' if status else '未启用'}（{dpapi.machine_fingerprint()}）"
    if args.json and args.action == "on":
        print(json.dumps({"enabled": True}, ensure_ascii=False))
    else:
        print(msg)
    return 0


# --------------------------------------------------------------------- 导入导出
def cmd_import(args, settings) -> int:
    source = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
    if not source.strip():
        raise VaultError("导入内容为空")

    records = importers.parse_any(source, filename=args.file, fmt=args.format)

    if args.dry_run:
        preview = []
        for record in records:
            item = {"title": record.title, "username": record.username,
                    "has_password": bool(record.password), "tags": record.tags}
            if record.fields:
                item["fields"] = record.fields
            preview.append(item)
        # 预演时不强制解锁：没有现成 vault 也能先检查解析结果
        try:
            vault = None if getattr(args, "no_vault", False) else unlock(args, settings)
        except VaultError:
            vault = None
        if vault is None:
            report = {"added": len(records), "updated": 0, "skipped": 0, "details": []}
        else:
            report = service.merge_import(vault, records, mode=args.mode, apply=False)
        if args.json:
            print(json.dumps({"dry_run": True, "parsed": len(records),
                              "preview": preview, "plan": report}, ensure_ascii=False, indent=2))
        else:
            print(f"[预演] 解析出 {len(records)} 条，将新增 {report['added']}、"
                  f"更新 {report['updated']}、跳过 {report['skipped']}。\n")
            rows = [[r.title, r.username or "—", "有" if r.password else "无",
                     ",".join(r.tags) or "—"] for r in records[:50]]
            print_table(["标题", "账号", "密码", "标签"], rows, [26, 22, 6, 16])
            if len(records) > 50:
                print(f"\n（仅显示前 50 条，共 {len(records)} 条）")
            print("\n确认无误后去掉 --dry-run 再执行一次。")
        return 0

    vault = unlock(args, settings)
    plan: dict = {}

    def _apply_import(fresh: Vault) -> bool:
        report = service.merge_import(fresh, records, mode=args.mode)
        plan["report"] = report
        return bool(report["added"] or report["updated"])

    save_or_fail(vault, _apply_import)
    report = plan.get("report") or {"added": 0, "updated": 0, "skipped": len(records), "details": []}

    if args.json:
        print(json.dumps({**report, "total_parsed": len(records)}, ensure_ascii=False, indent=2))
    else:
        print(f"导入完成：新增 {report['added']}，更新 {report['updated']}，"
              f"跳过 {report['skipped']}（共解析 {len(records)} 条）")
    return 0


def _warn_plaintext_export(destination: str) -> None:
    """把「你刚刚把整库明文写到某处」这句话送到 **stderr**。

    为什么是 stderr 而不是 stdout：`--json` 场景下 stdout 会被调用方解析成 JSON，
    往里塞中文提示会直接把下游解析搞坏；而 stderr 无论管道怎么接都会被人看到。
    """
    print(
        f"[pv] 注意：{destination} 是**明文**文件，任何拿到它的程序都能直接读出全部密码。"
        "用完请立刻删除；不要放进网盘同步目录、不要提交到代码仓库。",
        file=sys.stderr,
        flush=True,
    )


def cmd_export(args, settings) -> int:
    vault = unlock(args, settings)
    if not args.yes:
        raise Refused(
            "导出的是明文，等于把保护全部撤掉。确认请加 --yes，并确保目标位置安全。"
        )
    records = service.search(vault, " ".join(args.query)) if args.query else vault.records

    if args.format == "csv":
        text = importers.records_to_csv(records)
    else:
        text = importers.records_to_json(records)

    # 审计先于写文件：导出明文是本产品最高危的动作，必须留下「谁、什么时候、多少条」。
    # 位置在写文件之前，是为了让**枚举写错**（编程错误，默认抛 RuntimeError）在这里就炸，
    # 而不是先把明文吐出去再发现审计配置有问题。
    # 注意：审计的 **I/O 失败**仍然只降级到 stderr、不阻断导出 —— 磁盘满/只读不该
    # 让用户拿不到自己的数据（audit.py 规则 4）。所以这里的顺序是「先尝试记录」，
    # 不是「记录不成功就不许导出」。
    # 审计行里只有条数，没有任何字段值 —— 由 `audit.build_entry` 的白名单键保证。
    audit.append(
        settings,
        action="export",
        actor="cli",
        field_name=str(args.format or "json"),
        count=len(records),
    )

    if args.out and args.out != "-":
        Path(args.out).write_text(text, encoding="utf-8")
        _warn_plaintext_export(str(args.out))
        if args.json:
            print(json.dumps({"exported": len(records), "path": args.out}, ensure_ascii=False))
        else:
            print(f"已导出 {len(records)} 条明文记录到 {args.out}")
            print("用完请立刻删除该文件。")
    else:
        _warn_plaintext_export("标准输出")
        print(text)
    return 0


# --------------------------------------------------------------------- doctor
def cmd_doctor(args, settings) -> int:
    info = inspect(settings)
    health = None
    unlocked = None
    unlock_error = None

    if info.get("exists"):
        try:
            vault = unlock(args, settings)
            health = service.health(vault)
            unlocked = vault.unlocked_by
            info["revision"] = vault.revision
            info["records"] = len(vault.records)
        except Exception as exc:  # noqa: BLE001 - doctor 要能报告问题本身
            unlock_error = f"{type(exc).__name__}: {exc}"

    path_lower = str(settings.vault_path).lower()
    in_sync_dir = any(hint in path_lower for hint in SYNC_HINTS)

    if args.json:
        print(json.dumps({"file": info, "health": health, "unlocked_by": unlocked,
                          "unlock_error": unlock_error, "in_sync_dir": in_sync_dir},
                         ensure_ascii=False, indent=2, default=str))
        return 0

    print("文件")
    print(f"  路径      {info.get('path')}")
    if not info.get("exists"):
        print("  状态      不存在（先运行 pv init）")
        return 1
    print(f"  大小      {info.get('size')} 字节")
    print(f"  记录数    {info.get('records', '（未解锁）')}")
    print(f"  版本号    {info.get('version')}  修订 {info.get('revision', '?')}")
    print(f"  解锁方式  {', '.join(info.get('methods') or [])}")
    print(f"  KDF       {info.get('kdf')}")
    print(f"  快照      {info.get('snapshots')} 份，最新 {info.get('latest_snapshot') or '无'}")

    if unlock_error:
        print(f"\n解锁失败：{unlock_error}")

    print("\n备份")
    if in_sync_dir:
        print("  位置      看起来已在网盘同步目录内 ✓")
    else:
        print("  位置      不在常见网盘同步目录内")
        print("            若要异地容灾，把 vault 放到 OneDrive/坚果云目录，或用 --vault 指过去")
    print(f"  副本数    {'1 份（仅本地）' if not in_sync_dir else '2 份（本地 + 网盘）'}")
    print("  提醒      网盘一份只能防硬盘损坏，防不了误删和勒索软件。")
    print("            建议再加一块离线 U 盘，每月同步一次。")
    print("  恢复码    ", "已设置（请确认纸质备份还在）" if "recovery" in (info.get("methods") or []) else "未设置")

    if health:
        print("\n体检")
        print(f"  记录总数  {health['total']}")
        print(f"  含动态码  {health['with_totp']}")
        print(f"  无密码    {len(health['without_password'])}")
        if health["weak_passwords"]:
            names = "、".join(item["title"] for item in health["weak_passwords"][:5])
            print(f"  弱密码    {len(health['weak_passwords'])} 条：{names}")
        else:
            print("  弱密码    无")
        if health["reused_passwords"]:
            print(f"  重复使用  {len(health['reused_passwords'])} 组")
            for group in health["reused_passwords"][:3]:
                print(f"            {' = '.join(group)}")
        else:
            print("  重复使用  无")
        if health["stale_passwords"]:
            print(f"  超一年未改 {len(health['stale_passwords'])} 条")
    return 0


# --------------------------------------------------------------------- web / mcp
def cmd_web(args, settings) -> int:
    """`pv web` —— 起本地 Web 界面（只绑 127.0.0.1，一次性 token 写 runtime.json）。

    这条命令**必须**经 `pv.py` 入口跑：`clipboard.spawn_clear_watcher()` 靠
    `sys.argv[0]` 里的 `_clipwatch` 识别自家子进程，`python -m pwdvault.web`
    那种入口下 argv[0] 是包的 `__main__.py`，子进程会立刻退出、定时清空静默失效。
    （Web 侧调用 `copy_field` 时用的是 `spawn=False` 的进程内定时器，这里的
    入口约束是对 CLI 与将来复用者的提醒。）

    返回码：0 = 正常退出（Ctrl+C / stdin 关闭）；2 = 参数不合法；
    `Refused` 等 VaultError 由 `main()` 统一翻译成对应退出码。
    """
    from .web import serve as serve_web  # 局部导入：`pv find` 不该背上 Web 的导入成本

    port = getattr(args, "port", None)
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            print("错误：--port 需要一个整数。", file=sys.stderr)
            return 2
        if port < 0 or port > 65535:
            print("错误：--port 必须在 0 ~ 65535 之间（0 表示随便挑一个空闲端口）。", file=sys.stderr)
            return 2

    open_browser = not bool(getattr(args, "no_browser", False))
    exit_on_eof = bool(getattr(args, "exit_when_stdin_closes", False))

    # 实际地址由 `serve()` 在端口顺延之后打印（`requested_port` 被占会 +1 顺延，
    # 所以这里不能自己拼 URL —— 拼出来的是「想要的」，不是「真的」）。
    return serve_web(
        settings,
        port=port,
        open_browser=open_browser,
        exit_when_stdin_closes=exit_on_eof,
    )


def cmd_mcp(args, settings) -> int:
    """`pv mcp` —— 在 stdio 上跑 MCP 服务（给 Claude Desktop / Cursor 等客户端）。

    **stdout 是协议通道**：MCP 客户端把 stdout 的每一行都当 JSON-RPC 帧解析。
    只要有一行日志混进去，客户端就解析失败并**静默断连**（工具列表变空、日志里
    什么也看不到）—— 这是本项目最难排查的一类故障。所以：

    1. 本函数在调用 `mcp_server.main()` 之前**一行 print 都不能有**（包括错误提示）。
       `mcp_server.main()` 的第一件事就是 `install_stdout_guard()`：把 `sys.stdout`
       换成 `sys.stderr`，原始流只交给 transport 写帧。
    2. 这里也不能提前把 `sys.stdout` 换成 `sys.stderr`：`install_stdout_guard()`
       会把「当前的 `sys.stdout`」当成协议流，提前换过去等于让帧写到 stderr、
       客户端永远收不到 —— 修一个 bug 造一个更大的。
    3. 任何异常都只能进 `sys.stderr` 并在这里就地转成退出码。绝不能让它冒到
       `main()` 那层：那层在 `--json` 时会往 stdout 打 JSON，MCP 客户端会把它
       当协议帧解析，症状同样是静默断连。
    """
    from .mcp_server import main as mcp_main  # 局部导入：普通命令不加载协议层

    try:
        return int(mcp_main([], settings=settings))
    except KeyboardInterrupt:  # 放行：与 Ctrl+C 的常规语义一致
        return 130
    except SystemExit as exc:  # `SystemExit(0)` 这种正常结束不要当成故障
        code = exc.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)
    except BaseException as exc:  # noqa: BLE001 - 协议通道优先，绝不外冒
        print(
            f"[pv mcp] 内部错误：{type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return 1


# --------------------------------------------------------------------- 参数
def _add_common_args(parser: argparse.ArgumentParser, *, sub: bool) -> None:
    """全局参数在主/子 parser 各注册一次。

    子 parser 的 default 必须用 SUPPRESS：argparse 的子命令会新建 namespace 再把
    所有属性写回父对象，若子 parser 带 default=False，会把 `pv --json find` 里的
    True 冲掉。
    """
    vault_default = argparse.SUPPRESS if sub else None
    flag_default = argparse.SUPPRESS if sub else False

    parser.add_argument("--vault", default=vault_default, help="vault 文件路径")
    parser.add_argument("--json", action="store_true", default=flag_default, help="输出 JSON")
    parser.add_argument("--password-stdin", action="store_true", default=flag_default,
                        help="从标准输入读取主密码（脚本/agent 用）")
    parser.add_argument("--no-dpapi", action="store_true", default=flag_default,
                        help="忽略本机免密，强制用主密码")


def build_parser() -> argparse.ArgumentParser:
    main_common = argparse.ArgumentParser(add_help=False)
    _add_common_args(main_common, sub=False)

    sub_common = argparse.ArgumentParser(add_help=False)
    _add_common_args(sub_common, sub=True)

    parser = argparse.ArgumentParser(
        prog="pv",
        description="pwdvault —— 零知识本地密码库（密文可放网盘）",
        epilog="常用：pv init / pv add / pv find 关键词 / pv copy <id> / pv web / pv doctor",
        parents=[main_common],
    )
    sub = parser.add_subparsers(dest="cmd", metavar="命令")

    p = sub.add_parser("init", parents=[sub_common], help="初始化一个新 vault")
    p.add_argument("--local-unlock", dest="local_unlock", action="store_true", default=None,
                   help="启用本机免密")
    p.add_argument("--no-local-unlock", dest="local_unlock", action="store_false", default=None,
                   help="不启用本机免密")
    p.add_argument("--force", action="store_true", help="允许使用弱主密码")
    p.add_argument("--label", default="", help="给 vault 起个名字（会明文存于头部）")
    p.set_defaults(func=cmd_init)

    add = sub.add_parser("add", parents=[sub_common], help="新增一条记录")
    add.add_argument("-t", "--title"); add.add_argument("-u", "--username")
    add.add_argument("-p", "--password"); add.add_argument("--url")
    add.add_argument("-n", "--notes"); add.add_argument("--totp")
    add.add_argument("-g", "--tag", action="append"); add.add_argument("-f", "--field", action="append")
    add.add_argument("--from-json", metavar="文件|-", help="从 JSON 批量导入")
    add.add_argument("--mode", choices=["skip", "update", "append"], default="skip")
    add.add_argument("--dry-run", action="store_true")
    add.set_defaults(func=cmd_add)

    find = sub.add_parser("find", parents=[sub_common], help="模糊搜索")
    find.add_argument("query", nargs="+"); find.add_argument("--limit", type=int, default=None)
    find.add_argument("--reveal", action="store_true", help="--json 时输出明文密码（默认掩码）")
    find.set_defaults(func=cmd_find)

    lst = sub.add_parser("list", parents=[sub_common], help="列出全部")
    lst.add_argument("--reveal", action="store_true", help="--json 时输出明文密码（默认掩码）")
    lst.set_defaults(func=cmd_list)

    show = sub.add_parser("show", parents=[sub_common], help="查看一条（密码默认掩码）")
    show.add_argument("ref"); show.add_argument("--reveal", action="store_true")
    show.set_defaults(func=cmd_show)

    cp = sub.add_parser("copy", parents=[sub_common], help="把密码复制到剪贴板")
    cp.add_argument("ref"); cp.add_argument("--field"); cp.add_argument("--totp", action="store_true")
    cp.set_defaults(func=cmd_copy)

    tp = sub.add_parser("totp", parents=[sub_common], help="输出动态验证码")
    tp.add_argument("ref"); tp.add_argument("--at", type=float, default=None, help=argparse.SUPPRESS)
    tp.set_defaults(func=cmd_totp)

    edit = sub.add_parser("edit", parents=[sub_common], help="修改一条记录")
    edit.add_argument("ref")
    edit.add_argument("-t", "--title"); edit.add_argument("-u", "--username")
    edit.add_argument("-p", "--password"); edit.add_argument("--url")
    edit.add_argument("-n", "--notes"); edit.add_argument("--totp")
    edit.add_argument("-g", "--tag", action="append"); edit.add_argument("-f", "--field", action="append")
    edit.add_argument("-x", "--unset", action="append", help="删除某个字段")
    edit.add_argument("--dry-run", action="store_true")
    edit.set_defaults(func=cmd_edit)

    rm = sub.add_parser("rm", parents=[sub_common], help="删除一条记录")
    rm.add_argument("ref"); rm.add_argument("--yes", action="store_true")
    rm.set_defaults(func=cmd_rm)

    imp = sub.add_parser("import", parents=[sub_common], help="从 JSON/CSV/TXT 批量导入")
    imp.add_argument("file", help="文件路径，- 表示标准输入")
    imp.add_argument("--format", choices=["json", "csv", "txt"], default=None)
    imp.add_argument("--mode", choices=["skip", "update", "append"], default="skip")
    imp.add_argument("--dry-run", action="store_true")
    imp.set_defaults(func=cmd_import)

    exp = sub.add_parser("export", parents=[sub_common], help="导出明文（谨慎）")
    exp.add_argument("--format", choices=["json", "csv"], default="json")
    exp.add_argument("--out", "-o", default="-"); exp.add_argument("--yes", action="store_true")
    exp.add_argument("--query", nargs="*", default=None)
    exp.set_defaults(func=cmd_export)

    pw = sub.add_parser("passwd", parents=[sub_common], help="更换主密码")
    pw.add_argument("--force", action="store_true")
    pw.set_defaults(func=cmd_passwd)

    rec = sub.add_parser("recovery", parents=[sub_common], help="查看或重置恢复码")
    rec.add_argument("--reset", action="store_true")
    rec.set_defaults(func=cmd_recovery)

    lu = sub.add_parser("local-unlock", parents=[sub_common], help="本机免密开关")
    lu.add_argument("action", choices=["on", "off", "status"])
    lu.set_defaults(func=cmd_local_unlock)

    doc = sub.add_parser("doctor", parents=[sub_common], help="体检与备份提醒")
    doc.set_defaults(func=cmd_doctor)

    web = sub.add_parser("web", parents=[sub_common], help="打开本地网页界面")
    web.add_argument("--port", "-p", type=int, default=None,
                     help="监听端口（默认 8765；被占用则自动顺延）")
    web.add_argument("--no-browser", "-n", action="store_true",
                     help="不自动打开浏览器（服务器/脚本场景）")
    # 隐藏参数：只给测试与「父进程用管道接管」的场景用，不进 --help
    web.add_argument("--exit-when-stdin-closes", action="store_true",
                     default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    web.set_defaults(func=cmd_web)

    mcp = sub.add_parser("mcp", parents=[sub_common], help="以 MCP 服务方式运行（stdio）")
    # 不注册任何业务参数：`--vault` 由 sub_common 提供并透传给 load_settings。
    mcp.set_defaults(func=cmd_mcp)

    return parser


def _run_clipwatch(argv: list[str]) -> int:
    """剪贴板清空守护进程入口（内部命令，不进 argparse，避免污染帮助信息）。"""
    import time

    if len(argv) < 2:
        return 2
    digest, raw_seconds = argv[0], argv[1]
    try:
        seconds = int(raw_seconds)
    except ValueError:
        return 2
    time.sleep(max(1, seconds))
    clipboard.clear_if_matches(digest)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "_clipwatch":
        return _run_clipwatch(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0

    try:
        settings = load_settings(getattr(args, "vault", None))
        return args.func(args, settings)
    except VaultError as exc:
        if getattr(args, "json", False):
            print(json.dumps(exc.to_dict(), ensure_ascii=False))
        else:
            print(f"错误：{exc.message}", file=sys.stderr)
            if exc.hint:
                print(f"提示：{exc.hint}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
