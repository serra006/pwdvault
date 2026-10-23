"""存储层：文件格式、原子写入、快照轮转。

这一层只关心「字节怎么安全落盘」，不懂业务规则。
两个必须守住的底线：
  1. 任何一次写入都不能让唯一副本处于半截状态 —— tmp + fsync + rename。
  2. 每次覆盖旧文件之前先留一份快照 —— 用户手滑改错时有退路。
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from . import crypto, dpapi
from .config import FORMAT_NAME, FORMAT_VERSION, Settings
from .errors import (
    AuthenticationFailed,
    CorruptVault,
    NoUnlockMethod,
    StaleWrite,
    VaultExists,
    VaultError,
    VaultNotFound,
    VaultReplaced,
)
from .models import Record, now_iso

MAX_VAULT_BYTES = 64 * 1024 * 1024
HEADER_VERSION = FORMAT_VERSION

# os.replace 在目标被占用时的重试：20/40/80/160/320ms（合计约 620ms）
REPLACE_ATTEMPTS = 6
REPLACE_BASE_DELAY = 0.02


def _read_text_retry(path: Path, *, attempts: int = REPLACE_ATTEMPTS) -> str:
    """读取 data.enc 时重试。

    Windows 上别人正在 `os.replace` 的瞬间，读端可能拿到 `PermissionError`
    （共享冲突）。读路径不能因此报「文件损坏」，所以和有界重试对称处理。
    """
    for attempt in range(attempts):
        try:
            return path.read_text(encoding="utf-8")
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(REPLACE_BASE_DELAY * (2**attempt))
    raise CorruptVault("读取失败")  # pragma: no cover - 循环内必返回或抛出


# ---------------------------------------------------------------- 头部只读访问
def read_header(path: Path) -> dict:
    """只解析头部（不解密），供 revision 比对与 open_with_dek 复用。

    与 `Vault.open` 的头部校验保持一致，但完全不碰 KDF 与载荷。
    """
    target = Path(path)
    if not target.exists():
        raise VaultNotFound(str(target))
    size = target.stat().st_size
    if size == 0:
        raise CorruptVault("文件为空")
    if size > MAX_VAULT_BYTES:
        raise CorruptVault(f"文件异常偏大（{size} 字节）")
    try:
        raw = json.loads(_read_text_retry(target))
    except json.JSONDecodeError as exc:
        raise CorruptVault(f"不是合法的 JSON（{exc.msg}）") from exc
    if not isinstance(raw, dict):
        raise CorruptVault("头部不是键值对象")
    if raw.get("format") != FORMAT_NAME:
        raise CorruptVault("format 标识不匹配")
    if int(raw.get("version", 0)) > HEADER_VERSION:
        raise CorruptVault("文件由更高版本创建，请升级程序")
    if not raw.get("vault_id"):
        raise CorruptVault("缺少 vault_id")
    return raw


def read_revision(path: Path) -> int:
    """只读盘上的 revision。原子 rename 保证读到的必然是完整版本。"""
    return int((read_header(path).get("meta") or {}).get("revision", 0))


def encode_recovery_code(raw: bytes) -> str:
    """把 32 字节恢复码编码成人类可抄写的形式：XXXX-XXXX-... 共 8 组。"""
    text = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [text[i : i + 4] for i in range(0, len(text), 4)]
    return "-".join(groups)


def decode_recovery_code(text: str) -> bytes:
    cleaned = "".join(ch for ch in text.upper() if ch.isalnum())
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        return base64.b32decode(cleaned + pad)
    except Exception as exc:
        raise AuthenticationFailed("恢复码格式不正确") from exc


class Vault:
    def __init__(
        self,
        settings: Settings,
        header: dict,
        dek: bytes,
        records: list[Record],
        *,
        unlocked_by: str,
    ) -> None:
        self.settings = settings
        self.header = header
        self.dek = dek
        self.records = records
        self.unlocked_by = unlocked_by
        self.dirty = False

    # ------------------------------------------------------------------ 属性
    @property
    def path(self) -> Path:
        return self.settings.vault_path

    @property
    def vault_id(self) -> str:
        return self.header["vault_id"]

    @property
    def revision(self) -> int:
        return int(self.header.get("meta", {}).get("revision", 0))

    def has_method(self, method: str) -> bool:
        return method in self.header.get("wraps", {})

    # ------------------------------------------------------------------ 创建
    @classmethod
    def create(
        cls,
        settings: Settings,
        master_password: str,
        *,
        enable_dpapi: bool = False,
        label: str = "",
    ) -> tuple["Vault", str]:
        path = settings.vault_path
        if path.exists():
            raise VaultExists(str(path))

        salt = crypto.new_salt()
        kdf = dict(settings.kdf)
        kek = crypto.derive_kek(master_password, salt, kdf)
        dek = crypto.new_dek()
        vault_id = crypto.new_vault_id()

        # 恢复码用独立 salt：这样以后改主密码换了主 salt，恢复码依然有效。
        recovery_raw = secrets.token_bytes(32)
        recovery_code = encode_recovery_code(recovery_raw)
        recovery_salt = crypto.new_salt()
        recovery_kek = crypto.derive_kek(recovery_code, recovery_salt, kdf)

        wraps = {
            "password": crypto.wrap_dek(kek, dek, vault_id, "password"),
            "recovery": {
                **crypto.wrap_dek(recovery_kek, dek, vault_id, "recovery"),
                "salt": crypto.b64e(recovery_salt),
            },
        }
        if enable_dpapi:
            if not dpapi.is_supported():
                raise VaultError("当前系统不支持 DPAPI，无法启用本机免密")
            wraps["dpapi"] = {"blob": base64.b64encode(dpapi.protect(dek)).decode("ascii")}

        stamp = now_iso()
        header = {
            "format": FORMAT_NAME,
            "version": HEADER_VERSION,
            "vault_id": vault_id,
            "label": label,
            "kdf": {
                "algo": kdf["algo"],
                "time_cost": kdf["time_cost"],
                "memory_cost": kdf["memory_cost"],
                "parallelism": kdf["parallelism"],
                "salt": crypto.b64e(salt),
            },
            "wraps": wraps,
            "payload": {},
            "meta": {"created": stamp, "updated": stamp, "revision": 0, "count": 0},
        }

        vault = cls(settings, header, dek, [], unlocked_by="password")
        vault._write_payload()
        vault.save(first=True)
        return vault, recovery_code

    # ------------------------------------------------------------------ 打开
    @classmethod
    def open(
        cls,
        settings: Settings,
        *,
        password: str | None = None,
        recovery_code: str | None = None,
        allow_dpapi: bool = True,
    ) -> "Vault":
        path = settings.vault_path
        if not path.exists():
            raise VaultNotFound(str(path))
        size = path.stat().st_size
        if size == 0:
            raise CorruptVault("文件为空")
        if size > MAX_VAULT_BYTES:
            raise CorruptVault(f"文件异常偏大（{size} 字节）")

        try:
            raw = json.loads(_read_text_retry(path))
        except json.JSONDecodeError as exc:
            raise CorruptVault(f"不是合法的 JSON（{exc.msg}）") from exc

        if raw.get("format") != FORMAT_NAME:
            raise CorruptVault("format 标识不匹配")
        if int(raw.get("version", 0)) > HEADER_VERSION:
            raise CorruptVault("文件由更高版本创建，请升级程序")

        vault_id = raw.get("vault_id")
        kdf_info = raw.get("kdf") or {}
        wraps = raw.get("wraps") or {}
        if not vault_id or "salt" not in kdf_info or not wraps:
            raise CorruptVault("缺少必要头部字段")

        try:
            salt = crypto.b64d(kdf_info["salt"])
        except Exception as exc:
            raise CorruptVault("salt 编码异常") from exc

        kdf = {
            "algo": kdf_info.get("algo", "argon2id"),
            "time_cost": kdf_info.get("time_cost", 3),
            "memory_cost": kdf_info.get("memory_cost", 65536),
            "parallelism": kdf_info.get("parallelism", 4),
        }

        dek: bytes | None = None
        unlocked_by = ""

        if password is not None:
            kek = crypto.derive_kek(password, salt, kdf)
            dek = crypto.unwrap_dek(kek, wraps["password"], vault_id, "password")
            unlocked_by = "password"
        elif recovery_code is not None:
            if "recovery" not in wraps:
                raise AuthenticationFailed("该 vault 没有设置恢复码")
            rec_salt_raw = wraps["recovery"].get("salt")
            rec_salt = crypto.b64d(rec_salt_raw) if rec_salt_raw else salt
            kek = crypto.derive_kek(recovery_code, rec_salt, kdf)
            dek = crypto.unwrap_dek(kek, wraps["recovery"], vault_id, "recovery")
            unlocked_by = "recovery"
        elif allow_dpapi and "dpapi" in wraps:
            blob = base64.b64decode(wraps["dpapi"]["blob"])
            dek = dpapi.unprotect(blob)
            unlocked_by = "dpapi"

        if dek is None:
            raise NoUnlockMethod()

        payload = crypto.decrypt_payload(dek, raw.get("payload") or {}, vault_id)
        try:
            body = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CorruptVault("正文解密成功但内容无法解析") from exc

        records = [Record.from_dict(item, keep_id=True) for item in body.get("records", [])]

        vault = cls(settings, raw, dek, records, unlocked_by=unlocked_by)
        if vault.settings.snapshot_keep and "meta" not in raw:
            raw["meta"] = {}
        return vault

    @classmethod
    def open_with_dek(
        cls,
        settings: Settings,
        dek: bytes,
        *,
        expected_vault_id: str | None = None,
    ) -> "Vault":
        """用已解包的 DEK 直接打开（跳过 KDF），供 rebase reload 使用。

        `expected_vault_id` 用来识别「盘上的文件被换成了另一个库」：
        vault_id 不符 → `VaultReplaced`（DEK 已失效，必须重新解锁）。
        """
        raw = read_header(settings.vault_path)
        vault_id = str(raw.get("vault_id"))
        if expected_vault_id is not None and vault_id != expected_vault_id:
            raise VaultReplaced(
                "密码库文件已是另一个库（vault_id 不同），当前解锁状态失效，请重新解锁。"
            )

        payload = crypto.decrypt_payload(dek, raw.get("payload") or {}, vault_id)
        try:
            body = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CorruptVault("正文解密成功但内容无法解析") from exc

        records = [Record.from_dict(item, keep_id=True) for item in body.get("records", [])]
        if "meta" not in raw:
            raw["meta"] = {}
        return cls(settings, raw, dek, records, unlocked_by="dek")

    # ------------------------------------------------------------------ 保存
    def _serialize_payload(self) -> bytes:
        body = {"schema": HEADER_VERSION, "records": [r.to_dict() for r in self.records]}
        return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _write_payload(self) -> None:
        self.header["payload"] = crypto.encrypt_payload(
            self.dek, self._serialize_payload(), self.vault_id
        )

    def save(self, *, first: bool = False, expected_revision: int | None = None) -> None:
        """把当前内存状态原子写盘。

        **本方法自己不加锁**，锁由调用方持有（`VaultStore.commit` / `cli.save_or_fail`）。
        `expected_revision` 是防御性的冗余断言：默认 None 不校验（v1.0 语义不变），
        传了就必须与盘上 revision 一致，否则抛 `StaleWrite`，宁可失败也不静默覆盖。
        """
        if expected_revision is not None:
            current = 0
            try:
                current = read_revision(self.path)
            except VaultNotFound:
                current = 0
            if current != expected_revision:
                raise StaleWrite(
                    f"文件修订已是 {current}，而这次写入基于 {expected_revision}，已放弃写入。"
                )

        self._write_payload()
        stamp = now_iso()
        self.header["meta"] = {
            "created": self.header.get("meta", {}).get("created", stamp),
            "updated": stamp,
            "revision": 0 if first else self.revision + 1,
            "count": len(self.records),
        }

        text = json.dumps(self.header, ensure_ascii=False, indent=2)
        data = text.encode("utf-8")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not first and self.path.exists():
            self._snapshot()
        atomic_write(self.path, data)
        self.dirty = False

    def snapshot_now(self) -> bool:
        """显式打一份快照（commit 前用）。快照失败只记 stderr，不影响主数据写入。"""
        if not self.path.exists():
            return False
        try:
            self._snapshot()
            return True
        except OSError as exc:  # noqa: BLE001 - 快照是保险不是主数据
            print(f"[pv] WARNING 快照失败（不影响本次写入）：{type(exc).__name__}", file=sys.stderr)
            return False

    def _snapshot(self) -> None:
        keep = self.settings.snapshot_keep
        if keep <= 0:
            return
        snap_dir = self.settings.snapshot_dir
        snap_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = snap_dir / f"data-{stamp}.enc"
        counter = 1
        while target.exists():
            target = snap_dir / f"data-{stamp}-{counter}.enc"
            counter += 1
        shutil.copy2(self.path, target)
        self._rotate_snapshots(keep)

    def _rotate_snapshots(self, keep: int) -> None:
        snaps = sorted(self.settings.snapshot_dir.glob("data-*.enc"))
        for old in snaps[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------ 密钥维护
    def current_kdf(self) -> dict:
        info = self.header.get("kdf", {})
        return {
            "algo": info.get("algo", "argon2id"),
            "time_cost": info.get("time_cost", 3),
            "memory_cost": info.get("memory_cost", 65536),
            "parallelism": info.get("parallelism", 4),
        }

    def rewrap_password(self, new_password: str) -> None:
        """改主密码：换新 salt 重新派生 KEK，只重包一次 DEK，不动正文。"""
        salt = crypto.new_salt()
        kek = crypto.derive_kek(new_password, salt, self.current_kdf())
        self.header["kdf"]["salt"] = crypto.b64e(salt)
        self.header["wraps"]["password"] = crypto.wrap_dek(kek, self.dek, self.vault_id, "password")
        self.dirty = True

    def enable_local_unlock(self) -> None:
        if not dpapi.is_supported():
            raise VaultError("当前系统不支持 DPAPI")
        self.header["wraps"]["dpapi"] = {
            "blob": base64.b64encode(dpapi.protect(self.dek)).decode("ascii"),
            "machine": dpapi.machine_fingerprint(),
        }
        self.dirty = True

    def disable_local_unlock(self) -> None:
        self.header["wraps"].pop("dpapi", None)
        self.dirty = True

    def reset_recovery(self) -> str:
        """重新生成恢复码（旧的立即失效）。"""
        raw = secrets.token_bytes(32)
        code = encode_recovery_code(raw)
        salt = crypto.new_salt()
        kek = crypto.derive_kek(code, salt, self.current_kdf())
        self.header["wraps"]["recovery"] = {
            **crypto.wrap_dek(kek, self.dek, self.vault_id, "recovery"),
            "salt": crypto.b64e(salt),
        }
        self.dirty = True
        return code

    # ------------------------------------------------------------------ 便捷
    def find_by_id(self, record_id: str) -> Record | None:
        for record in self.records:
            if record.id == record_id:
                return record
        return None

    def touch(self) -> None:
        self.dirty = True


def atomic_write(path: Path, data: bytes) -> None:
    """先写临时文件并 fsync，再用一次 rename 原子替换。

    这是「不让唯一副本半截损坏」的最后一道保险。

    Windows 上 `os.replace` 在目标文件被别的进程打开读时可能抛 `PermissionError`
    （共享冲突），网盘同步与杀软会显著放大这个窗口 —— v1.0 没有重试，这是并发
    迭代引入的新暴露面，所以这里做 6 次指数退避重试（20/40/80/160/320ms）。
    """
    tmp = path.with_name(path.name + ".tmp")
    handle = open(tmp, "wb")
    try:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()

    for attempt in range(REPLACE_ATTEMPTS):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(REPLACE_BASE_DELAY * (2**attempt))


def inspect(settings: Settings) -> dict:
    """不解密，只读头部，用于 doctor 与故障排查。"""
    path = settings.vault_path
    if not path.exists():
        return {"exists": False, "path": str(path)}
    size = path.stat().st_size
    info: dict = {"exists": True, "path": str(path), "size": size}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        info.update(
            {
                "format": raw.get("format"),
                "version": raw.get("version"),
                "vault_id": raw.get("vault_id"),
                "methods": sorted((raw.get("wraps") or {}).keys()),
                "kdf": (raw.get("kdf") or {}).get("algo"),
                "meta": raw.get("meta", {}),
            }
        )
    except Exception as exc:  # noqa: BLE001 - doctor 需要容错
        info["error"] = f"{type(exc).__name__}: {exc}"
    snaps = sorted(settings.snapshot_dir.glob("data-*.enc")) if settings.snapshot_dir.exists() else []
    info["snapshots"] = len(snaps)
    info["latest_snapshot"] = snaps[-1].name if snaps else None
    return info
