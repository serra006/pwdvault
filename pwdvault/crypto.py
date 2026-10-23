"""密码学内核 —— 全项目唯一允许直接触碰加密库的地方。

设计要点
--------
1. KEK / DEK 两层：主密码派生 KEK，用 KEK 包裹随机 DEK；改密码只重包裹 DEK。
2. 每个 vault 有独立 vault_id，所有 AAD 都绑定它，跨 vault 搬运密文必然失败。
3. AAD 同时绑定用途（wrap/password、wrap/recovery、payload），
   防止把恢复码的包裹密文挪到主密码位置。
4. 不自行发明任何密码学构造，全部使用标准原语。
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .config import DEFAULT_KDF, FORMAT_NAME, FORMAT_VERSION
from .errors import AuthenticationFailed, VaultError

DEK_LEN = 32
NONCE_LEN = 12


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def to_secret_bytes(secret: str | bytes) -> bytes:
    """统一把密码归一到 UTF-8 字节。str 走 NFKC，避免全角/兼容字符导致无法解锁。"""
    if isinstance(secret, bytes):
        return secret
    import unicodedata

    return unicodedata.normalize("NFKC", secret).encode("utf-8")


def derive_kek(secret: str | bytes, salt: bytes, kdf: dict | None = None) -> bytes:
    """用 KDF 把用户口令派生成 256 位 KEK。"""
    params = {**DEFAULT_KDF, **(kdf or {})}
    raw = to_secret_bytes(secret)
    algo = params.get("algo", "argon2id")

    if algo == "argon2id":
        return hash_secret_raw(
            secret=raw,
            salt=salt,
            time_cost=int(params["time_cost"]),
            memory_cost=int(params["memory_cost"]),
            parallelism=int(params["parallelism"]),
            hash_len=DEK_LEN,
            type=Type.ID,
        )
    if algo == "scrypt":
        return hashlib.scrypt(
            raw,
            salt=salt,
            n=2**15,
            r=8,
            p=1,
            dklen=DEK_LEN,
            maxmem=96 * 1024 * 1024,
        )
    raise VaultError(f"不支持的 KDF 算法：{algo}", hint="可能是更新版本创建的 vault。")


def new_dek() -> bytes:
    return secrets.token_bytes(DEK_LEN)


def new_salt() -> bytes:
    return secrets.token_bytes(int(DEFAULT_KDF["salt_len"]))


def new_vault_id() -> str:
    return secrets.token_hex(8)


def make_aad(vault_id: str, purpose: str) -> bytes:
    return f"{FORMAT_NAME}/v{FORMAT_VERSION}/{vault_id}/{purpose}".encode("utf-8")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(NONCE_LEN)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def open_sealed(key: bytes, sealed: dict, aad: bytes, *, what: str = "数据") -> bytes:
    try:
        nonce = b64d(sealed["nonce"])
        ct = b64d(sealed["ct"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError(f"{what}密文结构不完整") from exc
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise AuthenticationFailed(f"{what}校验失败：口令错误或文件已被篡改") from exc


def wrap_dek(kek: bytes, dek: bytes, vault_id: str, method: str) -> dict:
    return seal(kek, dek, make_aad(vault_id, f"wrap/{method}"))


def unwrap_dek(kek: bytes, sealed: dict, vault_id: str, method: str) -> bytes:
    dek = open_sealed(kek, sealed, make_aad(vault_id, f"wrap/{method}"), what="密钥")
    if len(dek) != DEK_LEN:
        raise VaultError("解出的数据密钥长度异常")
    return dek


def encrypt_payload(dek: bytes, plaintext: bytes, vault_id: str) -> dict:
    return seal(dek, plaintext, make_aad(vault_id, "payload"))


def decrypt_payload(dek: bytes, sealed: dict, vault_id: str) -> bytes:
    return open_sealed(dek, sealed, make_aad(vault_id, "payload"))
