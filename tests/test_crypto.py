"""加密内核测试：往返、篡改检测、上下文隔离。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwdvault import crypto
from pwdvault.errors import AuthenticationFailed, VaultError

FAST_KDF = {"algo": "argon2id", "time_cost": 1, "memory_cost": 8192, "parallelism": 1}


class KdfTests(unittest.TestCase):
    def test_deterministic(self):
        salt = b"0123456789abcdef"
        a = crypto.derive_kek("同一口令", salt, FAST_KDF)
        b = crypto.derive_kek("同一口令", salt, FAST_KDF)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_different_salt_gives_different_key(self):
        a = crypto.derive_kek("pw", b"0" * 16, FAST_KDF)
        b = crypto.derive_kek("pw", b"1" * 16, FAST_KDF)
        self.assertNotEqual(a, b)

    def test_unicode_normalization(self):
        """全角字符应归一到半角，避免用户切换输入法后打不开 vault。"""
        a = crypto.derive_kek("abc123", b"0" * 16, FAST_KDF)
        b = crypto.derive_kek("ａｂｃ１２３", b"0" * 16, FAST_KDF)
        self.assertEqual(a, b)

    def test_scrypt_fallback(self):
        key = crypto.derive_kek("pw", b"0" * 16, {"algo": "scrypt"})
        self.assertEqual(len(key), 32)

    def test_unknown_algo(self):
        with self.assertRaises(VaultError):
            crypto.derive_kek("pw", b"0" * 16, {"algo": "rot13"})


class AeadTests(unittest.TestCase):
    def setUp(self):
        self.key = crypto.new_dek()
        self.aad = crypto.make_aad("vault01", "payload")

    def test_roundtrip(self):
        sealed = crypto.seal(self.key, "机密内容".encode(), self.aad)
        self.assertEqual(crypto.open_sealed(self.key, sealed, self.aad), "机密内容".encode())

    def test_nonce_is_unique(self):
        a = crypto.seal(self.key, b"x", self.aad)
        b = crypto.seal(self.key, b"x", self.aad)
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_ciphertext_tampering_detected(self):
        sealed = crypto.seal(self.key, b"data", self.aad)
        raw = bytearray(crypto.b64d(sealed["ct"]))
        raw[0] ^= 0x01
        with self.assertRaises(AuthenticationFailed):
            crypto.open_sealed(self.key, {"nonce": sealed["nonce"], "ct": crypto.b64e(bytes(raw))}, self.aad)

    def test_nonce_tampering_detected(self):
        sealed = crypto.seal(self.key, b"data", self.aad)
        nonce = bytearray(crypto.b64d(sealed["nonce"]))
        nonce[0] ^= 0xFF
        with self.assertRaises(AuthenticationFailed):
            crypto.open_sealed(self.key, {"nonce": crypto.b64e(bytes(nonce)), "ct": sealed["ct"]}, self.aad)

    def test_wrong_aad_rejected(self):
        sealed = crypto.seal(self.key, b"data", self.aad)
        other = crypto.make_aad("vault01", "wrap/password")
        with self.assertRaises(AuthenticationFailed):
            crypto.open_sealed(self.key, sealed, other)

    def test_wrong_vault_id_rejected(self):
        sealed = crypto.seal(self.key, b"data", self.aad)
        other = crypto.make_aad("vault02", "payload")
        with self.assertRaises(AuthenticationFailed):
            crypto.open_sealed(self.key, sealed, other)


class WrapTests(unittest.TestCase):
    def test_wrap_unwrap(self):
        kek = crypto.new_dek()
        dek = crypto.new_dek()
        sealed = crypto.wrap_dek(kek, dek, "vault01", "password")
        self.assertEqual(crypto.unwrap_dek(kek, sealed, "vault01", "password"), dek)

    def test_cannot_move_wrap_between_purposes(self):
        """把 password 的包裹密文挪到 recovery 位置必须失败。"""
        kek = crypto.new_dek()
        dek = crypto.new_dek()
        sealed = crypto.wrap_dek(kek, dek, "vault01", "password")
        with self.assertRaises(AuthenticationFailed):
            crypto.unwrap_dek(kek, sealed, "vault01", "recovery")


class RecoveryCodeTests(unittest.TestCase):
    def test_roundtrip(self):
        from pwdvault.vault import decode_recovery_code, encode_recovery_code

        raw = bytes(range(32))
        code = encode_recovery_code(raw)
        self.assertIn("-", code)
        self.assertEqual(decode_recovery_code(code), raw)

    def test_case_and_separator_insensitive(self):
        from pwdvault.vault import decode_recovery_code, encode_recovery_code

        raw = bytes(range(32))
        code = encode_recovery_code(raw)
        messy = " " + code.lower().replace("-", " ") + " "
        self.assertEqual(decode_recovery_code(messy), raw)


if __name__ == "__main__":
    unittest.main()
