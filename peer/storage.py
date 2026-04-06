# ─────────────────────────────────────────────────────────────────────────────
# storage.py – PBKDF2 + AES-GCM for at-rest files (matches Java StorageKey)
# ─────────────────────────────────────────────────────────────────────────────

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_SALT_PATH = Path("identity") / "storage_salt.bin"
_ITERATIONS = 600_000
_NONCE_LEN = 12
_TAG_BITS   = 128


class StorageKey:
    """AES-256 key derived from a passphrase (salt in identity/storage_salt.bin)."""

    def __init__(self, raw_key: bytes) -> None:
        if len(raw_key) != 32:
            raise ValueError("StorageKey requires exactly 32 bytes")
        self._key = raw_key

    @classmethod
    def derive(cls, passphrase: str) -> "StorageKey":
        """Build a key from the passphrase using PBKDF2-HMAC-SHA256 and the saved salt."""
        salt = _load_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_ITERATIONS,
        )
        return cls(kdf.derive(passphrase.encode("utf-8")))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt to nonce || ciphertext+tag (AES-GCM)."""
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, associated_data=None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt nonce || ciphertext+tag; raises InvalidTag on tamper/wrong key."""
        min_size = _NONCE_LEN + (_TAG_BITS // 8)
        if len(blob) < min_size:
            raise ValueError(
                f"Encrypted blob is too short ({len(blob)} bytes, minimum {min_size})"
            )
        nonce      = blob[:_NONCE_LEN]
        ciphertext = blob[_NONCE_LEN:]
        return AESGCM(self._key).decrypt(nonce, ciphertext, associated_data=None)


def _load_or_create_salt() -> bytes:
    """Load or create the 16-byte PBKDF2 salt file."""
    _SALT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _SALT_PATH.exists():
        return _SALT_PATH.read_bytes()
    salt = os.urandom(16)
    _SALT_PATH.write_bytes(salt)
    return salt
