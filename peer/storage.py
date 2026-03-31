"""
storage.py – Password-protected AES-256-GCM encryption for local files at rest

Requirement 9: "Securely store files on the local client device, so that an
attacker who steals the device should not be able to read them."

Why encrypt at rest?
────────────────────
Without at-rest encryption anyone who can access the filesystem (stolen
laptop, compromised OS account, forensic imaging) can read every received file
in plain text.  Encrypting with a passphrase-derived key means the attacker
also needs to know the passphrase.

Design
──────
  • The user provides a passphrase once at startup.
  • A 32-byte AES-256 key is derived from the passphrase using PBKDF2-HMAC-
    SHA256 (600 000 iterations) with a 16-byte random salt.  The salt is
    persisted to identity/storage_salt.bin so the same key is re-derived on
    every subsequent launch.
  • Each encrypted file is stored as:
        nonce(12 bytes)  ||  AES-GCM ciphertext  (plaintext + 16-byte auth tag)
  • Files in storage/downloads/ are always written encrypted (.enc extension).
  • Files in storage/shared/ placed there manually by the user are served as-is
    (they existed before the app ran).  The app also transparently reads any
    .enc file it finds in shared/ (encrypted imports via menu option).

Java interoperability
──────────────────────
The on-disk format is standard:
  • PBKDF2-HMAC-SHA256 → javax.crypto PBKDF2WithHmacSHA256
  • AES/GCM/NoPadding  → same JCA name
  • Salt file           → plain binary, trivially read with Files.readAllBytes()
"""

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Salt stored alongside identity keys so it lives outside git-tracked dirs.
_SALT_PATH = Path("identity") / "storage_salt.bin"

# 600 000 iterations – NIST SP 800-132 recommendation for PBKDF2-SHA256 (2023).
_ITERATIONS = 600_000

# AES-GCM nonce length (bytes) and authentication tag bits.
_NONCE_LEN = 12
_TAG_BITS   = 128


class StorageKey:
    """
    Thin wrapper around a PBKDF2-derived 32-byte AES-256 key.

    Create exactly once at startup with ``StorageKey.derive(passphrase)``
    and pass the instance to any component that reads or writes local files.

    The key itself is never written to disk – only the PBKDF2 salt is persisted,
    so the key can be reconstructed from the passphrase on the next launch.
    """

    def __init__(self, raw_key: bytes) -> None:
        if len(raw_key) != 32:
            raise ValueError("StorageKey requires exactly 32 bytes")
        self._key = raw_key

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def derive(cls, passphrase: str) -> "StorageKey":
        """
        Derive a StorageKey from a user-supplied passphrase.

        The PBKDF2 salt is loaded from identity/storage_salt.bin on every
        launch.  If the file does not exist (first run) a fresh 16-byte random
        salt is generated and saved there.

        Java equivalent:
          SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
          PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 600_000, 256);
          byte[] rawKey = skf.generateSecret(spec).getEncoded();
        """
        salt = _load_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_ITERATIONS,
        )
        return cls(kdf.derive(passphrase.encode("utf-8")))

    # ── Encryption / decryption ───────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext → nonce(12) || ciphertext_with_tag.

        [CONFIDENTIALITY + INTEGRITY at rest]
        A fresh 96-bit nonce is generated for every call.  The AES-GCM
        authentication tag (appended by the library to the ciphertext) detects
        any corruption or tampering before the file is used.

        Java equivalent:
          Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
          cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
          byte[] blob = concat(nonce, cipher.doFinal(plaintext));
        """
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, associated_data=None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        """
        Decrypt nonce(12) || ciphertext_with_tag → plaintext.

        Raises
        ------
        cryptography.exceptions.InvalidTag
            If the authentication tag does not match – the file was corrupted
            or tampered with on disk.  Callers MUST treat this as a security
            error (Requirement 10).
        ValueError
            If the blob is shorter than the minimum valid size.
        """
        min_size = _NONCE_LEN + (_TAG_BITS // 8)
        if len(blob) < min_size:
            raise ValueError(
                f"Encrypted blob is too short ({len(blob)} bytes, minimum {min_size})"
            )
        nonce      = blob[:_NONCE_LEN]
        ciphertext = blob[_NONCE_LEN:]
        return AESGCM(self._key).decrypt(nonce, ciphertext, associated_data=None)


# ── Private helpers ───────────────────────────────────────────────────────────

def _load_or_create_salt() -> bytes:
    """Load the PBKDF2 salt from disk, generating and saving it on first use."""
    _SALT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _SALT_PATH.exists():
        return _SALT_PATH.read_bytes()
    salt = os.urandom(16)
    _SALT_PATH.write_bytes(salt)
    return salt
