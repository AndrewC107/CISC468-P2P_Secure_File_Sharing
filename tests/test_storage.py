"""
tests/test_storage.py – Unit tests for at-rest file encryption (Requirement 9)

Covers:
  • StorageKey construction and PBKDF2 derivation
  • Encrypt → Decrypt roundtrip
  • Two encryptions of the same data produce different ciphertexts (random nonce)
  • Tamper detection (InvalidTag raised on ciphertext modification)
  • Wrong passphrase → decryption fails with InvalidTag
  • Short blob raises ValueError before decryption is attempted
  • Encrypted files written / read back correctly via save/load helpers
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from peer.storage import StorageKey


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def key_a() -> StorageKey:
    """A StorageKey derived from passphrase 'alice-pass'.
    Uses a temp salt file so it never touches identity/storage_salt.bin."""
    return _make_key("alice-pass")


@pytest.fixture(scope="module")
def key_b() -> StorageKey:
    """A different StorageKey derived from passphrase 'bob-pass'."""
    return _make_key("bob-pass")


def _make_key(passphrase: str) -> StorageKey:
    """Helper: derive a StorageKey with a fresh in-memory salt (no disk I/O)."""
    salt = os.urandom(16)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    raw_key = kdf.derive(passphrase.encode("utf-8"))
    return StorageKey(raw_key)


# ── Construction ──────────────────────────────────────────────────────────────

class TestStorageKeyConstruction:
    def test_rejects_wrong_key_length(self):
        """StorageKey must be exactly 32 bytes."""
        with pytest.raises(ValueError):
            StorageKey(b"too-short")

    def test_rejects_34_byte_key(self):
        with pytest.raises(ValueError):
            StorageKey(b"A" * 34)

    def test_accepts_32_byte_key(self):
        k = StorageKey(b"A" * 32)
        assert k is not None


# ── Encrypt / Decrypt roundtrip ───────────────────────────────────────────────

class TestEncryptDecryptRoundtrip:
    def test_roundtrip_plaintext(self, key_a):
        """Decrypt(Encrypt(data)) == data."""
        original = b"Hello, secure world!"
        blob     = key_a.encrypt(original)
        assert key_a.decrypt(blob) == original

    def test_roundtrip_binary_data(self, key_a):
        """Arbitrary binary data (e.g. an image header) roundtrips correctly."""
        data = bytes(range(256)) * 100   # 25 600 bytes
        assert key_a.decrypt(key_a.encrypt(data)) == data

    def test_roundtrip_empty_bytes(self, key_a):
        """Empty plaintext is a valid edge case."""
        assert key_a.decrypt(key_a.encrypt(b"")) == b""

    def test_ciphertext_differs_from_plaintext(self, key_a):
        """The encrypted blob must not equal the plaintext."""
        data = b"secret data"
        assert key_a.encrypt(data) != data

    def test_two_encryptions_differ(self, key_a):
        """Each call to encrypt() uses a fresh random nonce – blobs differ."""
        data  = b"same data every time"
        blob1 = key_a.encrypt(data)
        blob2 = key_a.encrypt(data)
        assert blob1 != blob2

    def test_nonce_is_12_bytes(self, key_a):
        """The first 12 bytes of the blob are the nonce; ciphertext follows."""
        data = b"test"
        blob = key_a.encrypt(data)
        # blob = nonce(12) + ciphertext_with_tag
        # ciphertext_with_tag = len(data) + 16 (GCM auth tag)
        assert len(blob) == 12 + len(data) + 16


# ── Security: tamper and wrong-key detection ──────────────────────────────────

class TestTamperDetection:
    def test_tampered_ciphertext_raises_invalid_tag(self, key_a):
        """Modifying any byte of the ciphertext triggers InvalidTag.
        [Requirement 10: display an error if a security check fails]
        """
        blob     = key_a.encrypt(b"important document")
        tampered = bytearray(blob)
        tampered[15] ^= 0xFF   # flip a bit in the ciphertext portion
        with pytest.raises(InvalidTag):
            key_a.decrypt(bytes(tampered))

    def test_tampered_nonce_raises_invalid_tag(self, key_a):
        """Modifying the nonce (first 12 bytes) also triggers InvalidTag."""
        blob     = key_a.encrypt(b"another file")
        tampered = bytearray(blob)
        tampered[5] ^= 0x01
        with pytest.raises(InvalidTag):
            key_a.decrypt(bytes(tampered))

    def test_wrong_key_raises_invalid_tag(self, key_a, key_b):
        """Decrypting with a different key should fail with InvalidTag.
        [Requirement 9: only the key holder can read the file]
        """
        blob = key_a.encrypt(b"private data")
        with pytest.raises(InvalidTag):
            key_b.decrypt(blob)

    def test_blob_too_short_raises_value_error(self, key_a):
        """A blob shorter than nonce+tag cannot be valid."""
        with pytest.raises(ValueError):
            key_a.decrypt(b"short")


# ── File save / load helpers (peer/files.py integration) ─────────────────────

class TestStorageKeyWithFileHelpers:
    def test_save_and_decrypt_downloaded_file(self, key_a, tmp_path, monkeypatch):
        """
        save_downloaded_file_secure + manual decrypt roundtrip.

        Verifies that the .enc file on disk contains the encrypted bytes and
        that decrypting them gives back the original plaintext.
        """
        import peer.files as files_mod

        monkeypatch.setattr(files_mod, "DOWNLOADS_DIR", str(tmp_path))

        plaintext = b"Top secret report"
        dest = files_mod.save_downloaded_file_secure("report.txt", plaintext, key_a)

        assert dest.name == "report.txt.enc"
        assert dest.exists()
        # The raw file bytes should NOT equal the plaintext
        assert dest.read_bytes() != plaintext
        # Decrypting should recover the original content
        assert key_a.decrypt(dest.read_bytes()) == plaintext

    def test_save_without_storage_key_is_plaintext(self, tmp_path, monkeypatch):
        """When no key is provided, files are written as plain bytes."""
        import peer.files as files_mod

        monkeypatch.setattr(files_mod, "DOWNLOADS_DIR", str(tmp_path))

        plaintext = b"unencrypted file"
        dest = files_mod.save_downloaded_file_secure("plain.txt", plaintext, None)

        assert dest.name == "plain.txt"
        assert dest.read_bytes() == plaintext

    def test_sha256_in_list_shared_files(self, tmp_path, monkeypatch):
        """list_shared_files() includes correct sha256 for each file."""
        import peer.files as files_mod

        monkeypatch.setattr(files_mod, "SHARED_DIR", str(tmp_path))

        content = b"file content for hashing"
        (tmp_path / "sample.txt").write_bytes(content)

        files = files_mod.list_shared_files()
        assert len(files) == 1
        assert files[0]["filename"] == "sample.txt"
        assert files[0]["sha256"] == hashlib.sha256(content).hexdigest()
