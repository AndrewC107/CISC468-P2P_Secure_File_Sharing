"""
tests/test_crypto_integration.py – Integration tests for the Phase 3 crypto pipeline.

Covers:
  - LocalIdentity generation and key loading
  - ECDH commutativity (sender and receiver derive the same AES key)
  - AES-256-GCM encrypt / decrypt roundtrip
  - GCM tamper detection (InvalidTag)
  - Ed25519 sign / verify roundtrip
  - Bad-signature rejection
  - Filename/nonce/ciphertext substitution attacks are detected
  - contacts.save_contact with encryption_key
"""

import base64
import pytest

from cryptography.exceptions import InvalidTag

from peer.crypto import (
    load_or_generate_keys,
    generate_ephemeral_x25519,
    x25519_public_key_to_raw,
    x25519_public_raw_from_pem,
    ecdh_derive_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    sign_transfer,
    verify_transfer_signature,
)
from peer.contacts import save_contact, get_contact


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def alice_identity():
    return load_or_generate_keys()


@pytest.fixture(scope="module")
def bob_identity():
    # Bob is simulated with a freshly generated in-memory Ed25519 key.
    # We cannot use load_or_generate_keys() here because it returns the same
    # on-disk keys as alice when running on the same machine.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from peer.crypto import LocalIdentity, compute_fingerprint

    sign_priv = Ed25519PrivateKey.generate()
    sign_pub_pem = sign_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    enc_priv = X25519PrivateKey.generate()
    enc_pub_pem = enc_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return LocalIdentity(
        signing_private_key=sign_priv,
        signing_public_key_pem=sign_pub_pem,
        fingerprint=compute_fingerprint(sign_pub_pem),
        encryption_private_key=enc_priv,
        encryption_public_key_pem=enc_pub_pem,
    )


@pytest.fixture(scope="module")
def ephemeral_key():
    return generate_ephemeral_x25519()


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestIdentityLoading:
    def test_identity_has_all_fields(self, alice_identity):
        assert alice_identity.signing_private_key is not None
        assert alice_identity.signing_public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert alice_identity.fingerprint != ""
        assert alice_identity.encryption_private_key is not None
        assert alice_identity.encryption_public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_fingerprint_format(self, alice_identity):
        parts = alice_identity.fingerprint.split(":")
        assert len(parts) == 32, "SHA-256 fingerprint should have 32 colon-separated pairs"
        assert all(len(p) == 2 for p in parts)
        assert all(c in "0123456789ABCDEF" for p in parts for c in p)

    def test_keys_are_stable_across_loads(self):
        id1 = load_or_generate_keys()
        id2 = load_or_generate_keys()
        assert id1.signing_public_key_pem == id2.signing_public_key_pem
        assert id1.encryption_public_key_pem == id2.encryption_public_key_pem
        assert id1.fingerprint == id2.fingerprint


class TestECDH:
    def test_ecdh_commutativity(self, alice_identity, ephemeral_key):
        """Sender and receiver must derive the same AES session key."""
        alice_raw_pub = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        eph_raw       = x25519_public_key_to_raw(ephemeral_key)

        # Sender: ECDH(ephemeral_private, alice_static_public)
        sender_key   = ecdh_derive_key(ephemeral_key, alice_raw_pub)
        # Receiver: ECDH(alice_static_private, ephemeral_public)
        receiver_key = ecdh_derive_key(alice_identity.encryption_private_key, eph_raw)

        assert sender_key == receiver_key

    def test_derived_key_is_32_bytes(self, alice_identity, ephemeral_key):
        alice_raw_pub = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw_pub)
        assert len(key) == 32

    def test_ephemeral_key_raw_is_32_bytes(self, ephemeral_key):
        raw = x25519_public_key_to_raw(ephemeral_key)
        assert len(raw) == 32


class TestAESGCM:
    def test_encrypt_decrypt_roundtrip(self, alice_identity, ephemeral_key):
        alice_raw = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw)
        plaintext = b"Hello, secure P2P world!"
        nonce, ciphertext = aes_gcm_encrypt(key, plaintext)
        recovered = aes_gcm_decrypt(key, nonce, ciphertext)
        assert recovered == plaintext

    def test_nonce_is_12_bytes(self, alice_identity, ephemeral_key):
        alice_raw = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw)
        nonce, _ = aes_gcm_encrypt(key, b"test")
        assert len(nonce) == 12

    def test_ciphertext_differs_from_plaintext(self, alice_identity, ephemeral_key):
        alice_raw = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw)
        plaintext = b"secret data"
        _, ciphertext = aes_gcm_encrypt(key, plaintext)
        assert ciphertext != plaintext

    def test_tamper_detection(self, alice_identity, ephemeral_key):
        """GCM authentication tag must detect ciphertext modification."""
        alice_raw = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw)
        nonce, ciphertext = aes_gcm_encrypt(key, b"important file contents")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(key, nonce, bytes(tampered))

    def test_wrong_key_raises(self, alice_identity, ephemeral_key):
        """Decryption with a different key must raise InvalidTag."""
        alice_raw = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw)
        nonce, ciphertext = aes_gcm_encrypt(key, b"confidential")
        wrong_key = b"\x00" * 32
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(wrong_key, nonce, ciphertext)


class TestEd25519SignVerify:
    FILENAME   = "report.pdf"
    PLAINTEXT  = b"This is the file content."

    def _make_transfer(self, alice_identity, ephemeral_key):
        alice_raw = x25519_public_raw_from_pem(alice_identity.encryption_public_key_pem)
        key = ecdh_derive_key(ephemeral_key, alice_raw)
        nonce, ciphertext = aes_gcm_encrypt(key, self.PLAINTEXT)
        eph_raw = x25519_public_key_to_raw(ephemeral_key)
        return eph_raw, nonce, ciphertext

    def test_valid_signature_accepted(self, alice_identity, ephemeral_key):
        eph_raw, nonce, ciphertext = self._make_transfer(alice_identity, ephemeral_key)
        sig = sign_transfer(
            alice_identity.signing_private_key,
            self.FILENAME, eph_raw, nonce, ciphertext,
        )
        assert verify_transfer_signature(
            alice_identity.signing_public_key_pem,
            self.FILENAME, eph_raw, nonce, ciphertext, sig,
        )

    def test_corrupt_signature_rejected(self, alice_identity, ephemeral_key):
        eph_raw, nonce, ciphertext = self._make_transfer(alice_identity, ephemeral_key)
        sig = sign_transfer(
            alice_identity.signing_private_key,
            self.FILENAME, eph_raw, nonce, ciphertext,
        )
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert not verify_transfer_signature(
            alice_identity.signing_public_key_pem,
            self.FILENAME, eph_raw, nonce, ciphertext, bytes(bad_sig),
        )

    def test_filename_substitution_detected(self, alice_identity, ephemeral_key):
        """Changing the filename must invalidate the signature."""
        eph_raw, nonce, ciphertext = self._make_transfer(alice_identity, ephemeral_key)
        sig = sign_transfer(
            alice_identity.signing_private_key,
            self.FILENAME, eph_raw, nonce, ciphertext,
        )
        assert not verify_transfer_signature(
            alice_identity.signing_public_key_pem,
            "malware.exe", eph_raw, nonce, ciphertext, sig,  # different filename
        )

    def test_ciphertext_substitution_detected(self, alice_identity, ephemeral_key):
        """Replacing the ciphertext must invalidate the signature."""
        eph_raw, nonce, ciphertext = self._make_transfer(alice_identity, ephemeral_key)
        sig = sign_transfer(
            alice_identity.signing_private_key,
            self.FILENAME, eph_raw, nonce, ciphertext,
        )
        different_ciphertext = bytes(b ^ 0x01 for b in ciphertext)
        assert not verify_transfer_signature(
            alice_identity.signing_public_key_pem,
            self.FILENAME, eph_raw, nonce, different_ciphertext, sig,
        )

    def test_wrong_public_key_rejected(self, alice_identity, bob_identity, ephemeral_key):
        """Verifying with a different peer's key must fail."""
        eph_raw, nonce, ciphertext = self._make_transfer(alice_identity, ephemeral_key)
        sig = sign_transfer(
            alice_identity.signing_private_key,
            self.FILENAME, eph_raw, nonce, ciphertext,
        )
        assert not verify_transfer_signature(
            bob_identity.signing_public_key_pem,  # wrong key
            self.FILENAME, eph_raw, nonce, ciphertext, sig,
        )


class TestContactsWithEncryptionKey:
    def test_save_and_retrieve_encryption_key(self, alice_identity):
        save_contact(
            peer_id="test-enc-001",
            peer_name="TestPeer",
            public_key=alice_identity.signing_public_key_pem,
            fingerprint=alice_identity.fingerprint,
            trusted=False,
            encryption_key=alice_identity.encryption_public_key_pem,
        )
        c = get_contact("test-enc-001")
        assert c is not None
        assert c["encryption_key"] == alice_identity.encryption_public_key_pem

    def test_encryption_key_preserved_on_update(self, alice_identity):
        save_contact(
            peer_id="test-enc-001",
            peer_name="UpdatedName",
            public_key=alice_identity.signing_public_key_pem,
            fingerprint=alice_identity.fingerprint,
            trusted=False,
            encryption_key=None,  # not providing it on update
        )
        c = get_contact("test-enc-001")
        # Should still have the key from the previous save
        assert c["encryption_key"] == alice_identity.encryption_public_key_pem
