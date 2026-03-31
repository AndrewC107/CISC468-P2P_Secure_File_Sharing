"""
tests/test_key_rotation.py – Unit tests for key migration (Requirement 6)

Covers:
  • sign_key_rotation() produces a verifiable signature
  • verify_key_rotation() returns True for a valid rotation signature
  • verify_key_rotation() returns False when the signature is corrupted
  • verify_key_rotation() returns False when the wrong old key is used to verify
  • verify_key_rotation() returns False when any payload field is substituted
  • rotate_keys() generates distinct keys from the old identity
  • contacts.get_contact_by_fingerprint() lookup succeeds / fails correctly
  • contacts.update_contact_keys() replaces keys correctly
  • End-to-end: server._handle_key_rotation() updates contact on valid rotation
  • End-to-end: server._handle_key_rotation() rejects invalid rotation
"""

import base64
import json
import os
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from peer.crypto import (
    sign_key_rotation,
    verify_key_rotation,
    compute_fingerprint,
    format_fingerprint_for_display,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _gen_ed25519_pem() -> tuple[Ed25519PrivateKey, str]:
    """Return (private_key, public_key_pem)."""
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv, pub_pem


def _gen_x25519_pem() -> tuple[X25519PrivateKey, str]:
    """Return (private_key, public_key_pem)."""
    priv = X25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv, pub_pem


@pytest.fixture
def old_signing_priv(tmp_path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def old_signing_pub_pem(old_signing_priv) -> str:
    return old_signing_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


@pytest.fixture
def old_fingerprint(old_signing_pub_pem) -> str:
    return compute_fingerprint(old_signing_pub_pem)


@pytest.fixture
def new_signing_pub_pem() -> str:
    _, pem = _gen_ed25519_pem()
    return pem


@pytest.fixture
def new_enc_pub_pem() -> str:
    _, pem = _gen_x25519_pem()
    return pem


@pytest.fixture
def new_fingerprint(new_signing_pub_pem) -> str:
    return compute_fingerprint(new_signing_pub_pem)


# ── sign_key_rotation / verify_key_rotation ───────────────────────────────────

class TestSignAndVerifyKeyRotation:
    def test_valid_signature_verifies(
        self,
        old_signing_priv, old_signing_pub_pem, old_fingerprint,
        new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
    ):
        """
        A signature produced with the old private key must verify with the
        corresponding old public key.
        """
        sig = sign_key_rotation(
            old_signing_priv,
            old_fingerprint,
            new_signing_pub_pem,
            new_enc_pub_pem,
            new_fingerprint,
        )
        assert verify_key_rotation(
            old_signing_pub_pem,
            old_fingerprint,
            new_signing_pub_pem,
            new_enc_pub_pem,
            new_fingerprint,
            sig,
        ) is True

    def test_corrupted_signature_fails(
        self,
        old_signing_priv, old_signing_pub_pem, old_fingerprint,
        new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
    ):
        """Flipping a bit in the signature must cause verification to fail."""
        sig = sign_key_rotation(
            old_signing_priv, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
        )
        bad_sig = bytearray(sig)
        bad_sig[10] ^= 0xFF
        assert verify_key_rotation(
            old_signing_pub_pem, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
            bytes(bad_sig),
        ) is False

    def test_wrong_old_public_key_fails(
        self,
        old_signing_priv, old_fingerprint,
        new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
    ):
        """Verification with an unrelated public key must fail."""
        _, unrelated_pub_pem = _gen_ed25519_pem()
        sig = sign_key_rotation(
            old_signing_priv, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
        )
        assert verify_key_rotation(
            unrelated_pub_pem, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
            sig,
        ) is False

    def test_substituted_new_key_fails(
        self,
        old_signing_priv, old_signing_pub_pem, old_fingerprint,
        new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
    ):
        """Signing with one new_public_key but verifying with another must fail."""
        sig = sign_key_rotation(
            old_signing_priv, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
        )
        _, substitute_pub = _gen_ed25519_pem()
        assert verify_key_rotation(
            old_signing_pub_pem, old_fingerprint,
            substitute_pub, new_enc_pub_pem, new_fingerprint,
            sig,
        ) is False

    def test_substituted_old_fingerprint_fails(
        self,
        old_signing_priv, old_signing_pub_pem, old_fingerprint,
        new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
    ):
        """The old_fingerprint is part of the signed payload; swapping it fails."""
        sig = sign_key_rotation(
            old_signing_priv, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
        )
        assert verify_key_rotation(
            old_signing_pub_pem,
            "AB:CD:EF:00:11:22:33:44",   # wrong fingerprint
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
            sig,
        ) is False

    def test_signature_is_64_bytes(
        self,
        old_signing_priv, old_fingerprint,
        new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
    ):
        """Ed25519 signatures are always exactly 64 bytes."""
        sig = sign_key_rotation(
            old_signing_priv, old_fingerprint,
            new_signing_pub_pem, new_enc_pub_pem, new_fingerprint,
        )
        assert len(sig) == 64


# ── rotate_keys() ─────────────────────────────────────────────────────────────

class TestRotateKeys:
    def test_new_identity_has_different_fingerprint(self, tmp_path, monkeypatch):
        """
        rotate_keys() must generate a new key pair with a different fingerprint.
        [Requirement 6: migrate to a new key]
        """
        import peer.crypto as crypto_mod

        # Point key files at tmp_path so we don't touch identity/
        monkeypatch.setattr(crypto_mod, "_IDENTITY_DIR",         tmp_path)
        monkeypatch.setattr(crypto_mod, "_ED25519_PRIVATE_FILE", tmp_path / "pk.pem")
        monkeypatch.setattr(crypto_mod, "_ED25519_PUBLIC_FILE",  tmp_path / "pub.pem")
        monkeypatch.setattr(crypto_mod, "_X25519_PRIVATE_FILE",  tmp_path / "x_pk.pem")
        monkeypatch.setattr(crypto_mod, "_X25519_PUBLIC_FILE",   tmp_path / "x_pub.pem")

        old_identity = crypto_mod.load_or_generate_keys()
        new_identity = crypto_mod.rotate_keys(old_identity)

        assert new_identity.fingerprint != old_identity.fingerprint

    def test_new_identity_has_different_signing_key(self, tmp_path, monkeypatch):
        import peer.crypto as crypto_mod

        monkeypatch.setattr(crypto_mod, "_IDENTITY_DIR",         tmp_path)
        monkeypatch.setattr(crypto_mod, "_ED25519_PRIVATE_FILE", tmp_path / "pk.pem")
        monkeypatch.setattr(crypto_mod, "_ED25519_PUBLIC_FILE",  tmp_path / "pub.pem")
        monkeypatch.setattr(crypto_mod, "_X25519_PRIVATE_FILE",  tmp_path / "x_pk.pem")
        monkeypatch.setattr(crypto_mod, "_X25519_PUBLIC_FILE",   tmp_path / "x_pub.pem")

        old_identity = crypto_mod.load_or_generate_keys()
        new_identity = crypto_mod.rotate_keys(old_identity)

        assert (new_identity.signing_public_key_pem
                != old_identity.signing_public_key_pem)

    def test_rotation_signature_is_verifiable(self, tmp_path, monkeypatch):
        """
        A KEY_ROTATION message built with old signing key and new key material
        must verify correctly.
        """
        import peer.crypto as crypto_mod

        monkeypatch.setattr(crypto_mod, "_IDENTITY_DIR",         tmp_path)
        monkeypatch.setattr(crypto_mod, "_ED25519_PRIVATE_FILE", tmp_path / "pk.pem")
        monkeypatch.setattr(crypto_mod, "_ED25519_PUBLIC_FILE",  tmp_path / "pub.pem")
        monkeypatch.setattr(crypto_mod, "_X25519_PRIVATE_FILE",  tmp_path / "x_pk.pem")
        monkeypatch.setattr(crypto_mod, "_X25519_PUBLIC_FILE",   tmp_path / "x_pub.pem")

        old_identity = crypto_mod.load_or_generate_keys()
        new_identity = crypto_mod.rotate_keys(old_identity)

        sig = sign_key_rotation(
            old_identity.signing_private_key,
            old_identity.fingerprint,
            new_identity.signing_public_key_pem,
            new_identity.encryption_public_key_pem,
            new_identity.fingerprint,
        )
        assert verify_key_rotation(
            old_identity.signing_public_key_pem,
            old_identity.fingerprint,
            new_identity.signing_public_key_pem,
            new_identity.encryption_public_key_pem,
            new_identity.fingerprint,
            sig,
        ) is True


# ── contacts helpers ──────────────────────────────────────────────────────────

class TestContactsKeyRotationHelpers:
    def test_get_contact_by_fingerprint_found(self, tmp_path, monkeypatch):
        import peer.contacts as cs

        monkeypatch.setattr(cs, "_CONTACTS_DIR",  tmp_path)
        monkeypatch.setattr(cs, "_CONTACTS_FILE", tmp_path / "contacts.json")

        cs.save_contact(
            peer_id="p1", peer_name="Alice",
            public_key="PEM-A", fingerprint="FP:AA:BB",
        )
        result = cs.get_contact_by_fingerprint("FP:AA:BB")
        assert result is not None
        assert result["peer_name"] == "Alice"

    def test_get_contact_by_fingerprint_not_found(self, tmp_path, monkeypatch):
        import peer.contacts as cs

        monkeypatch.setattr(cs, "_CONTACTS_DIR",  tmp_path)
        monkeypatch.setattr(cs, "_CONTACTS_FILE", tmp_path / "contacts.json")

        assert cs.get_contact_by_fingerprint("NO:SUCH:FINGERPRINT") is None

    def test_update_contact_keys_replaces_keys(self, tmp_path, monkeypatch):
        import peer.contacts as cs

        monkeypatch.setattr(cs, "_CONTACTS_DIR",  tmp_path)
        monkeypatch.setattr(cs, "_CONTACTS_FILE", tmp_path / "contacts.json")

        cs.save_contact(
            peer_id="p2", peer_name="Bob",
            public_key="OLD-PEM", fingerprint="OLD:FP", trusted=True,
        )
        updated = cs.update_contact_keys("p2", "NEW-PEM", "NEW-ENC", "NEW:FP")
        assert updated is True

        c = cs.get_contact("p2")
        assert c["public_key"]     == "NEW-PEM"
        assert c["encryption_key"] == "NEW-ENC"
        assert c["fingerprint"]    == "NEW:FP"
        # trusted status should be preserved
        assert c["trusted"] is True

    def test_update_contact_keys_unknown_peer_returns_false(self, tmp_path, monkeypatch):
        import peer.contacts as cs

        monkeypatch.setattr(cs, "_CONTACTS_DIR",  tmp_path)
        monkeypatch.setattr(cs, "_CONTACTS_FILE", tmp_path / "contacts.json")

        result = cs.update_contact_keys("ghost", "K", "E", "F")
        assert result is False


# ── Server-level integration: _handle_key_rotation ────────────────────────────

class TestServerHandleKeyRotation:
    """
    Test the server's KEY_ROTATION handler directly without network I/O.
    """

    def _make_server(self, tmp_path, monkeypatch):
        import peer.contacts as cs
        from peer.server import PeerServer
        from peer.models import PeerInfo
        import queue

        monkeypatch.setattr(cs, "_CONTACTS_DIR",  tmp_path)
        monkeypatch.setattr(cs, "_CONTACTS_FILE", tmp_path / "contacts.json")

        local_peer = PeerInfo(
            peer_id="local", peer_name="Local", ip="127.0.0.1", port=5000
        )
        server = PeerServer(
            host="0.0.0.0", port=5999,
            local_peer=local_peer,
            consent_queue=queue.Queue(),
        )
        return server

    def test_valid_rotation_updates_contact(self, tmp_path, monkeypatch):
        import peer.contacts as cs

        server = self._make_server(tmp_path, monkeypatch)

        # Create the old identity inline
        old_priv, old_pub_pem = _gen_ed25519_pem()
        old_fp                = compute_fingerprint(old_pub_pem)
        _, new_pub_pem        = _gen_ed25519_pem()
        _, new_enc_pem        = _gen_x25519_pem()
        new_fp                = compute_fingerprint(new_pub_pem)

        # Save the old contact in the store
        cs.save_contact(
            peer_id="remote-peer", peer_name="Remote",
            public_key=old_pub_pem, fingerprint=old_fp,
        )

        sig = sign_key_rotation(old_priv, old_fp, new_pub_pem, new_enc_pem, new_fp)

        from peer.models import Message
        from peer.protocol import MessageType
        msg = Message(
            type=MessageType.KEY_ROTATION,
            sender_id="remote-peer",
            sender_name="Remote",
            sender_port=5100,
            payload={
                "old_fingerprint":    old_fp,
                "new_public_key":     new_pub_pem,
                "new_encryption_key": new_enc_pem,
                "new_fingerprint":    new_fp,
                "signature":          base64.b64encode(sig).decode("ascii"),
            },
        )
        server._handle_key_rotation(msg)

        updated = cs.get_contact("remote-peer")
        assert updated["fingerprint"]    == new_fp
        assert updated["public_key"]     == new_pub_pem
        assert updated["encryption_key"] == new_enc_pem

    def test_invalid_signature_does_not_update_contact(self, tmp_path, monkeypatch):
        import peer.contacts as cs

        server = self._make_server(tmp_path, monkeypatch)

        old_priv, old_pub_pem = _gen_ed25519_pem()
        old_fp                = compute_fingerprint(old_pub_pem)
        _, new_pub_pem        = _gen_ed25519_pem()
        _, new_enc_pem        = _gen_x25519_pem()
        new_fp                = compute_fingerprint(new_pub_pem)

        cs.save_contact(
            peer_id="target", peer_name="Target",
            public_key=old_pub_pem, fingerprint=old_fp,
        )

        bad_sig = b"\x00" * 64  # invalid signature

        from peer.models import Message
        from peer.protocol import MessageType
        msg = Message(
            type=MessageType.KEY_ROTATION,
            sender_id="target",
            sender_name="Target",
            sender_port=5100,
            payload={
                "old_fingerprint":    old_fp,
                "new_public_key":     new_pub_pem,
                "new_encryption_key": new_enc_pem,
                "new_fingerprint":    new_fp,
                "signature":          base64.b64encode(bad_sig).decode("ascii"),
            },
        )
        server._handle_key_rotation(msg)

        # Contact must NOT be updated
        unchanged = cs.get_contact("target")
        assert unchanged["fingerprint"] == old_fp
        assert unchanged["public_key"]  == old_pub_pem
