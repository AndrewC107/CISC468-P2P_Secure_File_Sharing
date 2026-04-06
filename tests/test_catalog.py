# tests/test_catalog.py – catalog persistence and alternate-peer lookup (Req 5).

import hashlib
import os

import pytest

import peer.catalog as catalog_mod


def _fresh_catalog():
    """Reset the in-memory catalog between tests."""
    catalog_mod._catalog.clear()


class TestCatalogUpdate:
    def setup_method(self):
        _fresh_catalog()

    def test_stores_file_list(self):
        catalog_mod.update("peer-a", "Alice", [
            {"filename": "photo.jpg", "size": 512, "sha256": "abc123"},
            {"filename": "doc.pdf",   "size": 1024, "sha256": "def456"},
        ])
        assert "peer-a" in catalog_mod._catalog
        assert "photo.jpg" in catalog_mod._catalog["peer-a"]
        assert catalog_mod._catalog["peer-a"]["photo.jpg"]["sha256"] == "abc123"

    def test_overwrites_old_entry_on_update(self):
        catalog_mod.update("peer-a", "Alice", [
            {"filename": "file.txt", "sha256": "old-hash"},
        ])
        catalog_mod.update("peer-a", "Alice", [
            {"filename": "file.txt", "sha256": "new-hash"},
        ])
        assert catalog_mod._catalog["peer-a"]["file.txt"]["sha256"] == "new-hash"

    def test_missing_sha256_stored_as_empty_string(self):
        catalog_mod.update("peer-b", "Bob", [
            {"filename": "legacy.bin", "size": 100},
        ])
        assert catalog_mod._catalog["peer-b"]["legacy.bin"]["sha256"] == ""

    def test_skips_entries_without_filename(self):
        catalog_mod.update("peer-c", "Carol", [
            {"size": 999, "sha256": "should-be-ignored"},
        ])
        assert catalog_mod._catalog.get("peer-c", {}) == {}


class TestGetPeerFiles:
    def setup_method(self):
        _fresh_catalog()

    def test_returns_list_of_dicts_for_peer(self):
        catalog_mod.update("peer-x", "Xavier", [
            {"filename": "a.txt", "size": 1, "sha256": "aa"},
            {"filename": "b.txt", "size": 2, "sha256": "bb"},
        ])
        rows = catalog_mod.get_peer_files("peer-x")
        assert len(rows) == 2
        names = {r["filename"] for r in rows}
        assert names == {"a.txt", "b.txt"}
        for r in rows:
            assert "peer_name" in r and "sha256" in r and "size" in r


class TestGetExpectedHash:
    def setup_method(self):
        _fresh_catalog()
        catalog_mod.update("peer-a", "Alice", [
            {"filename": "secret.txt", "size": 64, "sha256": "feeddeadbeef"},
        ])

    def test_returns_correct_hash(self):
        assert catalog_mod.get_expected_hash("peer-a", "secret.txt") == "feeddeadbeef"

    def test_returns_none_for_unknown_peer(self):
        assert catalog_mod.get_expected_hash("unknown-peer", "secret.txt") is None

    def test_returns_none_for_unknown_file(self):
        assert catalog_mod.get_expected_hash("peer-a", "nonexistent.txt") is None

    def test_returns_none_for_empty_hash(self):
        catalog_mod.update("peer-d", "Dave", [
            {"filename": "nohash.bin", "size": 8, "sha256": ""},
        ])
        assert catalog_mod.get_expected_hash("peer-d", "nohash.bin") is None


class TestFindAlternatePeers:
    def setup_method(self):
        _fresh_catalog()
        catalog_mod.update("alice", "Alice", [
            {"filename": "report.pdf", "sha256": "hash-report"},
            {"filename": "photo.png",  "sha256": "hash-photo"},
        ])
        catalog_mod.update("bob", "Bob", [
            {"filename": "report.pdf", "sha256": "hash-report"},  # same file+hash
            {"filename": "other.txt",  "sha256": "hash-other"},
        ])
        catalog_mod.update("carol", "Carol", [
            {"filename": "report.pdf", "sha256": "DIFFERENT-HASH"},  # same name, wrong hash
        ])

    def test_finds_peer_with_matching_hash(self):
        candidates = catalog_mod.find_alternate_peers(
            filename="report.pdf",
            expected_sha256="hash-report",
            offline_peer_id="alice",
            known_peer_ids=["alice", "bob", "carol"],
        )
        assert "bob" in candidates

    def test_excludes_offline_peer(self):
        candidates = catalog_mod.find_alternate_peers(
            filename="report.pdf",
            expected_sha256="hash-report",
            offline_peer_id="alice",
            known_peer_ids=["alice", "bob"],
        )
        assert "alice" not in candidates

    def test_rejects_wrong_hash(self):
        """carol has 'report.pdf' but with the wrong hash – must NOT be suggested."""
        candidates = catalog_mod.find_alternate_peers(
            filename="report.pdf",
            expected_sha256="hash-report",
            offline_peer_id="alice",
            known_peer_ids=["alice", "bob", "carol"],
        )
        assert "carol" not in candidates

    def test_returns_empty_when_no_alternates(self):
        candidates = catalog_mod.find_alternate_peers(
            filename="photo.png",
            expected_sha256="hash-photo",
            offline_peer_id="alice",
            known_peer_ids=["alice", "bob", "carol"],
        )
        assert candidates == []

    def test_returns_empty_for_completely_unknown_file(self):
        candidates = catalog_mod.find_alternate_peers(
            filename="missing.tar.gz",
            expected_sha256="any-hash",
            offline_peer_id="alice",
            known_peer_ids=["alice", "bob", "carol"],
        )
        assert candidates == []


class TestHashIntegrityInFileReceive:
    """
    These tests exercise the sha256 verification path inside
    PeerClient._receive_encrypted_file() by calling it directly with a
    mock response that has already been "decrypted" to a known plaintext.

    We unit-test the hash-check logic in isolation without a full network
    round-trip, keeping tests fast and deterministic.
    """

    _PLAINTEXT = b"This is the real file content."

    @pytest.fixture
    def encrypted_response_fixture(self):
        """
        Build the crypto material for a FILE_TRANSFER response so that
        _receive_encrypted_file() can fully verify and decrypt it.
        """
        from peer.crypto import (
            LocalIdentity, generate_ephemeral_x25519,
            x25519_public_key_to_raw, ecdh_derive_key,
            aes_gcm_encrypt, sign_transfer,
            load_or_generate_keys,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64

        # ── Receiver (us): long-term X25519 static key ────────────────────────
        receiver_enc_priv = X25519PrivateKey.generate()
        receiver_enc_pub_pem = receiver_enc_priv.public_key().public_bytes(
            encoding=__import__(
                "cryptography.hazmat.primitives.serialization",
                fromlist=["Encoding", "PublicFormat"]
            ).Encoding.PEM,
            format=__import__(
                "cryptography.hazmat.primitives.serialization",
                fromlist=["Encoding", "PublicFormat"]
            ).PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # ── Sender: ephemeral X25519 + Ed25519 signing key ────────────────────
        sender_sign_priv = Ed25519PrivateKey.generate()
        sender_sign_pub  = sender_sign_priv.public_key()
        from cryptography.hazmat.primitives import serialization
        sender_sign_pub_pem = sender_sign_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        eph_priv    = generate_ephemeral_x25519()
        eph_pub_raw = x25519_public_key_to_raw(eph_priv)

        from peer.crypto import x25519_public_raw_from_pem
        receiver_raw_pub = x25519_public_raw_from_pem(receiver_enc_pub_pem)
        aes_key          = ecdh_derive_key(eph_priv, receiver_raw_pub)
        filename         = "testfile.txt"
        nonce, ciphertext = aes_gcm_encrypt(aes_key, self._PLAINTEXT)
        signature        = sign_transfer(
            sender_sign_priv, filename, eph_pub_raw, nonce, ciphertext
        )

        return {
            "sender_sign_pub_pem": sender_sign_pub_pem,
            "receiver_enc_priv":   receiver_enc_priv,
            "eph_pub_raw":         eph_pub_raw,
            "nonce":               nonce,
            "ciphertext":          ciphertext,
            "signature":           signature,
            "filename":            filename,
        }

    def _build_response_message(self, fixture, sender_id="peer-sender"):
        """Construct a fake FILE_TRANSFER Message from the crypto fixture."""
        import base64
        from peer.models import Message
        from peer.protocol import MessageType
        return Message(
            type=MessageType.FILE_TRANSFER,
            sender_id=sender_id,
            sender_name="Sender",
            sender_port=5000,
            payload={
                "filename":             fixture["filename"],
                "encrypted":            True,
                "ephemeral_public_key": base64.b64encode(fixture["eph_pub_raw"]).decode(),
                "nonce":                base64.b64encode(fixture["nonce"]).decode(),
                "ciphertext":           base64.b64encode(fixture["ciphertext"]).decode(),
                "signature":            base64.b64encode(fixture["signature"]).decode(),
                "original_size":        len(self._PLAINTEXT),
            },
        )

    def test_correct_hash_passes_verification(
        self, encrypted_response_fixture, tmp_path, monkeypatch
    ):
        """
        When expected_sha256 matches the plaintext, the file is saved.
        [Requirement 5: hash verification after downloading from alternate source]
        """
        import peer.contacts as cs
        import peer.files as files_mod

        monkeypatch.setattr(files_mod, "DOWNLOADS_DIR", str(tmp_path))
        sender_id = "peer-sender-hash-ok"

        monkeypatch.setattr(cs, "get_contact", lambda pid: {
            "public_key": encrypted_response_fixture["sender_sign_pub_pem"]
        })

        from peer.client import PeerClient
        from peer.models import PeerInfo
        client = PeerClient(
            local_peer=PeerInfo(
                peer_id="me", peer_name="Me", ip="127.0.0.1", port=5000
            ),
            encryption_private_key=encrypted_response_fixture["receiver_enc_priv"],
        )

        expected_sha256 = hashlib.sha256(self._PLAINTEXT).hexdigest()
        response = self._build_response_message(encrypted_response_fixture, sender_id)

        result = client._receive_encrypted_file(
            response,
            encrypted_response_fixture["filename"],
            expected_sha256=expected_sha256,
        )
        assert result is True

    def test_wrong_hash_discards_file(
        self, encrypted_response_fixture, tmp_path, monkeypatch, capsys
    ):
        """
        When expected_sha256 does NOT match the plaintext, the file is
        discarded and a security warning is printed.
        [Requirement 5: integrity check; Requirement 10: security error message]
        """
        import peer.contacts as cs
        import peer.files as files_mod

        monkeypatch.setattr(files_mod, "DOWNLOADS_DIR", str(tmp_path))
        sender_id = "peer-sender-hash-bad"

        monkeypatch.setattr(cs, "get_contact", lambda pid: {
            "public_key": encrypted_response_fixture["sender_sign_pub_pem"]
        })

        from peer.client import PeerClient
        from peer.models import PeerInfo
        client = PeerClient(
            local_peer=PeerInfo(
                peer_id="me", peer_name="Me", ip="127.0.0.1", port=5000
            ),
            encryption_private_key=encrypted_response_fixture["receiver_enc_priv"],
        )

        wrong_sha256 = "a" * 64   # definitely wrong
        response     = self._build_response_message(encrypted_response_fixture, sender_id)

        result = client._receive_encrypted_file(
            response,
            encrypted_response_fixture["filename"],
            expected_sha256=wrong_sha256,
        )
        assert result is False

        captured = capsys.readouterr()
        assert "MISMATCH" in captured.out or "hash" in captured.out.lower()
