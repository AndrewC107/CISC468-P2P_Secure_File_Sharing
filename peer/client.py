# ────────────────────────────────────────────────────────────────────────────
# client.py – Sends NDJSON messages to remote peers over TCP
#
# Public API summary
# ──────────────────
#   send_message(ip, port, msg)                         – fire-and-forget
#   send_hello(ip, port)                                – HELLO → HELLO_ACK
#   request_file_list(ip, port)                         – FILE_LIST_REQUEST
#   request_file(ip, port, filename, …)                 – FILE_REQUEST (+ fallback)
#   send_identity_exchange(ip, port)                    – IDENTITY_EXCHANGE
#   send_key_rotation(ip, port, old_identity, new_identity) – KEY_ROTATION
# ────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import hashlib
import json
import logging
import socket
from typing import TYPE_CHECKING, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from peer import catalog
from peer import contacts as contact_store
from peer import crypto
from peer.files import save_downloaded_file, save_downloaded_file_secure
from peer.models import Message, PeerInfo
from peer.protocol import MessageType, decode_message, encode_message
from peer.utils import recv_line

if TYPE_CHECKING:
    from peer.crypto import LocalIdentity
    from peer.storage import StorageKey

logger = logging.getLogger(__name__)

# Default timeout for most TCP operations (seconds)
_CONNECT_TIMEOUT = 5

# Longer timeout for file transfers: the remote user has to type y/n to accept
# the request, so we allow up to 30 seconds for the full round-trip.
_FILE_TRANSFER_TIMEOUT = 30


class PeerClient:
    """
    Connects to remote peers and sends NDJSON messages over TCP.

    Constructor arguments
    ─────────────────────
    local_peer             – this node's PeerInfo, used to fill sender fields
    encryption_private_key – X25519 key for decrypting incoming FILE_TRANSFER
    storage_key            – AES key for encrypting downloaded files at rest (Req 9)
    """

    def __init__(
        self,
        local_peer:             PeerInfo,
        encryption_private_key: X25519PrivateKey | None = None,
        storage_key:            "StorageKey | None" = None,
    ) -> None:
        self.local_peer              = local_peer
        self._encryption_private_key = encryption_private_key
        self._storage_key            = storage_key
        # Set to True by _send_and_recv when a connection error occurs (not a
        # protocol-level rejection).  Used by request_file() to decide whether
        # to try alternate sources.
        self._last_conn_failed       = False

    # ── Key rotation support (Requirement 6) ──────────────────────────────────

    def update_identity(self, new_identity: "LocalIdentity") -> None:
        """
        Hot-swap the client's encryption key after a key rotation.

        Called by main.py immediately after rotate_keys() so new incoming
        FILE_TRANSFER messages can be decrypted with the new X25519 key.
        """
        self._encryption_private_key = new_identity.encryption_private_key

    # ── Low-level helpers ─────────────────────────────────────────────────────

    def send_message(self, peer_ip: str, peer_port: int, message: Message) -> bool:
        """
        Connect, send one NDJSON message, then close (no response read).
        Returns True on success, False on any network error.
        """
        try:
            with socket.create_connection(
                (peer_ip, peer_port), timeout=_CONNECT_TIMEOUT
            ) as sock:
                sock.sendall(encode_message(message))
                logger.info(f"Sent '{message.type}' to {peer_ip}:{peer_port}")
                return True
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            logger.error(f"Error sending to {peer_ip}:{peer_port} – {exc}")
        return False

    def _send_and_recv(
        self,
        peer_ip: str,
        peer_port: int,
        message: Message,
        timeout: int = _CONNECT_TIMEOUT,
    ) -> Message | None:
        """
        Send one message and read back exactly one NDJSON response.

        Sets self._last_conn_failed = True when the failure is a network
        connection error (peer offline) vs. a protocol error.  Callers that
        need to distinguish the two cases (e.g. request_file fallback) can
        inspect this flag after a None return.

        Returns the parsed response Message, or None on any error.
        """
        self._last_conn_failed = False
        try:
            with socket.create_connection(
                (peer_ip, peer_port), timeout=timeout
            ) as sock:
                sock.sendall(encode_message(message))
                raw = recv_line(sock)
                if not raw.strip():
                    logger.warning(f"Empty response from {peer_ip}:{peer_port}")
                    return None
                return decode_message(raw)
        except ConnectionRefusedError:
            self._last_conn_failed = True
            print(f"  ✗ Connection refused by {peer_ip}:{peer_port} (peer may be offline)")
            logger.error(f"Connection refused by {peer_ip}:{peer_port}")
        except TimeoutError:
            self._last_conn_failed = True
            print(f"  ✗ Connection to {peer_ip}:{peer_port} timed out (peer may be offline)")
            logger.error(f"Connection to {peer_ip}:{peer_port} timed out")
        except OSError as exc:
            self._last_conn_failed = True
            print(f"  ✗ Network error reaching {peer_ip}:{peer_port} – {exc}")
            logger.error(f"OSError communicating with {peer_ip}:{peer_port} – {exc}")
        except json.JSONDecodeError as exc:
            print(f"  ✗ Malformed response from {peer_ip}:{peer_port} – {exc}")
            logger.error(f"Malformed JSON from {peer_ip}:{peer_port}: {exc}")
        except ValueError as exc:
            print(f"  ✗ Invalid response from {peer_ip}:{peer_port} – {exc}")
            logger.error(f"Invalid response from {peer_ip}:{peer_port}: {exc}")
        return None

    # ── High-level methods ────────────────────────────────────────────────────

    def send_hello(self, peer_ip: str, peer_port: int) -> Message | None:
        """
        Send HELLO and wait for HELLO_ACK.

        Returns the HELLO_ACK Message so the caller can extract the remote
        peer's identity and register them in the discovery table.
        Returns None if anything goes wrong.
        """
        message = Message(
            type=MessageType.HELLO,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={},
        )
        print(f"  → [{self.local_peer.peer_name}] Sending HELLO to {peer_ip}:{peer_port}")
        ack = self._send_and_recv(peer_ip, peer_port, message)
        if ack is not None and ack.type == MessageType.HELLO_ACK:
            print(f"  ✓ [{self.local_peer.peer_name}] HELLO_ACK received from {ack.sender_name}")
            return ack
        return None

    def request_file_list(
        self, peer_ip: str, peer_port: int
    ) -> list[dict] | None:
        """
        Ask the remote peer for their shared file list.

        Now includes sha256 fields when the remote peer supports them
        (Requirement 5).  The caller should update the catalog after this
        call so offline fallback can use the hash data.

        Returns a list of file-info dicts, or None on failure.
        """
        request = Message(
            type=MessageType.FILE_LIST_REQUEST,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={},
        )
        print(
            f"  → [{self.local_peer.peer_name}] Requesting file list"
            f" from {peer_ip}:{peer_port}"
        )
        response = self._send_and_recv(peer_ip, peer_port, request)
        if response is None:
            return None

        if response.type != MessageType.FILE_LIST_RESPONSE:
            logger.warning(
                f"Expected FILE_LIST_RESPONSE but got '{response.type}'"
                f" from {peer_ip}:{peer_port}"
            )
            return None

        files: list[dict] = response.payload.get("files", [])
        if files:
            print(f"  ✓ [{self.local_peer.peer_name}] {len(files)} file(s) shared by {response.sender_name}:")
            for i, f in enumerate(files, start=1):
                name   = f.get("filename", "?")
                size   = f.get("size", 0)
                sha256 = f.get("sha256", "")
                hash_part = f"  sha256:{sha256[:12]}…" if sha256 else ""
                print(f"      {i}.  {name}  ({_fmt_size(size)}){hash_part}")
        else:
            print(f"  ✓ [{self.local_peer.peer_name}] {response.sender_name} has no shared files.")
        return files

    def request_file(
        self,
        peer_ip:          str,
        peer_port:        int,
        filename:         str,
        expected_sha256:  str | None = None,
        original_peer_id: str | None = None,
        get_peers:        Callable[[], dict] | None = None,
    ) -> bool:
        """
        Ask the remote peer to send a specific file.

        Waits up to 30 seconds for the peer to accept/reject interactively.

        Offline fallback (Requirement 5)
        ──────────────────────────────────
        If expected_sha256, original_peer_id, and get_peers are provided AND
        the connection fails (peer offline), this method:
          1. Searches the file catalog for alternate peers with the same
             filename + sha256.
          2. Prompts the user to confirm the fallback attempt.
          3. Requests the file from each alternate in turn.
          4. After decryption, verifies sha256(plaintext) == expected_sha256.
             If the hash mismatches, the file is discarded and a security
             warning is shown (Requirement 10).

        Returns True if the file was received, verified, and saved.
        """
        request = Message(
            type=MessageType.FILE_REQUEST,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={"filename": filename},
        )
        print(
            f"  → [{self.local_peer.peer_name}] Requesting '{filename}'"
            f" from {peer_ip}:{peer_port}…"
        )
        print(f"     (waiting up to 30 s for the peer to accept)")

        response = self._send_and_recv(
            peer_ip, peer_port, request, timeout=_FILE_TRANSFER_TIMEOUT
        )

        if response is None:
            if self._last_conn_failed and expected_sha256 and original_peer_id and get_peers:
                return self._try_alternate_sources(
                    filename, expected_sha256, original_peer_id, get_peers
                )
            return False

        return self._process_file_transfer_response(response, filename, expected_sha256)

    def _process_file_transfer_response(
        self,
        response:        Message,
        filename:        str,
        expected_sha256: str | None = None,
    ) -> bool:
        """Process a FILE_TRANSFER or FILE_REJECTED response."""
        if response.type == MessageType.FILE_TRANSFER:
            encrypted = response.payload.get("encrypted", False)
            recv_name = response.payload.get("filename", filename)
            if encrypted:
                return self._receive_encrypted_file(response, recv_name, expected_sha256)
            else:
                # Legacy plaintext path
                b64_data = response.payload.get("data", "")
                try:
                    saved_path = save_downloaded_file(recv_name, b64_data)
                    print(f"  ✓ '{recv_name}' saved to {saved_path}")
                    return True
                except Exception as exc:
                    print(f"  ✗ Failed to save '{recv_name}': {exc}")
                    return False

        elif response.type == MessageType.FILE_REJECTED:
            reason = response.payload.get("reason", "declined")
            print(f"  ✗ {response.sender_name} declined to send '{filename}': {reason}")
            return False

        else:
            logger.warning(
                f"Unexpected response type '{response.type}' for FILE_REQUEST"
            )
            return False

    def _try_alternate_sources(
        self,
        filename:         str,
        expected_sha256:  str,
        original_peer_id: str,
        get_peers:        Callable[[], dict],
    ) -> bool:
        """
        Try to download a file from alternate peers when the primary is offline.

        Requirement 5: "If peer A is offline but peer B already had peer A's
        file list, peer B may find another peer C that had previously downloaded
        the file from peer A and request the file from them instead."

        Integrity is enforced by comparing sha256(plaintext) to the hash
        originally advertised by the offline peer.
        """
        peers_dict = get_peers()  # {peer_id: PeerInfo}
        known_ids  = list(peers_dict.keys())

        candidates = catalog.find_alternate_peers(
            filename, expected_sha256, original_peer_id, known_ids
        )

        if not candidates:
            print(
                f"  ✗ No alternate sources found for '{filename}'.\n"
                f"     No other known peer has advertised this file with the same hash."
            )
            return False

        peer_names = [
            peers_dict[pid].peer_name
            for pid in candidates
            if pid in peers_dict
        ]
        print(
            f"\n  ↻  Primary peer is offline.  Alternate source(s) found:\n"
            f"     {', '.join(peer_names)}\n"
            f"     The downloaded file will be verified against the original hash."
        )
        confirm = input("  Try alternate source? (y/n): ").strip().lower()
        if confirm != "y":
            print("  Fallback cancelled.")
            return False

        for alt_peer_id in candidates:
            alt_peer = peers_dict.get(alt_peer_id)
            if alt_peer is None:
                continue

            print(f"\n  → Trying alternate source: {alt_peer.peer_name} @ {alt_peer.ip}:{alt_peer.port}")
            request = Message(
                type=MessageType.FILE_REQUEST,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename},
            )
            print(f"     (waiting up to 30 s for {alt_peer.peer_name} to accept)")
            response = self._send_and_recv(
                alt_peer.ip, alt_peer.port, request, timeout=_FILE_TRANSFER_TIMEOUT
            )
            if response is None:
                continue  # that alternate is also unreachable – try next

            success = self._process_file_transfer_response(
                response, filename, expected_sha256
            )
            if success:
                return True
            # If the transfer itself was rejected or hash-failed, try next alternate.

        print(f"  ✗ All alternate sources failed for '{filename}'.")
        return False

    def _receive_encrypted_file(
        self,
        response:        Message,
        filename:        str,
        expected_sha256: str | None = None,
    ) -> bool:
        """
        Decrypt and verify an encrypted FILE_TRANSFER.

        Security checks:
          1. [AUTHENTICATION] Verify Ed25519 signature using contact's stored key.
          2. [CONFIDENTIALITY + INTEGRITY] Decrypt with AES-256-GCM.
          3. [INTEGRITY – alternate source] Compare sha256(plaintext) to the hash
             originally advertised by the intended peer (Requirement 5).

        Returns True only if all checks pass and the file is saved.
        """
        sender_id = response.sender_id

        if self._encryption_private_key is None:
            print(f"  ✗ Cannot decrypt '{filename}' – client has no encryption key.")
            return False

        # ── Decode base64 fields ───────────────────────────────────────────────
        try:
            eph_pub_raw = base64.b64decode(response.payload["ephemeral_public_key"])
            nonce       = base64.b64decode(response.payload["nonce"])
            ciphertext  = base64.b64decode(response.payload["ciphertext"])
            signature   = base64.b64decode(response.payload["signature"])
        except (KeyError, Exception) as exc:
            print(f"  ✗ Malformed encrypted FILE_TRANSFER for '{filename}': {exc}")
            return False

        # ── [AUTHENTICATION] Verify Ed25519 signature ─────────────────────────
        contact = contact_store.get_contact(sender_id)
        if not contact or not contact.get("public_key"):
            print(
                f"  ✗ SECURITY: Cannot verify '{filename}' from {response.sender_name}"
                f" – their signing key is not in your contacts.\n"
                f"     Use menu option 6 (Exchange identity) with this peer first."
            )
            return False

        sig_ok = crypto.verify_transfer_signature(
            contact["public_key"], filename, eph_pub_raw, nonce, ciphertext, signature
        )
        if not sig_ok:
            print(
                f"\n  ✗ SECURITY WARNING: Signature verification FAILED for '{filename}'"
                f" from {response.sender_name}.\n"
                f"     The file may have been tampered with or sent by an impostor.\n"
                f"     File discarded – NOT saved.\n"
            )
            return False

        print(f"  ✓ Signature verified for '{filename}' (sender: {response.sender_name})")

        # ── [CONFIDENTIALITY] Derive session key and decrypt ──────────────────
        try:
            aes_key   = crypto.ecdh_derive_key(self._encryption_private_key, eph_pub_raw)
            plaintext = crypto.aes_gcm_decrypt(aes_key, nonce, ciphertext)
        except InvalidTag:
            print(
                f"\n  ✗ SECURITY WARNING: Integrity check FAILED for '{filename}'"
                f" from {response.sender_name}.\n"
                f"     The authentication tag is invalid – data was corrupted or tampered.\n"
                f"     File discarded – NOT saved.\n"
            )
            return False
        except Exception as exc:
            print(f"  ✗ Decryption error for '{filename}': {exc}")
            return False

        # ── [INTEGRITY – alternate source] Hash verification (Requirement 5) ──
        if expected_sha256:
            actual_sha256 = hashlib.sha256(plaintext).hexdigest()
            if actual_sha256 != expected_sha256:
                print(
                    f"\n  ✗ SECURITY WARNING: Content hash MISMATCH for '{filename}'.\n"
                    f"     Expected : {expected_sha256}\n"
                    f"     Received : {actual_sha256}\n"
                    f"     The file from this alternate source differs from what the"
                    f" original peer advertised.\n"
                    f"     File discarded – NOT saved.\n"
                )
                return False
            print(f"  ✓ Content hash verified (matches original peer's advertised hash)")

        # ── Save (encrypted at rest if storage_key is set) ────────────────────
        try:
            dest     = save_downloaded_file_secure(filename, plaintext, self._storage_key)
            at_rest  = " (encrypted at rest)" if self._storage_key else ""
            orig_size = response.payload.get("original_size", len(plaintext))
            print(
                f"  ✓ '{filename}' decrypted and saved to {dest}"
                f"  ({orig_size:,} bytes){at_rest}"
            )
            return True
        except OSError as exc:
            print(f"  ✗ Failed to save '{filename}': {exc}")
            return False

    def send_identity_exchange(
        self, peer_ip: str, peer_port: int
    ) -> Message | None:
        """
        Send our IDENTITY_EXCHANGE to a peer and wait for their IDENTITY_ACK.

        Sends both our Ed25519 signing key and X25519 encryption key.
        Both are required so the remote peer can verify signatures and encrypt
        files destined for us.

        Returns the IDENTITY_ACK Message, or None if the exchange failed.
        """
        request = Message(
            type=MessageType.IDENTITY_EXCHANGE,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={
                "peer_id":        self.local_peer.peer_id,
                "peer_name":      self.local_peer.peer_name,
                "public_key":     self.local_peer.public_key     or "",
                "encryption_key": self.local_peer.encryption_key or "",
                "fingerprint":    self.local_peer.fingerprint    or "",
            },
        )
        print(
            f"  → [{self.local_peer.peer_name}]"
            f" Sending IDENTITY_EXCHANGE to {peer_ip}:{peer_port}"
        )
        ack = self._send_and_recv(peer_ip, peer_port, request)

        if ack is None or ack.type != MessageType.IDENTITY_ACK:
            print(f"  ✗ No IDENTITY_ACK received from {peer_ip}:{peer_port}")
            return None

        pub_key        = ack.payload.get("public_key", "")
        encryption_key = ack.payload.get("encryption_key", "")
        fingerprint    = ack.payload.get("fingerprint", "")

        if pub_key and fingerprint:
            contact_store.save_contact(
                peer_id=ack.sender_id,
                peer_name=ack.sender_name,
                public_key=pub_key,
                fingerprint=fingerprint,
                trusted=False,
                encryption_key=encryption_key or None,
            )
            enc_status = "with encryption key" if encryption_key else "signing key only"
            print(f"  ✓ Identity exchanged with {ack.sender_name} ({enc_status})")
            print(f"     Their fingerprint: {fingerprint}")
            print(f"     Contact saved as unverified – use 'Trust a contact' to verify.")
        else:
            print(f"  ✓ IDENTITY_ACK from {ack.sender_name} (no public key in response)")

        return ack

    def send_key_rotation(
        self,
        peer_ip:      str,
        peer_port:    int,
        old_identity: "LocalIdentity",
        new_identity: "LocalIdentity",
    ) -> bool:
        """
        Notify a peer that our keys have changed (Requirement 6).

        Builds a KEY_ROTATION message signed with the OLD private key so the
        receiver can verify the rotation is authorised.  No response is expected
        (fire-and-forget so the notification is best-effort).

        Parameters
        ──────────
        old_identity – identity BEFORE rotation (used to sign the message)
        new_identity – identity AFTER rotation (new keys to announce)

        Returns True if the message was sent successfully (TCP delivery only;
        the remote peer may still reject it if verification fails).
        """
        signature = crypto.sign_key_rotation(
            old_identity.signing_private_key,
            old_identity.fingerprint,
            new_identity.signing_public_key_pem,
            new_identity.encryption_public_key_pem,
            new_identity.fingerprint,
        )

        message = Message(
            type=MessageType.KEY_ROTATION,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={
                "old_fingerprint":    old_identity.fingerprint,
                "new_public_key":     new_identity.signing_public_key_pem,
                "new_encryption_key": new_identity.encryption_public_key_pem,
                "new_fingerprint":    new_identity.fingerprint,
                "signature":          base64.b64encode(signature).decode("ascii"),
            },
        )
        return self.send_message(peer_ip, peer_port, message)


# ── Formatting helper ─────────────────────────────────────────────────────────

def _fmt_size(size_bytes: int) -> str:
    """Return a human-readable file size string (e.g. '1.4 KB', '3.2 MB')."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.1f} GB"
