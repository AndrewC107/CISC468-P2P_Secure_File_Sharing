# ─────────────────────────────────────────────────────────────────────────────
# client.py – Outbound TCP NDJSON (matches java-client PeerClient)
# ─────────────────────────────────────────────────────────────────────────────

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

_CONNECT_TIMEOUT = 5
_FILE_TRANSFER_TIMEOUT = 30


class PeerClient:
    """TCP client for protocol messages; holds local_peer and keys for decrypt/save."""

    def __init__(
        self,
        local_peer:             PeerInfo,
        encryption_private_key: X25519PrivateKey | None = None,
        storage_key:            "StorageKey | None" = None,
    ) -> None:
        self.local_peer              = local_peer
        self._encryption_private_key = encryption_private_key
        self._storage_key            = storage_key
        self._last_conn_failed       = False

    def update_identity(self, new_identity: "LocalIdentity") -> None:
        """Replace the X25519 decryption key after local key rotation."""
        self._encryption_private_key = new_identity.encryption_private_key

    def send_message(self, peer_ip: str, peer_port: int, message: Message) -> bool:
        """Send one message without reading a reply; returns False on socket errors."""
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
        """Send one line and read one reply; sets _last_conn_failed on transport errors."""
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

    def send_hello(self, peer_ip: str, peer_port: int) -> Message | None:
        """HELLO / HELLO_ACK exchange; returns ack or None."""
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
        """FILE_LIST_REQUEST / RESPONSE; returns file dicts or None."""
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
        """FILE_REQUEST flow; on transport failure may prompt and try catalog alternate peers."""
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
        """Handle FILE_TRANSFER (plain or encrypted) or FILE_REJECTED."""
        if response.type == MessageType.FILE_TRANSFER:
            encrypted = response.payload.get("encrypted", False)
            recv_name = response.payload.get("filename", filename)
            if encrypted:
                return self._receive_encrypted_file(response, recv_name, expected_sha256)
            else:
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
        """Ask other catalog peers for the same file+hash when the primary is unreachable."""
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
                continue

            success = self._process_file_transfer_response(
                response, filename, expected_sha256
            )
            if success:
                return True

        print(f"  ✗ All alternate sources failed for '{filename}'.")
        return False

    def _receive_encrypted_file(
        self,
        response:        Message,
        filename:        str,
        expected_sha256: str | None = None,
    ) -> bool:
        """Verify signature, decrypt GCM payload, optional sha256 check, then save download."""
        sender_id = response.sender_id

        if self._encryption_private_key is None:
            print(f"  ✗ Cannot decrypt '{filename}' – client has no encryption key.")
            return False

        try:
            eph_pub_raw = base64.b64decode(response.payload["ephemeral_public_key"])
            nonce       = base64.b64decode(response.payload["nonce"])
            ciphertext  = base64.b64decode(response.payload["ciphertext"])
            signature   = base64.b64decode(response.payload["signature"])
        except (KeyError, Exception) as exc:
            print(f"  ✗ Malformed encrypted FILE_TRANSFER for '{filename}': {exc}")
            return False

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
        """Send IDENTITY_EXCHANGE, save peer from IDENTITY_ACK, return ack or None."""
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
        """Fire-and-forget signed KEY_ROTATION to one address; returns TCP send success."""
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


def _fmt_size(size_bytes: int) -> str:
    """Human-readable byte size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.1f} GB"
