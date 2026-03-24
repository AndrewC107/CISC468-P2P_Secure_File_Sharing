# ────────────────────────────────────────────────────────────────────────────
# client.py – Sends NDJSON messages to remote peers over TCP
#
# Public API summary
# ──────────────────
#   send_message(ip, port, msg)           – fire-and-forget; no response read
#   send_hello(ip, port)                  – HELLO → HELLO_ACK; returns ACK msg
#   request_file_list(ip, port)           – FILE_LIST_REQUEST → list of dicts
#   request_file(ip, port, filename)      – FILE_REQUEST → saves downloaded file
# ────────────────────────────────────────────────────────────────────────────

import base64
import json
import logging
import socket
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from peer import contacts as contact_store
from peer import crypto
from peer.config import DOWNLOADS_DIR
from peer.files import ensure_storage_dirs, save_downloaded_file
from peer.models import Message, PeerInfo
from peer.protocol import MessageType, decode_message, encode_message
from peer.utils import recv_line

logger = logging.getLogger(__name__)

# Default timeout for most TCP operations (seconds)
_CONNECT_TIMEOUT = 5

# Longer timeout for file transfers: the remote user has to type y/n to accept
# the request, so we allow up to 30 seconds for the full round-trip.
_FILE_TRANSFER_TIMEOUT = 30


class PeerClient:
    """
    Connects to remote peers and sends NDJSON messages over TCP.

    Constructor
    -----------
    local_peer – this node's PeerInfo, used to fill sender fields in messages

    Public methods
    --------------
    send_message(ip, port, message)   -> bool
    send_hello(ip, port)              -> Message | None   (HELLO_ACK)
    request_file_list(ip, port)       -> list[dict] | None
    request_file(ip, port, filename)  -> bool
    """

    def __init__(
        self,
        local_peer:             PeerInfo,
        encryption_private_key: X25519PrivateKey | None = None,
    ) -> None:
        self.local_peer              = local_peer
        self._encryption_private_key = encryption_private_key

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
        except ConnectionRefusedError:
            logger.error(f"Connection refused by {peer_ip}:{peer_port}")
        except TimeoutError:
            logger.error(f"Connection to {peer_ip}:{peer_port} timed out")
        except OSError as exc:
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

        The `timeout` parameter lets callers use a longer wait for operations
        that require human interaction on the remote side (e.g. FILE_REQUEST,
        where the remote user must type y/n before we get a response).

        Returns the parsed response Message, or None on any error.
        """
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
            print(f"  ✗ Connection refused by {peer_ip}:{peer_port}")
            logger.error(f"Connection refused by {peer_ip}:{peer_port}")
        except TimeoutError:
            print(f"  ✗ Connection to {peer_ip}:{peer_port} timed out")
            logger.error(f"Connection to {peer_ip}:{peer_port} timed out")
        except json.JSONDecodeError as exc:
            print(f"  ✗ Malformed response from {peer_ip}:{peer_port} – {exc}")
            logger.error(f"Malformed JSON from {peer_ip}:{peer_port}: {exc}")
        except ValueError as exc:
            print(f"  ✗ Invalid response from {peer_ip}:{peer_port} – {exc}")
            logger.error(f"Invalid response from {peer_ip}:{peer_port}: {exc}")
        except OSError as exc:
            logger.error(f"Error communicating with {peer_ip}:{peer_port} – {exc}")
        return None

    # ── High-level helpers ────────────────────────────────────────────────────

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

        Sends FILE_LIST_REQUEST and returns a list of file-info dicts on success:
            [{"filename": "photo.jpg", "size": 204800}, ...]

        Returns None if the request failed or the peer sent an unexpected type.
        An empty list is valid – the peer simply has nothing shared.
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
                name = f.get("filename", "?")
                size = f.get("size", 0)
                print(f"      {i}.  {name}  ({_fmt_size(size)})")
        else:
            print(f"  ✓ [{self.local_peer.peer_name}] {response.sender_name} has no shared files.")
        return files

    def request_file(
        self, peer_ip: str, peer_port: int, filename: str
    ) -> bool:
        """
        Ask the remote peer to send a specific file.

        Sends FILE_REQUEST and waits up to 30 seconds for the peer to
        accept/reject the request interactively.

        Encrypted transfer flow (requires prior IDENTITY_EXCHANGE):
          1. Remote peer encrypts the file with AES-256-GCM under a session key
             derived from ECDH(their_ephemeral_X25519_priv, our_X25519_pub).
          2. They sign the transfer with their Ed25519 key.
          3. We receive the FILE_TRANSFER, verify the signature, decrypt, save.

        Returns True if the file was received and saved, False otherwise.
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
        print(f"     (waiting for {peer_ip}:{peer_port} to accept – up to 30 s)")

        response = self._send_and_recv(
            peer_ip, peer_port, request, timeout=_FILE_TRANSFER_TIMEOUT
        )
        if response is None:
            return False

        if response.type == MessageType.FILE_TRANSFER:
            encrypted = response.payload.get("encrypted", False)
            recv_name = response.payload.get("filename", filename)
            if encrypted:
                return self._receive_encrypted_file(response, recv_name)
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
                f"Unexpected response type '{response.type}'"
                f" from {peer_ip}:{peer_port} for FILE_REQUEST"
            )
            return False

    def _receive_encrypted_file(self, response: Message, filename: str) -> bool:
        """
        Decrypt and verify an encrypted FILE_TRANSFER received in response to FILE_REQUEST.

        Security checks (both must pass before the file is saved):
          1. [AUTHENTICATION] Verify the sender's Ed25519 signature using their
             public key from the contact store.
          2. [CONFIDENTIALITY + INTEGRITY] Decrypt with AES-256-GCM.
             The GCM authentication tag detects any ciphertext tampering.

        The session key is derived from:
          ECDH(our_X25519_private_key, sender_ephemeral_X25519_public) + HKDF-SHA256
        This is the ECDH-symmetric counterpart of what the sender computed.

        Returns True if the file was successfully verified, decrypted, and saved.
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
                f"     The authentication tag is invalid – the ciphertext was corrupted"
                f" or tampered with.\n"
                f"     File discarded – NOT saved.\n"
            )
            return False
        except Exception as exc:
            print(f"  ✗ Decryption error for '{filename}': {exc}")
            return False

        # ── Save the plaintext file ────────────────────────────────────────────
        try:
            ensure_storage_dirs()
            dest = Path(DOWNLOADS_DIR) / filename
            dest.write_bytes(plaintext)
            orig_size = response.payload.get("original_size", len(plaintext))
            print(
                f"  ✓ 🔓 '{filename}' decrypted and saved to {dest}"
                f"  ({orig_size:,} bytes)"
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
        Both are required so the remote peer can:
          • Verify our file-transfer signatures (Ed25519 public key)
          • Encrypt files they send to us (X25519 public key)

        Mutual authentication flow (client side):
          1. Build IDENTITY_EXCHANGE with both PEM public keys + fingerprint.
          2. Send it and wait for IDENTITY_ACK from the remote peer.
          3. Extract their public_key, encryption_key, fingerprint from the ACK.
          4. Save both keys in the local contact store (trusted=False).

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

        # Save both of the remote peer's public keys locally
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
            print(f"  ✓ [{self.local_peer.peer_name}] Identity exchanged with {ack.sender_name} ({enc_status})")
            print(f"     Their fingerprint: {fingerprint}")
            print(f"     Contact saved as unverified – use 'Trust a contact' to verify.")
        else:
            print(
                f"  ✓ [{self.local_peer.peer_name}] IDENTITY_ACK from {ack.sender_name}"
                f" (no public key in response)"
            )

        return ack


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
