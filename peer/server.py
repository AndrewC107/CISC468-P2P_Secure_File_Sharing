# ─────────────────────────────────────────────────────────────────────────────
# server.py – Inbound TCP NDJSON (matches java-client PeerServer)
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import json
import logging
import queue
import socket
import threading
from typing import TYPE_CHECKING, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from peer import contacts as contact_store
from peer import crypto
from peer.files import (
    list_shared_files,
    read_shared_file_bytes,
    save_downloaded_file,
    save_downloaded_file_secure,
)
from peer.models import Message, PeerInfo
from peer.protocol import MessageType, decode_message, encode_message
from peer.utils import recv_line

if TYPE_CHECKING:
    from peer.storage import StorageKey

logger = logging.getLogger(__name__)


class PendingConsentRequest:
    """FILE_REQUEST consent: worker waits on an Event; main thread calls resolve()."""

    def __init__(
        self,
        peer_name: str,
        peer_id:   str,
        peer_ip:   str,
        peer_port: int,
        filename:  str,
    ) -> None:
        self.peer_name = peer_name
        self.peer_id   = peer_id
        self.peer_ip   = peer_ip
        self.peer_port = peer_port
        self.filename  = filename

        self._accepted    = False
        self._event       = threading.Event()
        self._timed_out   = False

    @property
    def timed_out(self) -> bool:
        """True if the server gave up waiting before the user answered."""
        return self._timed_out

    def resolve(self, accepted: bool) -> None:
        """Unblock wait_for_decision with the user's choice."""
        self._accepted = accepted
        self._event.set()

    def wait_for_decision(self, timeout: float = 25.0) -> bool:
        """Block until resolve() or timeout; returns whether the user accepted."""
        fired = self._event.wait(timeout=timeout)
        if not fired:
            self._timed_out = True
        return self._accepted


class PeerServer:
    """Listen for one NDJSON message per connection, dispatch, optional reply."""

    def __init__(
        self,
        host: str,
        port: int,
        local_peer: PeerInfo,
        consent_queue:       queue.Queue | None = None,
        notification_queue:  queue.Queue | None = None,
        on_message: Callable[[Message, tuple[str, int]], None] | None = None,
        signing_private_key:    Ed25519PrivateKey | None = None,
        encryption_private_key: X25519PrivateKey  | None = None,
        storage_key:            "StorageKey | None" = None,
    ) -> None:
        self.host                    = host
        self.port                    = port
        self.local_peer              = local_peer
        self.consent_queue           = consent_queue
        self.notification_queue      = notification_queue
        self.on_message              = on_message
        self._signing_private_key    = signing_private_key
        self._encryption_private_key = encryption_private_key
        self._storage_key            = storage_key
        self._running                = False
        self._server_socket: socket.socket | None = None

    def start(self) -> None:
        """Bind and run the accept loop in a daemon thread."""
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        print(f"  → [{self.local_peer.peer_name}] TCP server listening on port {self.port}")
        logger.info(f"TCP server listening on {self.host}:{self.port}")
        threading.Thread(
            target=self._accept_loop, daemon=True, name="tcp-server"
        ).start()

    def stop(self) -> None:
        """Stop accepting; close listen socket."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()

    def _notify(self, message: str) -> None:
        """Queue a line for the main thread to print, or print directly if no queue."""
        if self.notification_queue is not None:
            self.notification_queue.put(message)
        else:
            print(message)

    def update_identity(
        self,
        new_signing_key:    Ed25519PrivateKey,
        new_encryption_key: X25519PrivateKey,
    ) -> None:
        """Update signing and encryption private keys after local rotation."""
        self._signing_private_key    = new_signing_key
        self._encryption_private_key = new_encryption_key

    def _accept_loop(self) -> None:
        """accept() loop; each connection runs _handle_connection in a thread."""
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_connection,
                args=(conn, addr),
                daemon=True,
                name=f"tcp-conn-{addr[1]}",
            ).start()

    def _handle_connection(
        self, conn: socket.socket, addr: tuple[str, int]
    ) -> None:
        """Read one line, dispatch, optional write, then on_message."""
        try:
            raw = recv_line(conn)
            if not raw.strip():
                return

            try:
                message = decode_message(raw)
            except json.JSONDecodeError as exc:
                self._notify(f"  ✗ [{self.local_peer.peer_name}] Bad JSON from {addr[0]}:{addr[1]} – {exc}")
                return
            except ValueError as exc:
                self._notify(f"  ✗ [{self.local_peer.peer_name}] Invalid message from {addr[0]}:{addr[1]} – {exc}")
                return

            self._print_received(message, addr)

            response = self._dispatch(message, addr)
            if response is not None:
                conn.sendall(encode_message(response))

            if self.on_message is not None:
                self.on_message(message, addr)

        except Exception as exc:
            logger.error(f"Error handling connection from {addr}: {exc}")
        finally:
            conn.close()

    def _dispatch(self, message: Message, addr: tuple[str, int]) -> Message | None:
        """Return a reply message for types that need one, else None."""
        if message.type == MessageType.HELLO:
            return self._handle_hello(message)
        elif message.type == MessageType.HELLO_ACK:
            return None
        elif message.type == MessageType.FILE_LIST_REQUEST:
            return self._handle_file_list_request(message)
        elif message.type == MessageType.FILE_LIST_RESPONSE:
            return None
        elif message.type == MessageType.FILE_REQUEST:
            return self._handle_file_request(message, addr)
        elif message.type == MessageType.FILE_TRANSFER:
            self._handle_file_transfer(message)
            return None
        elif message.type == MessageType.FILE_REJECTED:
            return None
        elif message.type == MessageType.IDENTITY_EXCHANGE:
            return self._handle_identity_exchange(message)
        elif message.type == MessageType.IDENTITY_ACK:
            return None
        elif message.type == MessageType.KEY_ROTATION:
            self._handle_key_rotation(message)
            return None
        else:
            logger.debug(f"No built-in handler for '{message.type}'")
            return None

    def _handle_hello(self, message: Message) -> Message:
        """Reply HELLO_ACK."""
        return Message(
            type=MessageType.HELLO_ACK,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={},
        )

    def _handle_file_list_request(self, message: Message) -> Message:
        """Return FILE_LIST_RESPONSE with shared files and plaintext sha256."""
        return Message(
            type=MessageType.FILE_LIST_RESPONSE,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={"files": list_shared_files(self._storage_key)},
        )

    def _handle_file_request(
        self, message: Message, addr: tuple[str, int]
    ) -> Message:
        """Consent queue + encrypt file with ephemeral X25519 / AES-GCM / Ed25519 sign."""
        filename  = message.payload.get("filename", "")
        sender_id = message.sender_id

        contact = contact_store.get_contact(sender_id)
        if not contact or not contact.get("encryption_key"):
            reason = (
                "encrypted transfer requires identity exchange – "
                "ask the requester to use menu option 6 (Exchange identity) first"
            )
            logger.warning(f"FILE_REQUEST from {sender_id} rejected: no encryption key in contacts")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": reason},
            )

        if self._signing_private_key is None:
            reason = "server has no signing key configured – restart the application"
            logger.error("FILE_REQUEST received but signing_private_key is not set")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": reason},
            )

        if self.consent_queue is None:
            logger.warning("FILE_REQUEST received but consent_queue is not set; auto-declining")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": "server not configured for file transfer"},
            )

        req = PendingConsentRequest(
            peer_name=message.sender_name,
            peer_id=sender_id,
            peer_ip=addr[0],
            peer_port=message.sender_port,
            filename=filename,
        )
        print(
            f"\n  ⚑  [{self.local_peer.peer_name}]"
            f" {message.sender_name} wants to receive '{filename}'\n"
            f"     Press Enter at the menu to accept or decline.\n",
            flush=True,
        )
        self.consent_queue.put(req)
        accepted = req.wait_for_decision(timeout=25.0)

        if not accepted:
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": "declined by user"},
            )

        plaintext = read_shared_file_bytes(filename, self._storage_key)
        if plaintext is None:
            self._notify(f"  ✗ [{self.local_peer.peer_name}] File '{filename}' not found in storage/shared/")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": "file not found"},
            )

        try:
            ephemeral_key = crypto.generate_ephemeral_x25519()
            eph_pub_raw   = crypto.x25519_public_key_to_raw(ephemeral_key)

            receiver_raw_pub = crypto.x25519_public_raw_from_pem(contact["encryption_key"])
            aes_key          = crypto.ecdh_derive_key(ephemeral_key, receiver_raw_pub)

            nonce, ciphertext = crypto.aes_gcm_encrypt(aes_key, plaintext)

            signature = crypto.sign_transfer(
                self._signing_private_key, filename, eph_pub_raw, nonce, ciphertext
            )

        except Exception as exc:
            logger.error(f"Encryption failed for '{filename}': {exc}")
            self._notify(f"  ✗ [{self.local_peer.peer_name}] Encryption failed for '{filename}': {exc}")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": "encryption error"},
            )

        return Message(
            type=MessageType.FILE_TRANSFER,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={
                "filename":             filename,
                "encrypted":            True,
                "ephemeral_public_key": base64.b64encode(eph_pub_raw).decode("ascii"),
                "nonce":                base64.b64encode(nonce).decode("ascii"),
                "ciphertext":           base64.b64encode(ciphertext).decode("ascii"),
                "signature":            base64.b64encode(signature).decode("ascii"),
                "original_size":        len(plaintext),
            },
        )

    def _handle_file_transfer(self, message: Message) -> None:
        """Save pushed file data (encrypted path verifies then decrypts)."""
        filename  = message.payload.get("filename", "received_file")
        encrypted = message.payload.get("encrypted", False)

        if encrypted:
            self._receive_encrypted_file(message)
        else:
            b64_data = message.payload.get("data", "")
            try:
                saved_path = save_downloaded_file(filename, b64_data)
                self._notify(f"\n  ✓ File received: '{filename}' saved to {saved_path}")
            except Exception as exc:
                self._notify(f"  ✗ Failed to save '{filename}': {exc}")

    def _receive_encrypted_file(self, message: Message) -> None:
        """Verify Ed25519, ECDH+AES-GCM decrypt, save to downloads (optional at-rest encrypt)."""
        filename  = message.payload.get("filename", "received_file")
        sender_id = message.sender_id

        if self._encryption_private_key is None:
            self._notify(f"  ✗ Cannot decrypt '{filename}' – no encryption key configured.")
            return

        try:
            eph_pub_raw  = base64.b64decode(message.payload["ephemeral_public_key"])
            nonce        = base64.b64decode(message.payload["nonce"])
            ciphertext   = base64.b64decode(message.payload["ciphertext"])
            signature    = base64.b64decode(message.payload["signature"])
        except (KeyError, Exception) as exc:
            self._notify(f"  ✗ Malformed encrypted FILE_TRANSFER from {message.sender_name}: {exc}")
            return

        contact = contact_store.get_contact(sender_id)
        if not contact or not contact.get("public_key"):
            self._notify(
                f"  ✗ SECURITY: Cannot verify '{filename}' from {message.sender_name}"
                f" – no signing key in contacts.  Exchange identities first."
            )
            return

        sig_ok = crypto.verify_transfer_signature(
            contact["public_key"], filename, eph_pub_raw, nonce, ciphertext, signature
        )
        if not sig_ok:
            self._notify(
                f"\n  ✗ SECURITY WARNING: Signature verification FAILED for '{filename}'"
                f" from {message.sender_name}.\n"
                f"     The file may have been tampered with or sent by an impostor.\n"
                f"     File discarded.\n"
            )
            return

        try:
            aes_key   = crypto.ecdh_derive_key(self._encryption_private_key, eph_pub_raw)
            plaintext = crypto.aes_gcm_decrypt(aes_key, nonce, ciphertext)
        except InvalidTag:
            self._notify(
                f"\n  ✗ SECURITY WARNING: Integrity check FAILED for '{filename}'"
                f" from {message.sender_name}.\n"
                f"     The ciphertext authentication tag is invalid – data was corrupted"
                f" or tampered with.\n"
                f"     File discarded.\n"
            )
            return
        except Exception as exc:
            self._notify(f"  ✗ Decryption error for '{filename}': {exc}")
            return

        try:
            dest = save_downloaded_file_secure(filename, plaintext, self._storage_key)
            at_rest = " (encrypted at rest)" if self._storage_key else ""
            self._notify(
                f"\n  ✓ File received and decrypted: '{filename}' saved to {dest}"
                f"  ({len(plaintext):,} bytes, signature verified){at_rest}\n"
            )
        except OSError as exc:
            self._notify(f"  ✗ Failed to save '{filename}': {exc}")

    def _handle_identity_exchange(self, message: Message) -> Message:
        """Persist peer keys to contacts and return IDENTITY_ACK with our keys."""
        payload        = message.payload
        public_key     = payload.get("public_key", "")
        encryption_key = payload.get("encryption_key", "")
        fingerprint    = payload.get("fingerprint", "")

        if public_key and fingerprint:
            contact_store.save_contact(
                peer_id=message.sender_id,
                peer_name=message.sender_name,
                public_key=public_key,
                fingerprint=fingerprint,
                trusted=False,
                encryption_key=encryption_key or None,
            )
            self._notify(
                f"\n  ⚿  [{self.local_peer.peer_name}]"
                f" Identity received from {message.sender_name}"
                f" – saved to contacts (unverified)\n"
                f"     Fingerprint: {fingerprint}\n"
            )

        return Message(
            type=MessageType.IDENTITY_ACK,
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

    def _handle_key_rotation(self, message: Message) -> None:
        """Verify rotation signature with old contact key, then update stored PEMs and fingerprint."""
        payload            = message.payload
        old_fingerprint    = payload.get("old_fingerprint", "")
        new_public_key     = payload.get("new_public_key", "")
        new_encryption_key = payload.get("new_encryption_key", "")
        new_fingerprint    = payload.get("new_fingerprint", "")
        b64_sig            = payload.get("signature", "")

        if not all([old_fingerprint, new_public_key, new_fingerprint, b64_sig]):
            self._notify(f"  ✗ Malformed KEY_ROTATION from {message.sender_name} – missing fields, ignored")
            return

        contact = contact_store.get_contact_by_fingerprint(old_fingerprint)
        if not contact:
            self._notify(
                f"  ✗ KEY_ROTATION from {message.sender_name}: no contact with"
                f" fingerprint {old_fingerprint[:24]}… – ignored"
            )
            return

        try:
            signature = base64.b64decode(b64_sig)
        except Exception:
            self._notify(f"  ✗ KEY_ROTATION from {message.sender_name}: invalid base64 signature – ignored")
            return

        valid = crypto.verify_key_rotation(
            contact["public_key"],
            old_fingerprint,
            new_public_key,
            new_encryption_key,
            new_fingerprint,
            signature,
        )

        if not valid:
            self._notify(
                f"\n  ✗ SECURITY WARNING: KEY_ROTATION from {message.sender_name} has INVALID signature.\n"
                f"     This may be a spoofed rotation attempt.  Contact NOT updated.\n"
            )
            return

        contact_store.update_contact_keys(
            contact["peer_id"],
            new_public_key,
            new_encryption_key,
            new_fingerprint,
        )
        self._notify(
            f"\n  ⚿  Key rotation verified for {message.sender_name}.\n"
            f"     Old fingerprint: {old_fingerprint}\n"
            f"     New fingerprint: {new_fingerprint}\n"
            f"     Contact record updated.  Re-verify the new fingerprint out-of-band.\n"
        )

    def _print_received(self, message: Message, addr: tuple[str, int]) -> None:
        """Optional user-visible line for interesting inbound types."""
        tag    = message.type.upper()
        sender = f"{message.sender_name} @ {addr[0]}:{addr[1]}"

        if message.type == MessageType.HELLO:
            pass

        elif message.type == MessageType.HELLO_ACK:
            pass

        elif message.type == MessageType.FILE_LIST_REQUEST:
            pass

        elif message.type == MessageType.FILE_LIST_RESPONSE:
            files   = message.payload.get("files", [])
            names   = [f["filename"] if isinstance(f, dict) else str(f) for f in files]
            summary = ", ".join(names) if names else "(empty)"
            self._notify(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: {summary}")

        elif message.type == MessageType.FILE_REQUEST:
            pass

        elif message.type == MessageType.FILE_TRANSFER:
            filename = message.payload.get("filename", "?")
            self._notify(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: '{filename}'")

        elif message.type == MessageType.FILE_REJECTED:
            filename = message.payload.get("filename", "?")
            reason   = message.payload.get("reason", "declined")
            self._notify(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: '{filename}' – {reason}")

        elif message.type == MessageType.IDENTITY_EXCHANGE:
            fp = message.payload.get("fingerprint", "?")
            self._notify(
                f"  ← [{self.local_peer.peer_name}] {tag} from {sender} – sending ACK\n"
                f"     Their fingerprint: {fp}"
            )

        elif message.type == MessageType.IDENTITY_ACK:
            fp = message.payload.get("fingerprint", "?")
            self._notify(
                f"  ← [{self.local_peer.peer_name}] {tag} from {sender}\n"
                f"     Their fingerprint: {fp}"
            )

        elif message.type == MessageType.KEY_ROTATION:
            old_fp = message.payload.get("old_fingerprint", "?")
            new_fp = message.payload.get("new_fingerprint", "?")
            self._notify(
                f"  ← [{self.local_peer.peer_name}] {tag} from {sender}"
                f" (old: {old_fp[:24]}… → new: {new_fp[:24]}…)"
            )

        else:
            self._notify(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: {message.payload}")
