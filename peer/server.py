# ────────────────────────────────────────────────────────────────────────────
# server.py – TCP server that receives and dispatches NDJSON messages
#
# Message dispatch table
# ──────────────────────
#   HELLO              → reply with HELLO_ACK  (symmetric discovery)
#   HELLO_ACK          → no reply
#   FILE_LIST_REQUEST  → reply with FILE_LIST_RESPONSE (real file list)
#   FILE_LIST_RESPONSE → no reply
#   FILE_REQUEST       → enqueue PendingConsentRequest, wait for main loop
#   FILE_TRANSFER      → save received file to storage/downloads/
#   FILE_REJECTED      → no reply (client already handles the print)
#   anything else      → forwarded to on_message callback only
# ────────────────────────────────────────────────────────────────────────────

import base64
import json
import logging
import queue
import socket
import threading
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from peer import contacts as contact_store
from peer import crypto
from peer.files import list_shared_files, read_shared_file_b64, save_downloaded_file
from peer.models import Message, PeerInfo
from peer.protocol import MessageType, decode_message, encode_message
from peer.utils import recv_line

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# PendingConsentRequest
# ─────────────────────────────────────────────────────────────────────────────

class PendingConsentRequest:
    """
    Carries a FILE_REQUEST that needs the user's accept/decline decision.

    Why not call input() directly in the server thread?
    ────────────────────────────────────────────────────
    Python's input() reads from the process's standard input stream (stdin).
    When two threads both call input() at the same time:

      1. Both threads print their prompts.  On most terminals those two
         print() calls will interleave and produce garbled/overlapping text.

      2. The OS delivers each keypress to only ONE of the two callers –
         whichever grabbed stdin first, or in an unpredictable order.

      3. The thread that "lost" the race is stuck waiting for input that
         will never arrive (the other thread consumed it), so its prompt
         sits on screen silently and the connection eventually times out.

    The fix: the server thread never calls input().  Instead it creates a
    PendingConsentRequest, puts it in a shared queue, and BLOCKS on an
    Event until the main CLI thread resolves it.  The main thread is the
    only place that ever calls input(), so prompts are always clean.

    Life-cycle
    ──────────
    1. Server thread: creates request, puts it in consent_queue, calls
       wait_for_decision() – this blocks until the event fires or times out.
    2. Main thread:   reads request from queue, shows "[REQUEST] ..." prompt,
       calls resolve(True/False) – this sets _accepted and fires the event.
    3. Server thread: wait_for_decision() returns _accepted; builds and
       returns the appropriate Message (FILE_TRANSFER or FILE_REJECTED).
    """

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

        self._accepted    = False          # set by resolve()
        self._event       = threading.Event()
        self._timed_out   = False          # True if wait_for_decision timed out

    @property
    def timed_out(self) -> bool:
        """
        True after wait_for_decision() returned because of a timeout (not a
        resolve() call).  The main thread uses this to skip stale requests
        that the server has already handled with a default rejection.
        """
        return self._timed_out

    def resolve(self, accepted: bool) -> None:
        """
        Called by the MAIN THREAD to provide the user's decision.
        Stores the answer and unblocks the server thread.
        Safe to call even after the server thread has already timed out
        (the event.set() is a no-op in that case for the server thread).
        """
        self._accepted = accepted
        self._event.set()

    def wait_for_decision(self, timeout: float = 25.0) -> bool:
        """
        Called by the SERVER THREAD to block until the user decides.

        The timeout (25 s) is set a few seconds below the client's 30-second
        connection timeout so we can still send FILE_REJECTED before the
        requesting peer gives up and closes the socket.

        Returns True  – user accepted
                False – user declined OR timeout expired
        """
        fired = self._event.wait(timeout=timeout)
        if not fired:
            # Timeout expired before the main thread resolved this request.
            # Mark it so handle_pending_consents() can skip the stale prompt.
            self._timed_out = True
        return self._accepted


# ─────────────────────────────────────────────────────────────────────────────
# PeerServer
# ─────────────────────────────────────────────────────────────────────────────

class PeerServer:
    """
    TCP server that accepts, parses, and dispatches NDJSON messages.

    Pass a consent_queue (queue.Queue) to enable FILE_REQUEST handling.
    The server thread enqueues PendingConsentRequest objects; the main
    CLI loop drains the queue and prompts the user (see main.py).
    """

    def __init__(
        self,
        host: str,
        port: int,
        local_peer: PeerInfo,
        consent_queue: queue.Queue | None = None,
        on_message: Callable[[Message, tuple[str, int]], None] | None = None,
        signing_private_key:    Ed25519PrivateKey | None = None,
        encryption_private_key: X25519PrivateKey  | None = None,
    ) -> None:
        """
        host                   – bind address; "0.0.0.0" listens on all interfaces
        port                   – TCP port to listen on
        local_peer             – this node's identity (used to build response messages)
        consent_queue          – thread-safe queue for pending FILE_REQUEST consents
        on_message             – optional callback(message, addr) fired for every message
        signing_private_key    – Ed25519 key for signing outgoing FILE_TRANSFER messages
        encryption_private_key – X25519 key for decrypting unsolicited incoming FILE_TRANSFER
        """
        self.host                   = host
        self.port                   = port
        self.local_peer             = local_peer
        self.consent_queue          = consent_queue
        self.on_message             = on_message
        self._signing_private_key    = signing_private_key
        self._encryption_private_key = encryption_private_key
        self._running               = False
        self._server_socket: socket.socket | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the socket and start the accept loop in a daemon thread."""
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
        """Signal the server to stop accepting new connections."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()

    # ── Accept loop ───────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        """Wait for connections and spawn a handler thread for each."""
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

    # ── Connection handler ────────────────────────────────────────────────────

    def _handle_connection(
        self, conn: socket.socket, addr: tuple[str, int]
    ) -> None:
        """
        Read one NDJSON message, dispatch it, send a response if needed,
        then call the on_message callback.
        """
        try:
            raw = recv_line(conn)
            if not raw.strip():
                return

            # ── Parse ──────────────────────────────────────────────────────────
            try:
                message = decode_message(raw)
            except json.JSONDecodeError as exc:
                print(f"  ✗ [{self.local_peer.peer_name}] Bad JSON from {addr[0]}:{addr[1]} – {exc}")
                return
            except ValueError as exc:
                print(f"  ✗ [{self.local_peer.peer_name}] Invalid message from {addr[0]}:{addr[1]} – {exc}")
                return

            # ── Print summary (before dispatch so user sees what arrived) ──────
            self._print_received(message, addr)

            # ── Dispatch: run handler, send response if one is returned ────────
            response = self._dispatch(message, addr)
            if response is not None:
                conn.sendall(encode_message(response))

            # ── Notify application layer (e.g. to register the peer) ───────────
            if self.on_message is not None:
                self.on_message(message, addr)

        except Exception as exc:
            logger.error(f"Error handling connection from {addr}: {exc}")
        finally:
            conn.close()

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, message: Message, addr: tuple[str, int]) -> Message | None:
        """Route a message to its handler. Returns a response or None."""
        if message.type == MessageType.HELLO:
            return self._handle_hello(message)
        elif message.type == MessageType.HELLO_ACK:
            return None
        elif message.type == MessageType.FILE_LIST_REQUEST:
            return self._handle_file_list_request(message)
        elif message.type == MessageType.FILE_LIST_RESPONSE:
            return None
        elif message.type == MessageType.FILE_REQUEST:
            # addr is passed so we can store the requester's IP in the consent request
            return self._handle_file_request(message, addr)
        elif message.type == MessageType.FILE_TRANSFER:
            self._handle_file_transfer(message)
            return None
        elif message.type == MessageType.FILE_REJECTED:
            return None
        elif message.type == MessageType.IDENTITY_EXCHANGE:
            return self._handle_identity_exchange(message)
        elif message.type == MessageType.IDENTITY_ACK:
            # The client already processes the ACK payload; nothing to do here.
            return None
        else:
            logger.debug(f"No built-in handler for '{message.type}'")
            return None

    # ── Message handlers ──────────────────────────────────────────────────────

    def _handle_hello(self, message: Message) -> Message:
        """HELLO – reply with HELLO_ACK carrying our identity."""
        return Message(
            type=MessageType.HELLO_ACK,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={},
        )

    def _handle_file_list_request(self, message: Message) -> Message:
        """FILE_LIST_REQUEST – reply with real {filename, size} entries."""
        return Message(
            type=MessageType.FILE_LIST_RESPONSE,
            sender_id=self.local_peer.peer_id,
            sender_name=self.local_peer.peer_name,
            sender_port=self.local_peer.port,
            payload={"files": list_shared_files()},
        )

    def _handle_file_request(
        self, message: Message, addr: tuple[str, int]
    ) -> Message:
        """
        FILE_REQUEST – ask the user for consent, then encrypt and send the file.

        Encrypted transfer flow
        ───────────────────────
        1. Look up the requester's X25519 encryption key in the contact store.
           If not found, reject with a clear reason – identity exchange is required
           before encrypted file transfer.
        2. Ask the user for consent via the consent queue (never calls input() here).
        3. On acceptance:
           a. Generate a fresh ephemeral X25519 key pair. [PERFECT FORWARD SECRECY]
           b. Derive an AES-256 session key via ECDH + HKDF-SHA256.  [CONFIDENTIALITY]
           c. Encrypt the file bytes with AES-256-GCM.  [CONFIDENTIALITY + INTEGRITY]
           d. Sign (filename + ephemeral key + nonce + ciphertext) with Ed25519.  [AUTHENTICATION]
           e. Return a FILE_TRANSFER message with all encrypted fields.
        """
        filename  = message.payload.get("filename", "")
        sender_id = message.sender_id

        # ── Require identity exchange before encrypted transfer ────────────────
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

        # ── Get user consent ───────────────────────────────────────────────────
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
            f"     Press Enter at the menu to accept or decline.\n"
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

        # ── Read the file ──────────────────────────────────────────────────────
        from pathlib import Path
        from peer.config import SHARED_DIR
        file_path = Path(SHARED_DIR) / filename
        if not file_path.exists() or not file_path.is_file():
            print(f"  ✗ [{self.local_peer.peer_name}] File '{filename}' not found in storage/shared/")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": "file not found"},
            )
        plaintext = file_path.read_bytes()

        # ── Encrypt the file ───────────────────────────────────────────────────
        try:
            # [PFS] Generate a fresh ephemeral X25519 key pair for this transfer only.
            ephemeral_key = crypto.generate_ephemeral_x25519()
            eph_pub_raw   = crypto.x25519_public_key_to_raw(ephemeral_key)

            # [CONFIDENTIALITY] Derive AES session key via ECDH + HKDF-SHA256.
            receiver_raw_pub = crypto.x25519_public_raw_from_pem(contact["encryption_key"])
            aes_key          = crypto.ecdh_derive_key(ephemeral_key, receiver_raw_pub)

            # [CONFIDENTIALITY + INTEGRITY] Encrypt with AES-256-GCM.
            nonce, ciphertext = crypto.aes_gcm_encrypt(aes_key, plaintext)

            # [AUTHENTICATION] Sign transfer metadata with our Ed25519 key.
            signature = crypto.sign_transfer(
                self._signing_private_key, filename, eph_pub_raw, nonce, ciphertext
            )

        except Exception as exc:
            logger.error(f"Encryption failed for '{filename}': {exc}")
            print(f"  ✗ [{self.local_peer.peer_name}] Encryption failed for '{filename}': {exc}")
            return Message(
                type=MessageType.FILE_REJECTED,
                sender_id=self.local_peer.peer_id,
                sender_name=self.local_peer.peer_name,
                sender_port=self.local_peer.port,
                payload={"filename": filename, "reason": "encryption error"},
            )

        print(f"  🔒 [{self.local_peer.peer_name}] Sending '{filename}' encrypted to {message.sender_name}")

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
        """
        FILE_TRANSFER (unsolicited push from a remote peer) – decrypt and save.

        Handles both encrypted (Phase 2+) and legacy plaintext transfers.
        For encrypted transfers, verifies the Ed25519 signature BEFORE
        attempting decryption.
        """
        filename  = message.payload.get("filename", "received_file")
        encrypted = message.payload.get("encrypted", False)

        if encrypted:
            self._receive_encrypted_file(message)
        else:
            # Legacy plaintext path (no encryption_key exchange needed)
            b64_data = message.payload.get("data", "")
            try:
                saved_path = save_downloaded_file(filename, b64_data)
                print(f"\n  ✓ File received: '{filename}' saved to {saved_path}")
            except Exception as exc:
                print(f"  ✗ Failed to save '{filename}': {exc}")

    def _receive_encrypted_file(self, message: Message) -> None:
        """
        Decrypt and verify an encrypted FILE_TRANSFER pushed to this server.

        Uses self._encryption_private_key (the local peer's long-term X25519 key)
        together with the sender's ephemeral public key to reconstruct the
        AES session key.  The sender's Ed25519 public key is looked up in
        the contact store for signature verification.

        Security errors (bad signature, failed decryption) are logged and
        displayed but never silently ignored.
        """
        filename  = message.payload.get("filename", "received_file")
        sender_id = message.sender_id

        if self._encryption_private_key is None:
            print(f"  ✗ Cannot decrypt '{filename}' – no encryption key configured.")
            return

        # ── Decode all base64 fields ───────────────────────────────────────────
        try:
            eph_pub_raw  = base64.b64decode(message.payload["ephemeral_public_key"])
            nonce        = base64.b64decode(message.payload["nonce"])
            ciphertext   = base64.b64decode(message.payload["ciphertext"])
            signature    = base64.b64decode(message.payload["signature"])
        except (KeyError, Exception) as exc:
            print(f"  ✗ Malformed encrypted FILE_TRANSFER from {message.sender_name}: {exc}")
            return

        # ── [AUTHENTICATION] Verify signature before touching the ciphertext ──
        contact = contact_store.get_contact(sender_id)
        if not contact or not contact.get("public_key"):
            print(
                f"  ✗ SECURITY: Cannot verify '{filename}' from {message.sender_name}"
                f" – no signing key in contacts.  Exchange identities first."
            )
            return

        sig_ok = crypto.verify_transfer_signature(
            contact["public_key"], filename, eph_pub_raw, nonce, ciphertext, signature
        )
        if not sig_ok:
            print(
                f"\n  ✗ SECURITY WARNING: Signature verification FAILED for '{filename}'"
                f" from {message.sender_name}.\n"
                f"     The file may have been tampered with or sent by an impostor.\n"
                f"     File discarded.\n"
            )
            return

        # ── [CONFIDENTIALITY] Decrypt with AES-256-GCM ────────────────────────
        try:
            aes_key   = crypto.ecdh_derive_key(self._encryption_private_key, eph_pub_raw)
            plaintext = crypto.aes_gcm_decrypt(aes_key, nonce, ciphertext)
        except InvalidTag:
            print(
                f"\n  ✗ SECURITY WARNING: Integrity check FAILED for '{filename}'"
                f" from {message.sender_name}.\n"
                f"     The ciphertext authentication tag is invalid – data was corrupted"
                f" or tampered with.\n"
                f"     File discarded.\n"
            )
            return
        except Exception as exc:
            print(f"  ✗ Decryption error for '{filename}': {exc}")
            return

        # ── Save the decrypted file ────────────────────────────────────────────
        try:
            from pathlib import Path
            from peer.config import DOWNLOADS_DIR
            from peer.files import ensure_storage_dirs
            ensure_storage_dirs()
            dest = Path(DOWNLOADS_DIR) / filename
            dest.write_bytes(plaintext)
            print(
                f"\n  ✓ 🔓 File received and decrypted: '{filename}' saved to {dest}"
                f"  ({len(plaintext):,} bytes, signature verified)\n"
            )
        except OSError as exc:
            print(f"  ✗ Failed to save '{filename}': {exc}")

    def _handle_identity_exchange(self, message: Message) -> Message:
        """
        IDENTITY_EXCHANGE – save the sender's identity and reply with ours.

        Saves both the Ed25519 signing key (public_key) and the X25519
        encryption key (encryption_key) from the payload into the contact store.
        Both are required before encrypted file transfer can proceed.
        """
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
            print(
                f"\n  ⚿  [{self.local_peer.peer_name}]"
                f" Identity received from {message.sender_name}"
                f" – saved to contacts (unverified)\n"
                f"     Fingerprint: {fingerprint}\n"
            )

        # Reply with both our Ed25519 and X25519 public keys
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

    # ── Terminal output ───────────────────────────────────────────────────────

    def _print_received(self, message: Message, addr: tuple[str, int]) -> None:
        """Print a one-line log of the received message type."""
        tag    = message.type.upper()
        sender = f"{message.sender_name} @ {addr[0]}:{addr[1]}"

        if message.type == MessageType.HELLO:
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender} – sending ACK")

        elif message.type == MessageType.HELLO_ACK:
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}")

        elif message.type == MessageType.FILE_LIST_REQUEST:
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender} – sending file list")

        elif message.type == MessageType.FILE_LIST_RESPONSE:
            files   = message.payload.get("files", [])
            names   = [f["filename"] if isinstance(f, dict) else str(f) for f in files]
            summary = ", ".join(names) if names else "(empty)"
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: {summary}")

        elif message.type == MessageType.FILE_REQUEST:
            # _handle_file_request prints its own notification and the main
            # loop shows the interactive prompt – no duplicate line needed here.
            pass

        elif message.type == MessageType.FILE_TRANSFER:
            filename = message.payload.get("filename", "?")
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: '{filename}'")

        elif message.type == MessageType.FILE_REJECTED:
            filename = message.payload.get("filename", "?")
            reason   = message.payload.get("reason", "declined")
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: '{filename}' – {reason}")

        elif message.type == MessageType.IDENTITY_EXCHANGE:
            fp = message.payload.get("fingerprint", "?")
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender} – sending ACK")
            print(f"     Their fingerprint: {fp}")

        elif message.type == MessageType.IDENTITY_ACK:
            fp = message.payload.get("fingerprint", "?")
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}")
            print(f"     Their fingerprint: {fp}")

        else:
            print(f"  ← [{self.local_peer.peer_name}] {tag} from {sender}: {message.payload}")
