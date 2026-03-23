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

import json
import logging
import socket

from peer.files import save_downloaded_file
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

    def __init__(self, local_peer: PeerInfo) -> None:
        self.local_peer = local_peer

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

        If accepted: decodes the base64 payload and saves to storage/downloads/.
        If rejected: prints a message explaining why.

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

        # Use the longer timeout so the remote user has time to type y/n
        response = self._send_and_recv(
            peer_ip, peer_port, request, timeout=_FILE_TRANSFER_TIMEOUT
        )
        if response is None:
            return False

        if response.type == MessageType.FILE_TRANSFER:
            b64_data = response.payload.get("data", "")
            recv_name = response.payload.get("filename", filename)
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
