# ──────────────────────────────────────────────────────────────────────
# protocol.py – JSON wire format for all messages exchanged between peers
#
# Framing: newline-delimited JSON (NDJSON) over TCP.
#   - Each message is a single JSON object followed by '\n'.
#   - Splitting a byte stream into messages is trivially done by splitting
#     on '\n', and is easy to replicate in any language (Java, Go, etc.).
# ──────────────────────────────────────────────────────────────────────

import json
from dataclasses import asdict

from peer.models import Message


# ── Message type constants ──────────────────────────────────────────────
# Plain class of string constants – readable in logs and identical in any
# language that implements this protocol.

class MessageType:
    HELLO               = "hello"               # Initial greeting / peer announcement
    HELLO_ACK           = "hello_ack"           # Acknowledgement sent in reply to HELLO
    CHAT                = "chat"                # Plain text chat message
    BYE                 = "bye"                 # Polite disconnect notification
    FILE_OFFER          = "file_offer"          # Notify a peer that a file is available
    FILE_LIST_REQUEST   = "file_list_request"   # Ask a peer for their shared file list
    FILE_LIST_RESPONSE  = "file_list_response"  # Reply carrying the list of filenames
    FILE_REQUEST        = "file_request"        # Ask a peer to send a specific file
    FILE_TRANSFER       = "file_transfer"       # Carry file data (base64-encoded) to receiver
    FILE_REJECTED       = "file_rejected"       # Sender declined the file request

    # ── Identity / authentication messages (Phase 2) ──────────────────────────
    # These messages form the foundation for mutual authentication:
    #   1. Either peer initiates IDENTITY_EXCHANGE, sending their public key.
    #   2. The recipient saves the key, verifies the fingerprint, and replies
    #      with IDENTITY_ACK carrying their own public key.
    #   3. Both peers now have each other's keys stored locally.
    #   4. A future phase adds signatures to every message so each peer can
    #      cryptographically verify that a message was sent by the expected peer.
    #
    # Payload fields (both directions):
    #   peer_id     – sender's stable UUID
    #   peer_name   – sender's display name
    #   public_key  – PEM-encoded Ed25519 public key (SubjectPublicKeyInfo format)
    #   fingerprint – SHA-256 fingerprint string for out-of-band comparison
    IDENTITY_EXCHANGE   = "identity_exchange"   # Send our public key to a peer
    IDENTITY_ACK        = "identity_ack"        # Acknowledge and send our own key back


# ── Required fields (validated on every inbound message) ───────────────
_REQUIRED_FIELDS: tuple[str, ...] = (
    "type", "sender_id", "sender_name", "sender_port", "payload"
)


# ── Validation ──────────────────────────────────────────────────────────

def validate_message(data: dict) -> None:
    """
    Check that all required fields are present and have the right types.

    Raises ValueError listing every missing field, making it easy to log
    or surface a clear error when a malformed message arrives.
    """
    missing = [f for f in _REQUIRED_FIELDS if f not in data]
    if missing:
        raise ValueError(f"Message is missing required fields: {missing}")

    if not isinstance(data["sender_port"], int):
        raise ValueError("sender_port must be an integer")

    if not isinstance(data["payload"], dict):
        raise ValueError("payload must be a JSON object (dict)")


# ── Serialization ────────────────────────────────────────────────────────

def message_to_json(message: Message) -> str:
    """
    Serialize a Message dataclass to a newline-terminated JSON string.

    The trailing '\\n' is the NDJSON frame delimiter.  On the receiving end,
    split the incoming byte stream on '\\n' to recover individual messages –
    this pattern works identically in Python, Java, or any other language.

    Example output (one line, truncated):
        {"type": "hello", "sender_id": "...", ...}\\n
    """
    return json.dumps(asdict(message)) + "\n"


# ── Deserialization ──────────────────────────────────────────────────────

def json_to_message(raw: str) -> Message:
    """
    Parse a JSON string (with or without a trailing newline) into a Message.

    Raises:
        json.JSONDecodeError – if raw is not valid JSON
        ValueError           – if required fields are missing or have wrong types
    """
    data = json.loads(raw.strip())   # strip() removes the frame-delimiter newline
    validate_message(data)
    return Message(**data)


# ── Byte-level helpers (convenience wrappers for TCP send/recv) ──────────
# These wrap the string API so the rest of the codebase (server, client)
# can work directly with bytes without calling encode/decode manually.

def encode_message(message: Message) -> bytes:
    """Encode a Message to UTF-8 bytes ready to be written to a TCP socket."""
    return message_to_json(message).encode("utf-8")


def decode_message(raw: bytes) -> Message:
    """Decode UTF-8 bytes received from a TCP socket into a Message."""
    return json_to_message(raw.decode("utf-8"))
