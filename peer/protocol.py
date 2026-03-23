# ──────────────────────────────────────────────────────────────────────
# protocol.py – JSON wire format for all messages exchanged between peers
# ──────────────────────────────────────────────────────────────────────

import json
from dataclasses import asdict

from peer.models import Message


# ── Message type constants ──────────────────────────────────────────────
# Using a plain class of string constants keeps things simple and readable.
# These values are what travels in the "msg_type" field on the wire.

class MessageType:
    HELLO      = "hello"       # Greeting when a peer connects / says hi
    CHAT       = "chat"        # Plain text chat message
    BYE        = "bye"         # Polite disconnect notification
    FILE_OFFER = "file_offer"  # (Future) notify a peer that a file is available


# ── Encoding ────────────────────────────────────────────────────────────

def encode_message(message: Message) -> bytes:
    """
    Serialize a Message dataclass to UTF-8 encoded JSON bytes.

    This is what gets sent over the TCP socket.
    """
    data = asdict(message)           # Convert dataclass → plain dict
    return json.dumps(data).encode("utf-8")


# ── Decoding ────────────────────────────────────────────────────────────

def decode_message(raw: bytes) -> Message:
    """
    Deserialize UTF-8 encoded JSON bytes back into a Message dataclass.

    Raises json.JSONDecodeError if the bytes are not valid JSON.
    Raises TypeError if required fields are missing.
    """
    data = json.loads(raw.decode("utf-8"))  # bytes → dict
    return Message(**data)                  # dict → dataclass
