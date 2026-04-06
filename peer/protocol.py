# ─────────────────────────────────────────────────────────────────────────────
# protocol.py – NDJSON message format over TCP (one JSON object + newline per frame)
# ─────────────────────────────────────────────────────────────────────────────

import json
from dataclasses import asdict

from peer.models import Message


class MessageType:
    HELLO               = "hello"
    HELLO_ACK           = "hello_ack"
    CHAT                = "chat"
    BYE                 = "bye"
    FILE_OFFER          = "file_offer"
    FILE_LIST_REQUEST   = "file_list_request"
    FILE_LIST_RESPONSE  = "file_list_response"
    FILE_REQUEST        = "file_request"
    FILE_TRANSFER       = "file_transfer"
    FILE_REJECTED       = "file_rejected"
    IDENTITY_EXCHANGE   = "identity_exchange"
    IDENTITY_ACK        = "identity_ack"
    KEY_ROTATION        = "key_rotation"


_REQUIRED_FIELDS: tuple[str, ...] = (
    "type", "sender_id", "sender_name", "sender_port", "payload"
)


def validate_message(data: dict) -> None:
    """Ensure required fields exist and types are valid; raises ValueError if not."""
    missing = [f for f in _REQUIRED_FIELDS if f not in data]
    if missing:
        raise ValueError(f"Message is missing required fields: {missing}")

    if not isinstance(data["sender_port"], int):
        raise ValueError("sender_port must be an integer")

    if not isinstance(data["payload"], dict):
        raise ValueError("payload must be a JSON object (dict)")


def message_to_json(message: Message) -> str:
    """Serialize a Message to one NDJSON line (JSON + newline)."""
    return json.dumps(asdict(message)) + "\n"


def json_to_message(raw: str) -> Message:
    """Parse one NDJSON line into a Message."""
    data = json.loads(raw.strip())
    validate_message(data)
    return Message(**data)


def encode_message(message: Message) -> bytes:
    """Encode a Message to UTF-8 bytes for send()."""
    return message_to_json(message).encode("utf-8")


def decode_message(raw: bytes) -> Message:
    """Decode socket bytes into a Message."""
    return json_to_message(raw.decode("utf-8"))
