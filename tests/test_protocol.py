"""
tests/test_protocol.py – Unit tests for the JSON message protocol (Phase 2).

Run with:
    python -m pytest tests/ -v
"""

import json

import pytest

from peer.models import Message, PeerInfo
from peer.protocol import (
    MessageType,
    decode_message,
    encode_message,
    json_to_message,
    message_to_json,
    validate_message,
)


# ── Helpers ───────────────────────────────────────────────────────────────

def make_message(**overrides) -> Message:
    """Return a minimal valid Message, overriding any fields as needed."""
    defaults: dict = dict(
        type=MessageType.HELLO,
        sender_id="peer-abc",
        sender_name="Alice",
        sender_port=5000,
        payload={},
    )
    defaults.update(overrides)
    return Message(**defaults)


# ── Round-trip serialization ──────────────────────────────────────────────

class TestRoundtrip:
    """A Message serialised then deserialised must be field-for-field identical."""

    def test_hello_message(self):
        original = make_message()
        decoded  = json_to_message(message_to_json(original))
        assert decoded.type        == original.type
        assert decoded.sender_id   == original.sender_id
        assert decoded.sender_name == original.sender_name
        assert decoded.sender_port == original.sender_port
        assert decoded.payload     == original.payload
        assert decoded.msg_id      == original.msg_id
        assert decoded.timestamp   == original.timestamp

    def test_chat_message_with_payload(self):
        original = make_message(type=MessageType.CHAT, payload={"text": "hi there"})
        decoded  = json_to_message(message_to_json(original))
        assert decoded.payload["text"] == "hi there"

    def test_file_offer_message(self):
        original = make_message(
            type=MessageType.FILE_OFFER,
            payload={"filename": "photo.jpg", "size": 204800},
        )
        decoded = json_to_message(message_to_json(original))
        assert decoded.payload["filename"] == "photo.jpg"
        assert decoded.payload["size"]     == 204800

    def test_bye_message(self):
        original = make_message(type=MessageType.BYE, sender_name="Bob", sender_port=5100)
        decoded  = json_to_message(message_to_json(original))
        assert decoded.type        == MessageType.BYE
        assert decoded.sender_name == "Bob"
        assert decoded.sender_port == 5100


# ── Newline framing (NDJSON) ──────────────────────────────────────────────

class TestNewlineFraming:
    """message_to_json must produce newline-terminated, single-line output."""

    def test_output_ends_with_newline(self):
        assert message_to_json(make_message()).endswith("\n")

    def test_body_has_no_embedded_newlines(self):
        # Only one line + the terminating '\n' — no mid-body breaks.
        body = message_to_json(make_message(payload={"text": "hello"})).rstrip("\n")
        assert "\n" not in body

    def test_json_to_message_strips_trailing_newline(self):
        """Framed output (with trailing \\n) must parse back cleanly."""
        msg    = make_message()
        framed = message_to_json(msg)          # ends with '\n'
        assert framed.endswith("\n")
        decoded = json_to_message(framed)
        assert decoded.sender_id == msg.sender_id

    def test_multiple_frames_split_correctly(self):
        """Simulate splitting a stream on '\\n' to recover two messages."""
        m1 = make_message(sender_name="Alice")
        m2 = make_message(sender_name="Bob",   type=MessageType.CHAT)
        stream = message_to_json(m1) + message_to_json(m2)
        frames = [line for line in stream.split("\n") if line.strip()]
        assert len(frames) == 2
        assert json_to_message(frames[0]).sender_name == "Alice"
        assert json_to_message(frames[1]).sender_name == "Bob"


# ── Byte-level helpers ────────────────────────────────────────────────────

class TestByteHelpers:
    """encode_message / decode_message wrap the string API for TCP I/O."""

    def test_encode_returns_bytes(self):
        assert isinstance(encode_message(make_message()), bytes)

    def test_decode_roundtrip(self):
        original = make_message(type=MessageType.CHAT, payload={"k": "v"})
        assert decode_message(encode_message(original)).payload == {"k": "v"}

    def test_encoded_output_is_valid_utf8_json(self):
        msg    = make_message(sender_name="Bob", sender_port=5100)
        parsed = json.loads(encode_message(msg).decode("utf-8").strip())
        assert parsed["sender_name"] == "Bob"
        assert parsed["sender_port"] == 5100

    def test_all_required_fields_present_in_encoded_output(self):
        msg    = make_message()
        parsed = json.loads(encode_message(msg).decode("utf-8").strip())
        for f in ("type", "sender_id", "sender_name", "sender_port", "payload"):
            assert f in parsed, f"Missing field: {f}"


# ── Validation ────────────────────────────────────────────────────────────

class TestValidation:
    """validate_message should pass on good data and raise on bad data."""

    def test_valid_dict_passes(self):
        # Must not raise
        validate_message({
            "type": "hello", "sender_id": "x",
            "sender_name": "Alice", "sender_port": 5000, "payload": {},
        })

    def test_missing_single_field_raises(self):
        with pytest.raises(ValueError, match="missing required fields"):
            validate_message({"type": "hello", "sender_id": "x"})

    def test_missing_multiple_fields_reported(self):
        # The error message should list all missing fields
        with pytest.raises(ValueError) as exc_info:
            validate_message({"type": "hello"})
        assert "sender_id"   in str(exc_info.value)
        assert "sender_name" in str(exc_info.value)

    def test_wrong_sender_port_type_raises(self):
        with pytest.raises(ValueError, match="sender_port"):
            validate_message({
                "type": "hello", "sender_id": "x",
                "sender_name": "Alice", "sender_port": "not-an-int", "payload": {},
            })

    def test_wrong_payload_type_raises(self):
        with pytest.raises(ValueError, match="payload"):
            validate_message({
                "type": "hello", "sender_id": "x",
                "sender_name": "Alice", "sender_port": 5000, "payload": "bad",
            })

    def test_invalid_json_raises_decode_error(self):
        with pytest.raises(json.JSONDecodeError):
            json_to_message("not json at all")

    def test_missing_field_in_json_string_raises(self):
        raw = json.dumps({"type": "hello", "sender_id": "x"})
        with pytest.raises(ValueError):
            json_to_message(raw)


# ── MessageType constants ─────────────────────────────────────────────────

class TestMessageTypes:
    """MessageType values must be plain strings and all distinct."""

    def test_all_types_are_strings(self):
        for attr in ("HELLO", "CHAT", "BYE", "FILE_OFFER"):
            assert isinstance(getattr(MessageType, attr), str), \
                f"MessageType.{attr} is not a str"

    def test_types_are_distinct(self):
        types = [MessageType.HELLO, MessageType.CHAT, MessageType.BYE, MessageType.FILE_OFFER]
        assert len(set(types)) == len(types), "MessageType values must be unique"


# ── PeerInfo dataclass ────────────────────────────────────────────────────

class TestPeerInfo:
    """PeerInfo should store peer metadata and default last_seen to now."""

    def test_last_seen_defaults_to_float(self):
        p = PeerInfo(peer_id="x", peer_name="Alice", ip="127.0.0.1", port=5000)
        assert isinstance(p.last_seen, float)

    def test_explicit_fields(self):
        p = PeerInfo(peer_id="abc", peer_name="Bob", ip="10.0.0.1", port=5100, last_seen=1.0)
        assert p.peer_id   == "abc"
        assert p.peer_name == "Bob"
        assert p.ip        == "10.0.0.1"
        assert p.port      == 5100
        assert p.last_seen == 1.0

    def test_two_peers_are_independent(self):
        a = PeerInfo(peer_id="a", peer_name="Alice", ip="127.0.0.1", port=5000)
        b = PeerInfo(peer_id="b", peer_name="Bob",   ip="127.0.0.1", port=5100)
        assert a.peer_id != b.peer_id
        assert a.port    != b.port
