"""
tests/test_protocol.py – Unit tests for the JSON message protocol.

Run with:
    cd p2p_secure_share
    python -m pytest tests/ -v
"""

import json

import pytest

from peer.models import Message
from peer.protocol import MessageType, decode_message, encode_message


class TestEncodeDecodeRoundtrip:
    """A message serialised then deserialised should be identical."""

    def test_chat_message(self):
        original = Message(
            msg_type=MessageType.CHAT,
            sender_id="peer-abc",
            payload={"text": "Hello!"},
        )
        decoded = decode_message(encode_message(original))

        assert decoded.msg_type  == original.msg_type
        assert decoded.sender_id == original.sender_id
        assert decoded.payload   == original.payload
        assert decoded.msg_id    == original.msg_id
        assert decoded.timestamp == original.timestamp

    def test_hello_message_with_empty_payload(self):
        original = Message(
            msg_type=MessageType.HELLO,
            sender_id="peer-xyz",
            payload={},
        )
        decoded = decode_message(encode_message(original))
        assert decoded.msg_type == MessageType.HELLO
        assert decoded.payload  == {}

    def test_file_offer_message(self):
        original = Message(
            msg_type=MessageType.FILE_OFFER,
            sender_id="peer-123",
            payload={"filename": "photo.jpg", "size": 204800},
        )
        decoded = decode_message(encode_message(original))
        assert decoded.payload["filename"] == "photo.jpg"
        assert decoded.payload["size"]     == 204800


class TestEncoding:
    """encode_message should produce valid UTF-8 JSON bytes."""

    def test_returns_bytes(self):
        msg = Message(msg_type=MessageType.HELLO, sender_id="x", payload={})
        assert isinstance(encode_message(msg), bytes)

    def test_is_valid_json(self):
        msg = Message(msg_type=MessageType.CHAT, sender_id="x", payload={"k": "v"})
        parsed = json.loads(encode_message(msg).decode("utf-8"))
        assert parsed["msg_type"]  == MessageType.CHAT
        assert parsed["sender_id"] == "x"
        assert parsed["payload"]   == {"k": "v"}

    def test_all_required_fields_present(self):
        msg = Message(msg_type=MessageType.BYE, sender_id="x", payload={})
        parsed = json.loads(encode_message(msg).decode("utf-8"))
        for field in ("msg_type", "sender_id", "payload", "timestamp", "msg_id"):
            assert field in parsed, f"Missing field: {field}"


class TestDecoding:
    """decode_message should raise on bad input."""

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            decode_message(b"not json at all")

    def test_missing_field_raises(self):
        # Omit the required 'sender_id' field
        raw = json.dumps({"msg_type": "hello", "payload": {}}).encode()
        with pytest.raises(TypeError):
            decode_message(raw)


class TestMessageTypes:
    """MessageType constants should be plain strings."""

    def test_all_types_are_strings(self):
        for attr in ("HELLO", "CHAT", "BYE", "FILE_OFFER"):
            value = getattr(MessageType, attr)
            assert isinstance(value, str), f"MessageType.{attr} is not a str"

    def test_types_are_distinct(self):
        types = [MessageType.HELLO, MessageType.CHAT, MessageType.BYE, MessageType.FILE_OFFER]
        assert len(types) == len(set(types)), "MessageType values must be unique"
