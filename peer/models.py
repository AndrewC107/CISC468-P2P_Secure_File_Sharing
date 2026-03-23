# ───────────────────────────────────────────────────────────────
# models.py – Core data structures shared across the application
# ───────────────────────────────────────────────────────────────

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Message:
    """
    A single message exchanged between two peers over TCP.

    Fields are kept flat and JSON-serialisable so a future Java (or any other)
    client can parse them without custom deserializers.

    type        – what kind of message this is (see MessageType in protocol.py)
    sender_id   – UUID of the originating peer
    sender_name – human-readable display name of the sender
    sender_port – TCP port the sender's server is listening on
    payload     – arbitrary key/value data; content depends on type
    msg_id      – unique ID for deduplication
    timestamp   – Unix timestamp (seconds) when the message was created
    """
    type: str
    sender_id: str
    sender_name: str
    sender_port: int
    payload: dict[str, Any]
    msg_id: str   = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)


@dataclass
class PeerInfo:
    """
    Represents a discovered peer on the network.

    peer_id   – stable UUID for the lifetime of the remote process
    peer_name – human-readable display name (e.g. "Alice")
    ip        – IP address of the peer
    port      – TCP port the peer's server is listening on
    last_seen – Unix timestamp of the last discovery announcement
    """
    peer_id: str
    peer_name: str
    ip: str
    port: int
    last_seen: float = field(default_factory=time.time)
