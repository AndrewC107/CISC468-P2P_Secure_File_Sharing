# ───────────────────────────────────────────────────────────────
# models.py – Core data structures shared across the application
# ───────────────────────────────────────────────────────────────

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Peer:
    """
    Represents a single node in the P2P network.

    Each peer is uniquely identified by peer_id, and reachable at host:port.
    last_seen is updated whenever we hear from this peer (via discovery or message).
    """
    peer_id: str        # UUID string – stable for the lifetime of the process
    host: str           # IP address (e.g. "192.168.1.5")
    port: int           # TCP port the peer's server is listening on
    name: str           # Human-readable display name (e.g. "Alice")
    last_seen: float = field(default_factory=time.time)  # Unix timestamp


@dataclass
class Message:
    """
    A single message exchanged between two peers over TCP.

    msg_type  – what kind of message this is (see MessageType in protocol.py)
    sender_id – peer_id of the originating peer
    payload   – arbitrary key/value data; content depends on msg_type
    timestamp – when the message was created (Unix timestamp)
    msg_id    – unique ID so messages can be deduplicated if needed later
    """
    msg_type: str
    sender_id: str
    payload: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
