# ───────────────────────────────────────────────────────────────
# models.py – Message and PeerInfo (wire + discovery)
# ───────────────────────────────────────────────────────────────

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Message:
    """One TCP NDJSON message: type, sender fields, JSON payload, and optional id/time."""
    type: str
    sender_id: str
    sender_name: str
    sender_port: int
    payload: dict[str, Any]
    msg_id: str   = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)


@dataclass
class PeerInfo:
    """A remote peer: id, display name, address, and optional identity keys from exchange."""
    peer_id: str
    peer_name: str
    ip: str
    port: int
    last_seen:        float      = field(default_factory=time.time)
    public_key:       str | None = None
    fingerprint:      str | None = None
    encryption_key:   str | None = None
