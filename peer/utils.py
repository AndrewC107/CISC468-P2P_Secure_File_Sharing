# ────────────────────────────────────────────────────────────────
# utils.py – Small helper functions used across the application
# ────────────────────────────────────────────────────────────────

import socket
import time
import uuid


def generate_peer_id() -> str:
    """Return a new random UUID string to uniquely identify a peer."""
    return str(uuid.uuid4())


def get_local_ip() -> str:
    """
    Determine the LAN IP address of this machine.

    Technique: open a UDP socket toward a public address (no data is sent)
    and read back which local interface the OS would use.  Falls back to
    loopback if anything goes wrong.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def current_timestamp() -> float:
    """Return the current time as a Unix timestamp (float)."""
    return time.time()
