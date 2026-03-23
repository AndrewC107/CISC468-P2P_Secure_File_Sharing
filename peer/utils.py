# ────────────────────────────────────────────────────────────────
# utils.py – Small helper functions used across the application
# ────────────────────────────────────────────────────────────────

import socket
import time
import uuid

# Default read size per recv() call (used by recv_line)
_BUF_SIZE = 4096


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


def recv_line(sock: socket.socket) -> bytes:
    """
    Read bytes from a TCP socket until a newline character ('\\n') is found.

    This is the correct way to receive one NDJSON-framed message: each
    message ends with '\\n', so we accumulate recv() chunks until we see it.
    Handles the (rare on localhost) case where a message arrives in fragments.

    Returns the raw bytes including the trailing '\\n', or whatever was
    received before the connection closed.
    """
    buf = b""
    while True:
        chunk = sock.recv(_BUF_SIZE)
        if not chunk:           # remote side closed the connection
            break
        buf += chunk
        if b"\n" in buf:        # we have a complete NDJSON frame
            break
    return buf
