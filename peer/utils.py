# ────────────────────────────────────────────────────────────────
# utils.py – Small helpers (UUID, local IP, NDJSON recv)
# ────────────────────────────────────────────────────────────────

import socket
import time
import uuid

_BUF_SIZE = 4096


def generate_peer_id() -> str:
    """Return a new UUID string for this process session."""
    return str(uuid.uuid4())


def get_local_ip() -> str:
    """Best-effort LAN IP via UDP route lookup; falls back to 127.0.0.1."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def current_timestamp() -> float:
    """Unix time as float seconds."""
    return time.time()


def recv_line(sock: socket.socket) -> bytes:
    """Read from sock until '\\n' or EOF (one NDJSON frame)."""
    buf = b""
    while True:
        chunk = sock.recv(_BUF_SIZE)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf:
            break
    return buf
