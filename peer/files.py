# ────────────────────────────────────────────────────────────────────────────
# files.py – Helpers for the local file storage (shared + downloads)
#
# Storage layout
# ──────────────
#   storage/shared/      Files this peer is willing to share with others.
#                        Drop any file here before starting the client.
#   storage/downloads/   Files received from other peers.
#
# Base64 encoding
# ───────────────
# File contents are sent inside JSON as a base64 string.
# base64 is a text-safe encoding of arbitrary binary data, so ANY file type
# (images, PDFs, binaries, etc.) can be carried in a plain JSON field without
# corrupting the JSON.  The receiver decodes it back to the original bytes.
#
# Java compatibility
# ──────────────────
# Java's java.util.Base64.getEncoder().encodeToString() and
# Base64.getDecoder().decode() are directly compatible with Python's
# base64.b64encode / b64decode (both use the standard RFC 4648 alphabet).
# ────────────────────────────────────────────────────────────────────────────

import base64
from pathlib import Path

from peer.config import DOWNLOADS_DIR, SHARED_DIR


# ── Directory setup ───────────────────────────────────────────────────────────

def ensure_storage_dirs() -> None:
    """
    Create the shared and downloads folders if they do not already exist.

    Call this once at application startup (see main.py).
    It is also called automatically inside save_downloaded_file() so that
    the downloads folder is always ready when a file arrives.
    """
    Path(SHARED_DIR).mkdir(parents=True, exist_ok=True)
    Path(DOWNLOADS_DIR).mkdir(parents=True, exist_ok=True)


# ── Shared-file helpers ───────────────────────────────────────────────────────

def list_shared_files() -> list[dict]:
    """
    Return metadata for every file in the shared folder.

    Each entry is a dict:
        {"filename": str, "size": int}   # size is in bytes

    Returns an empty list if the folder does not exist yet.
    This format is used in FILE_LIST_RESPONSE payloads and is easy to
    parse in any language (Java, Go, etc.).
    """
    shared = Path(SHARED_DIR)
    if not shared.exists():
        return []
    return [
        {"filename": f.name, "size": f.stat().st_size}
        for f in sorted(shared.iterdir())   # sorted for a stable, predictable order
        if f.is_file()
    ]


def read_shared_file_b64(filename: str) -> str | None:
    """
    Read a file from the shared folder and return its contents as a
    base64-encoded UTF-8 string.

    Returns None if the file does not exist in the shared folder.

    Security note: `filename` is joined to SHARED_DIR using Path.  Paths
    that escape the shared directory (e.g. "../secret.txt") are not prevented
    here; a future version should add path-traversal validation.
    """
    path = Path(SHARED_DIR) / filename
    if not path.exists() or not path.is_file():
        return None
    with open(path, "rb") as f:
        raw_bytes = f.read()
    # base64.b64encode returns bytes; decode to str so it fits in a JSON field
    return base64.b64encode(raw_bytes).decode("utf-8")


# ── Download helpers ──────────────────────────────────────────────────────────

def save_downloaded_file(filename: str, b64_data: str) -> Path:
    """
    Decode a base64 string and write the resulting bytes to storage/downloads/.

    Creates the downloads folder if it does not exist (safe to call any time).
    Returns the Path where the file was saved.

    Raises:
        ValueError  – if b64_data is not valid base64
        OSError     – if the file cannot be written (permissions, disk full…)
    """
    ensure_storage_dirs()
    destination = Path(DOWNLOADS_DIR) / filename
    decoded_bytes = base64.b64decode(b64_data)
    with open(destination, "wb") as f:
        f.write(decoded_bytes)
    return destination
