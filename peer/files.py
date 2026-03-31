# ────────────────────────────────────────────────────────────────────────────
# files.py – Helpers for the local file storage (shared + downloads)
#
# Storage layout
# ──────────────
#   storage/shared/      Files this peer is willing to share with others.
#                        Drop any plain file here, or use the "Import file
#                        to share" menu option to add an encrypted copy.
#   storage/downloads/   Files received from other peers.
#                        Always stored encrypted (.enc) when a StorageKey is
#                        active (Requirement 9).
#
# At-rest encryption (Requirement 9)
# ────────────────────────────────────
# When a StorageKey is provided, every file written to downloads/ is stored as
# an AES-256-GCM encrypted blob (nonce || ciphertext) with a ".enc" suffix.
# Files in shared/ may also be encrypted if imported via the menu; the helpers
# here transparently decrypt them before sending.
#
# Content integrity (Requirement 5)
# ───────────────────────────────────
# list_shared_files() now includes a "sha256" field for each file.  This hash
# is over the PLAINTEXT bytes so it is the same regardless of whether the file
# is stored in plain or encrypted form.  Receivers use this hash to verify that
# a file obtained from an alternate source matches what the original peer
# advertised.
#
# Base64 encoding
# ───────────────
# File contents travelling over the wire are still base64-encoded inside JSON.
# base64 is a text-safe encoding of arbitrary binary data (images, PDFs, …).
# Java's Base64.getEncoder() / getDecoder() are directly compatible.
# ────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from peer.config import DOWNLOADS_DIR, SHARED_DIR

if TYPE_CHECKING:
    from peer.storage import StorageKey


# ── Directory setup ───────────────────────────────────────────────────────────

def ensure_storage_dirs() -> None:
    """
    Create the shared and downloads folders if they do not already exist.

    Call this once at application startup (see main.py).
    It is also called automatically inside the save helpers so that the
    directories are always ready when a file arrives.
    """
    Path(SHARED_DIR).mkdir(parents=True, exist_ok=True)
    Path(DOWNLOADS_DIR).mkdir(parents=True, exist_ok=True)


# ── Shared-file helpers ───────────────────────────────────────────────────────

def list_shared_files(storage_key: "StorageKey | None" = None) -> list[dict]:
    """
    Return metadata for every file in the shared folder.

    Each entry is:
        {"filename": str, "size": int, "sha256": str}

    The sha256 is the hex digest of the PLAINTEXT bytes.  It is included in
    FILE_LIST_RESPONSE payloads so peers can verify file integrity when
    downloading from an alternate source (Requirement 5).

    Both plain files and .enc files (encrypted imports) are listed; .enc files
    are decrypted on-the-fly if storage_key is provided.  The ".enc" suffix is
    stripped from the filename so the wire format is always the original name.
    """
    shared = Path(SHARED_DIR)
    if not shared.exists():
        return []

    result: list[dict] = []
    seen_names: set[str] = set()  # avoid duplicates when both plain + .enc exist

    for f in sorted(shared.iterdir()):
        if not f.is_file():
            continue

        if f.suffix == ".enc":
            if storage_key is None:
                continue  # can't decrypt without the key – skip
            try:
                data = storage_key.decrypt(f.read_bytes())
            except Exception:
                continue  # corrupted or wrong key – skip
            display_name = f.stem   # strip .enc → original filename

        else:
            data = f.read_bytes()
            display_name = f.name

        if display_name in seen_names:
            continue
        seen_names.add(display_name)

        result.append({
            "filename": display_name,
            "size":     len(data),
            "sha256":   hashlib.sha256(data).hexdigest(),
        })

    return result


def read_shared_file_bytes(
    filename: str,
    storage_key: "StorageKey | None" = None,
) -> bytes | None:
    """
    Read a file from the shared folder and return its raw plaintext bytes.

    Look-up order:
      1. storage/shared/<filename>.enc  – encrypted import (decrypt if key given)
      2. storage/shared/<filename>      – plain file dropped manually

    Returns None if neither variant exists or decryption fails.
    """
    shared = Path(SHARED_DIR)
    enc_path   = shared / (filename + ".enc")
    plain_path = shared / filename

    if enc_path.exists() and storage_key is not None:
        try:
            return storage_key.decrypt(enc_path.read_bytes())
        except Exception:
            pass  # fall through to plain version

    if plain_path.exists() and plain_path.is_file():
        return plain_path.read_bytes()

    return None


def read_shared_file_b64(
    filename: str,
    storage_key: "StorageKey | None" = None,
) -> str | None:
    """
    Read a shared file and return its contents as a base64 string (for JSON).

    Returns None if the file does not exist.
    """
    data = read_shared_file_bytes(filename, storage_key)
    if data is None:
        return None
    return base64.b64encode(data).decode("utf-8")


def import_file_to_shared(
    source_path: str,
    storage_key: "StorageKey | None" = None,
) -> Path:
    """
    Copy an external file into storage/shared/, encrypting it if a StorageKey
    is active.

    This is the preferred way to add files to the share list when at-rest
    encryption is enabled.  It ensures the stored copy is protected even if
    the source file is later deleted.

    Returns the path of the stored file.
    """
    ensure_storage_dirs()
    src = Path(source_path)
    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {source_path}")

    data = src.read_bytes()
    shared = Path(SHARED_DIR)

    if storage_key is not None:
        dest = shared / (src.name + ".enc")
        dest.write_bytes(storage_key.encrypt(data))
    else:
        dest = shared / src.name
        dest.write_bytes(data)

    return dest


# ── Download helpers ──────────────────────────────────────────────────────────

def save_downloaded_file(filename: str, b64_data: str) -> Path:
    """
    Decode a base64 string and write the resulting bytes to storage/downloads/.

    LEGACY helper used by the unencrypted transfer path and tests.
    Prefer save_downloaded_file_secure() when a StorageKey is available.

    Returns the Path where the file was saved.
    """
    ensure_storage_dirs()
    destination = Path(DOWNLOADS_DIR) / filename
    decoded_bytes = base64.b64decode(b64_data)
    with open(destination, "wb") as f:
        f.write(decoded_bytes)
    return destination


def save_downloaded_file_secure(
    filename: str,
    plaintext: bytes,
    storage_key: "StorageKey | None" = None,
) -> Path:
    """
    Write plaintext bytes to storage/downloads/, encrypting if a StorageKey
    is active (Requirement 9).

    When storage_key is provided the file is stored as AES-256-GCM encrypted
    blob with a ".enc" suffix.  When it is None the raw bytes are written
    (backward compatible with builds that have no passphrase).

    Returns the Path where the file was saved.
    """
    ensure_storage_dirs()

    if storage_key is not None:
        dest = Path(DOWNLOADS_DIR) / (filename + ".enc")
        dest.write_bytes(storage_key.encrypt(plaintext))
    else:
        dest = Path(DOWNLOADS_DIR) / filename
        dest.write_bytes(plaintext)

    return dest


def list_downloaded_files(storage_key: "StorageKey | None" = None) -> list[dict]:
    """
    Return metadata for files in downloads/, decrypting .enc entries.

    Each entry: {"filename": str, "size": int}
    The ".enc" suffix is stripped so the user sees the original filename.
    """
    downloads = Path(DOWNLOADS_DIR)
    if not downloads.exists():
        return []

    result: list[dict] = []
    seen: set[str] = set()

    for f in sorted(downloads.iterdir()):
        if not f.is_file():
            continue

        if f.suffix == ".enc":
            display_name = f.stem
            if storage_key is not None:
                try:
                    data = storage_key.decrypt(f.read_bytes())
                    size = len(data)
                except Exception:
                    size = f.stat().st_size  # fallback: show encrypted size
            else:
                size = f.stat().st_size
        else:
            display_name = f.name
            size = f.stat().st_size

        if display_name not in seen:
            seen.add(display_name)
            result.append({"filename": display_name, "size": size})

    return result
