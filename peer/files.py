# ─────────────────────────────────────────────────────────────────────────────
# files.py – storage/shared and storage/downloads helpers (matches Java FileStore)
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from peer.config import DOWNLOADS_DIR, SHARED_DIR

if TYPE_CHECKING:
    from peer.storage import StorageKey


def ensure_storage_dirs() -> None:
    """Create shared/ and downloads/ if missing."""
    Path(SHARED_DIR).mkdir(parents=True, exist_ok=True)
    Path(DOWNLOADS_DIR).mkdir(parents=True, exist_ok=True)


def list_shared_files(storage_key: "StorageKey | None" = None) -> list[dict]:
    """List shareable files as {filename, size, sha256} (plaintext hash; decrypts .enc when keyed)."""
    shared = Path(SHARED_DIR)
    if not shared.exists():
        return []

    result: list[dict] = []
    seen_names: set[str] = set()

    for f in sorted(shared.iterdir()):
        if not f.is_file():
            continue

        if f.suffix == ".enc":
            if storage_key is None:
                continue
            try:
                data = storage_key.decrypt(f.read_bytes())
            except Exception:
                continue
            display_name = f.stem

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
    """Read plaintext bytes for a shared file (.enc first if key present, else plain path)."""
    shared = Path(SHARED_DIR)
    enc_path   = shared / (filename + ".enc")
    plain_path = shared / filename

    if enc_path.exists() and storage_key is not None:
        try:
            return storage_key.decrypt(enc_path.read_bytes())
        except Exception:
            pass

    if plain_path.exists() and plain_path.is_file():
        return plain_path.read_bytes()

    return None


def read_shared_file_b64(
    filename: str,
    storage_key: "StorageKey | None" = None,
) -> str | None:
    """Same as read_shared_file_bytes but base64-encoded for JSON."""
    data = read_shared_file_bytes(filename, storage_key)
    if data is None:
        return None
    return base64.b64encode(data).decode("utf-8")


def import_file_to_shared(
    source_path: str,
    storage_key: "StorageKey | None" = None,
) -> Path:
    """Copy a file into shared/; encrypt to .enc when storage_key is set."""
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


def save_downloaded_file(filename: str, b64_data: str) -> Path:
    """Decode base64 and write a plain file under downloads/ (legacy path)."""
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
    """Write received plaintext to downloads/, optionally as AES-GCM .enc."""
    ensure_storage_dirs()

    if storage_key is not None:
        dest = Path(DOWNLOADS_DIR) / (filename + ".enc")
        dest.write_bytes(storage_key.encrypt(plaintext))
    else:
        dest = Path(DOWNLOADS_DIR) / filename
        dest.write_bytes(plaintext)

    return dest


def list_downloaded_files(storage_key: "StorageKey | None" = None) -> list[dict]:
    """List downloads as {filename, size}; decrypts .enc for size when keyed."""
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
                    size = f.stat().st_size
            else:
                size = f.stat().st_size
        else:
            display_name = f.name
            size = f.stat().st_size

        if display_name not in seen:
            seen.add(display_name)
            result.append({"filename": display_name, "size": size})

    return result
