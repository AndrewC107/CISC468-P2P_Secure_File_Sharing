"""
catalog.py – File availability catalog for offline peer fallback (Requirement 5)

Requirement 5 says:
    "If peer A is offline but peer B already had peer A's list of available
     files, peer B may find another peer C that had previously downloaded the
     file from peer A, and request the file from them instead.  But peer B
     must be able to verify that the file has not been tampered with."

How this module addresses that requirement
──────────────────────────────────────────
1. Every time peer B receives a FILE_LIST_RESPONSE it calls catalog.update()
   to record each filename and its SHA-256 hash (of the plaintext content)
   against the sender's peer_id.

2. When peer B wants a file from peer A but the connection fails (A is offline),
   it calls catalog.find_alternate_peers() to find any other known peer that
   advertised the same file with the same SHA-256 hash.

3. After downloading from the alternate peer C, the plaintext is hashed and
   compared to A's advertised value.  If they differ the file is discarded and
   a security warning is shown (Requirement 10).

Persistence
───────────
The catalog is kept in memory (updated on every FILE_LIST_RESPONSE) and is
also written to contacts/file_catalog.json so it survives application restarts.
This lets peer B remember A's file list even when A is offline.

Catalog structure (both in memory and on disk):
{
  "<peer_id>": {
    "<filename>": {
      "peer_name": "Alice",
      "size":      1234,
      "sha256":    "abc123..."
    }
  }
}
"""

import json
from pathlib import Path

_CATALOG_FILE = Path("contacts") / "file_catalog.json"

# In-memory catalog: {peer_id: {filename: {peer_name, size, sha256}}}
_catalog: dict[str, dict[str, dict]] = {}


# ── Public API ────────────────────────────────────────────────────────────────

def update(peer_id: str, peer_name: str, file_list: list[dict]) -> None:
    """
    Record (or refresh) a peer's advertised file list.

    file_list entries should contain at minimum:
        {"filename": str, "size": int, "sha256": str}

    Old Java clients that send FILE_LIST_RESPONSE without sha256 are handled
    gracefully – the sha256 defaults to "" and integrity verification will be
    skipped for those files.

    Call this every time a FILE_LIST_RESPONSE is received so the catalog stays
    current.
    """
    _catalog[peer_id] = {
        entry["filename"]: {
            "peer_name": peer_name,
            "size":      entry.get("size", 0),
            "sha256":    entry.get("sha256", ""),
        }
        for entry in file_list
        if "filename" in entry
    }
    _persist()


def get_expected_hash(peer_id: str, filename: str) -> str | None:
    """
    Return the SHA-256 hash that peer_id advertised for filename.

    Returns None if the peer or filename is not in the catalog, or if the
    stored hash is empty (peer sent no sha256 field).
    """
    entry = _catalog.get(peer_id, {}).get(filename)
    if entry is None:
        return None
    h = entry.get("sha256", "")
    return h if h else None


def find_alternate_peers(
    filename:         str,
    expected_sha256:  str,
    offline_peer_id:  str,
    known_peer_ids:   list[str],
) -> list[str]:
    """
    Return peer_ids (excluding offline_peer_id) that have advertised a file
    with the same name AND the same SHA-256 hash.

    Both conditions must match because two files with the same name but
    different hashes are NOT the same file – using them for fallback would
    violate the integrity requirement.

    Parameters
    ----------
    filename        : the file the user originally wanted
    expected_sha256 : hash from the offline peer's catalog entry
    offline_peer_id : peer to exclude from results (they're offline)
    known_peer_ids  : currently visible peers from the discovery table
    """
    candidates: list[str] = []
    for pid in known_peer_ids:
        if pid == offline_peer_id:
            continue
        entry = _catalog.get(pid, {}).get(filename)
        if entry and entry.get("sha256") == expected_sha256:
            candidates.append(pid)
    return candidates


def get_all_peers_for_file(filename: str) -> list[dict]:
    """
    Return all catalog entries that have advertised filename.

    Each entry: {"peer_id": str, "peer_name": str, "sha256": str, "size": int}
    Useful for showing the user which peers have a file.
    """
    results: list[dict] = []
    for pid, files in _catalog.items():
        if filename in files:
            info = files[filename]
            results.append({
                "peer_id":   pid,
                "peer_name": info.get("peer_name", "?"),
                "sha256":    info.get("sha256", ""),
                "size":      info.get("size", 0),
            })
    return results


def list_known_peers() -> list[str]:
    """Return peer_ids that have at least one entry in the catalog."""
    return list(_catalog.keys())


# ── Private helpers ───────────────────────────────────────────────────────────

def _persist() -> None:
    """Write the in-memory catalog to disk."""
    try:
        _CATALOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CATALOG_FILE.write_text(json.dumps(_catalog, indent=2), encoding="utf-8")
    except OSError:
        pass  # non-fatal; in-memory catalog is still usable


def _load() -> None:
    """Populate the in-memory catalog from disk (called once on import)."""
    global _catalog
    if _CATALOG_FILE.exists():
        try:
            _catalog = json.loads(_CATALOG_FILE.read_text(encoding="utf-8"))
            return
        except (json.JSONDecodeError, OSError):
            pass
    _catalog = {}


_load()
