# ─────────────────────────────────────────────────────────────────────────────
# catalog.py – Cached file lists per peer for offline / alternate-source download
# ─────────────────────────────────────────────────────────────────────────────

import json
from pathlib import Path

_CATALOG_FILE = Path("contacts") / "file_catalog.json"

# { peer_id: { filename: { peer_name, size, sha256 } } }
_catalog: dict[str, dict[str, dict]] = {}


def update(peer_id: str, peer_name: str, file_list: list[dict]) -> None:
    """Store or replace this peer's advertised file list and persist to disk."""
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
    """Return the sha256 we last saw for this file from that peer, or None if unknown/empty."""
    entry = _catalog.get(peer_id, {}).get(filename)
    if entry is None:
        return None
    h = entry.get("sha256", "")
    return h if h else None


def get_peer_files(peer_id: str) -> list[dict]:
    """Return cached catalog rows for one peer as dicts (filename, peer_name, size, sha256)."""
    files = _catalog.get(peer_id, {})
    return [{"filename": fn, **meta} for fn, meta in files.items()]


def find_alternate_peers(
    filename:         str,
    expected_sha256:  str,
    offline_peer_id:  str,
    known_peer_ids:   list[str],
) -> list[str]:
    """List other known peers who advertised the same filename and sha256 (for fallback download)."""
    candidates: list[str] = []
    for pid in known_peer_ids:
        if pid == offline_peer_id:
            continue
        entry = _catalog.get(pid, {}).get(filename)
        if entry and entry.get("sha256") == expected_sha256:
            candidates.append(pid)
    return candidates


def get_all_peers_for_file(filename: str) -> list[dict]:
    """Return every catalog entry that includes this filename."""
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
    """Return peer_ids that appear in the catalog."""
    return list(_catalog.keys())


def _persist() -> None:
    """Write the in-memory catalog to contacts/file_catalog.json."""
    try:
        _CATALOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CATALOG_FILE.write_text(json.dumps(_catalog, indent=2), encoding="utf-8")
    except OSError:
        pass


def _load() -> None:
    """Load catalog from disk on import."""
    global _catalog
    if _CATALOG_FILE.exists():
        try:
            _catalog = json.loads(_CATALOG_FILE.read_text(encoding="utf-8"))
            return
        except (json.JSONDecodeError, OSError):
            pass
    _catalog = {}


_load()
