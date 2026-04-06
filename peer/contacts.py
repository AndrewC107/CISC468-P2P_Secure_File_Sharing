# ─────────────────────────────────────────────────────────────────────────────
# contacts.py – Persisted contacts in contacts/contacts.json (matches Java ContactStore)
# ─────────────────────────────────────────────────────────────────────────────

import json
from pathlib import Path
from typing import Any


_CONTACTS_DIR  = Path("contacts")
_CONTACTS_FILE = _CONTACTS_DIR / "contacts.json"


def save_contact(
    peer_id:        str,
    peer_name:      str,
    public_key:     str,
    fingerprint:    str,
    trusted:        bool = False,
    encryption_key: str | None = None,
) -> None:
    """Insert or update a contact; merges by peer_id or matching fingerprint."""
    data: dict[str, Any] = _load_all()
    contacts: list[dict] = data.setdefault("contacts", [])

    def _update_entry(entry: dict) -> None:
        entry["peer_id"]    = peer_id
        entry["peer_name"]  = peer_name
        entry["public_key"] = public_key
        entry["fingerprint"] = fingerprint
        if encryption_key is not None:
            entry["encryption_key"] = encryption_key
        if not entry.get("trusted", False):
            entry["trusted"] = trusted

    for entry in contacts:
        if entry.get("peer_id") == peer_id:
            _update_entry(entry)
            _save_all(data)
            return

    if fingerprint:
        for entry in contacts:
            if entry.get("fingerprint") == fingerprint:
                _update_entry(entry)
                _save_all(data)
                return

    contacts.append({
        "peer_id":        peer_id,
        "peer_name":      peer_name,
        "public_key":     public_key,
        "encryption_key": encryption_key or "",
        "fingerprint":    fingerprint,
        "trusted":        trusted,
    })
    _save_all(data)


def get_contact(peer_id: str) -> dict | None:
    """Look up one contact by peer_id."""
    for entry in _load_all().get("contacts", []):
        if entry.get("peer_id") == peer_id:
            return entry
    return None


def list_contacts() -> list[dict]:
    """Return all contact records."""
    return _load_all().get("contacts", [])


def get_contact_by_fingerprint(fingerprint: str) -> dict | None:
    """Find a contact by Ed25519 fingerprint (used for KEY_ROTATION lookup)."""
    for entry in _load_all().get("contacts", []):
        if entry.get("fingerprint") == fingerprint:
            return entry
    return None


def update_contact_keys(
    peer_id:            str,
    new_public_key:     str,
    new_encryption_key: str,
    new_fingerprint:    str,
) -> bool:
    """Replace signing/encryption PEMs and fingerprint after verified rotation."""
    data = _load_all()
    for entry in data.get("contacts", []):
        if entry.get("peer_id") == peer_id:
            entry["public_key"]     = new_public_key
            entry["encryption_key"] = new_encryption_key
            entry["fingerprint"]    = new_fingerprint
            _save_all(data)
            return True
    return False


def set_trusted(peer_id: str, trusted: bool = True) -> bool:
    """Set the trusted flag for a contact; returns whether the peer_id was found."""
    data = _load_all()
    for entry in data.get("contacts", []):
        if entry.get("peer_id") == peer_id:
            entry["trusted"] = trusted
            _save_all(data)
            return True
    return False


def _load_all() -> dict[str, Any]:
    """Load contacts.json or return an empty store."""
    if not _CONTACTS_FILE.exists():
        return {"contacts": []}
    try:
        return json.loads(_CONTACTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"contacts": []}


def _save_all(data: dict[str, Any]) -> None:
    """Write contacts.json."""
    _CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
    _CONTACTS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
