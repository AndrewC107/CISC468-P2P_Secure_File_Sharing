"""
contacts.py – Local contact and trust store for P2P Secure Share

Contacts are persisted in  contacts/contacts.json  at the project root.

Contact record format
──────────────────────
{
  "peer_id":       "550e8400-e29b-41d4-a716-446655440000",  ← stable UUID
  "peer_name":     "Alice",                                  ← display name
  "public_key":    "-----BEGIN PUBLIC KEY-----\\n...",       ← Ed25519 PEM (signing)
  "encryption_key": "-----BEGIN PUBLIC KEY-----\\n...",      ← X25519 PEM (encryption)
  "fingerprint":   "3A:F1:C2:...",                          ← SHA-256 of Ed25519 key
  "trusted":       false                                    ← explicit trust flag
}

encryption_key is the X25519 SubjectPublicKeyInfo PEM for the peer.
It is stored here so the server can look it up when encrypting a file
transfer for that peer.  It is set via IDENTITY_EXCHANGE (Phase 2+).

Trust model
───────────
Trust is NOT automatic.  When a peer sends IDENTITY_EXCHANGE their details
are saved with  trusted=False.  The local user must explicitly mark them
trusted after verifying the fingerprint out-of-band (phone call, in person,
etc.).

This follows the TOFU (Trust On First Use) model:
  • You save everyone you meet.
  • You only trust those you have independently verified.
  • A future signing/verification step can then refuse messages whose
    signature does not match the trusted public key.
"""

import json
from pathlib import Path
from typing import Any


_CONTACTS_DIR  = Path("contacts")
_CONTACTS_FILE = _CONTACTS_DIR / "contacts.json"


# ── Public API ────────────────────────────────────────────────────────────────

def save_contact(
    peer_id:        str,
    peer_name:      str,
    public_key:     str,
    fingerprint:    str,
    trusted:        bool = False,
    encryption_key: str | None = None,
) -> None:
    """
    Save or update a contact in the store.

    If a record with this peer_id already exists it is updated in place so
    that a peer can change their display name without creating duplicates.
    Otherwise a new entry is appended.

    trusted defaults to False – the user must call set_trusted() explicitly
    after verifying the fingerprint out-of-band.

    encryption_key is the X25519 SubjectPublicKeyInfo PEM for this peer.
    It is needed to derive the AES session key when sending them a file.
    If not provided (None), an existing value in the store is preserved.
    """
    data: dict[str, Any] = _load_all()
    contacts: list[dict] = data.setdefault("contacts", [])

    for entry in contacts:
        if entry.get("peer_id") == peer_id:
            entry["peer_name"]   = peer_name
            entry["public_key"]  = public_key
            entry["fingerprint"] = fingerprint
            if encryption_key is not None:
                entry["encryption_key"] = encryption_key
            # Never downgrade an already-trusted contact automatically
            if not entry.get("trusted", False):
                entry["trusted"] = trusted
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
    """Return the contact dict for peer_id, or None if not found."""
    for entry in _load_all().get("contacts", []):
        if entry.get("peer_id") == peer_id:
            return entry
    return None


def list_contacts() -> list[dict]:
    """Return all saved contact dicts (may be empty)."""
    return _load_all().get("contacts", [])


def set_trusted(peer_id: str, trusted: bool = True) -> bool:
    """
    Update the trust flag for a contact identified by peer_id.

    Returns True if the contact was found and updated, False if not found.

    Call this after the user has manually verified the fingerprint
    (e.g. confirmed the fingerprint over a phone call).
    """
    data = _load_all()
    for entry in data.get("contacts", []):
        if entry.get("peer_id") == peer_id:
            entry["trusted"] = trusted
            _save_all(data)
            return True
    return False


# ── Private helpers ───────────────────────────────────────────────────────────

def _load_all() -> dict[str, Any]:
    """Load the full contacts store from disk; return empty structure on error."""
    if not _CONTACTS_FILE.exists():
        return {"contacts": []}
    try:
        return json.loads(_CONTACTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"contacts": []}


def _save_all(data: dict[str, Any]) -> None:
    """Persist the full contacts store to disk."""
    _CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
    _CONTACTS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
