# ─────────────────────────────────────────────────────────────────────────────
# crypto.py – Ed25519 / X25519 / AES-GCM / HKDF (matches java-client CryptoService)
# ─────────────────────────────────────────────────────────────────────────────

import base64
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)


_IDENTITY_DIR           = Path("identity")
_ED25519_PRIVATE_FILE   = _IDENTITY_DIR / "private_key.pem"
_ED25519_PUBLIC_FILE    = _IDENTITY_DIR / "public_key.pem"
_X25519_PRIVATE_FILE    = _IDENTITY_DIR / "x25519_private_key.pem"
_X25519_PUBLIC_FILE     = _IDENTITY_DIR / "x25519_public_key.pem"

_HKDF_INFO = b"P2P-SecureShare-v1-file"


@dataclass
class LocalIdentity:
    """Long-term signing and encryption keys plus PEM strings and Ed25519 fingerprint."""
    signing_private_key:       Ed25519PrivateKey
    signing_public_key_pem:    str
    fingerprint:               str
    encryption_private_key:    X25519PrivateKey
    encryption_public_key_pem: str


def load_or_generate_keys() -> LocalIdentity:
    """Load Ed25519 and X25519 key pairs from identity/, or create and save them."""
    _IDENTITY_DIR.mkdir(parents=True, exist_ok=True)

    if _ED25519_PRIVATE_FILE.exists() and _ED25519_PUBLIC_FILE.exists():
        signing_priv = _load_ed25519_private()
        signing_pub_pem = _ED25519_PUBLIC_FILE.read_text(encoding="utf-8")
    else:
        signing_priv = Ed25519PrivateKey.generate()
        signing_pub_pem = _save_ed25519_pair(signing_priv)

    if _X25519_PRIVATE_FILE.exists() and _X25519_PUBLIC_FILE.exists():
        enc_priv = _load_x25519_private()
        enc_pub_pem = _X25519_PUBLIC_FILE.read_text(encoding="utf-8")
    else:
        enc_priv = X25519PrivateKey.generate()
        enc_pub_pem = _save_x25519_pair(enc_priv)

    fingerprint = compute_fingerprint(signing_pub_pem)
    return LocalIdentity(
        signing_private_key=signing_priv,
        signing_public_key_pem=signing_pub_pem,
        fingerprint=fingerprint,
        encryption_private_key=enc_priv,
        encryption_public_key_pem=enc_pub_pem,
    )


def compute_fingerprint(public_key_pem: str) -> str:
    """SHA-256 of the Ed25519 SPKI DER, formatted as colon-separated hex (uppercase)."""
    try:
        pub_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid PEM public key: {exc}") from exc

    der_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import hashlib
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def format_fingerprint_for_display(fingerprint: str) -> str:
    """Split the fingerprint into two 16-byte lines for printing."""
    parts = fingerprint.split(":")
    row1 = ":".join(parts[:16])
    row2 = ":".join(parts[16:])
    return f"  {row1}\n  {row2}"


def generate_ephemeral_x25519() -> X25519PrivateKey:
    """Create a one-time X25519 key for a single file transfer."""
    return X25519PrivateKey.generate()


def x25519_public_key_to_raw(key: X25519PrivateKey) -> bytes:
    """Raw 32-byte encoding of the public side of an X25519 private key."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_raw_from_pem(pem: str) -> bytes:
    """Convert an X25519 SPKI PEM to raw 32-byte u coordinate."""
    pub_key = load_pem_public_key(pem.encode("utf-8"))
    return pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ecdh_derive_key(local_private: X25519PrivateKey, peer_raw_public: bytes) -> bytes:
    """X25519 ECDH then HKDF-SHA256 to a 32-byte AES key (same as Java client)."""
    peer_public = X25519PublicKey.from_public_bytes(peer_raw_public)
    shared_secret = local_private.exchange(peer_public)

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(shared_secret)
    return key


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt; returns (12-byte nonce, ciphertext including tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-256-GCM decrypt; raises InvalidTag if the tag fails."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def sign_transfer(
    signing_key:        Ed25519PrivateKey,
    filename:           str,
    ephemeral_pub_bytes: bytes,
    nonce:              bytes,
    ciphertext:         bytes,
) -> bytes:
    """Ed25519-sign the transfer binding (filename, eph key, nonce, ciphertext)."""
    return signing_key.sign(_build_sign_target(filename, ephemeral_pub_bytes, nonce, ciphertext))


def verify_transfer_signature(
    signing_public_key_pem: str,
    filename:               str,
    ephemeral_pub_bytes:    bytes,
    nonce:                  bytes,
    ciphertext:             bytes,
    signature:              bytes,
) -> bool:
    """Verify a transfer signature; returns False on any error."""
    try:
        pub_key = load_pem_public_key(signing_public_key_pem.encode("utf-8"))
        if not isinstance(pub_key, Ed25519PublicKey):
            return False
        signed_data = _build_sign_target(filename, ephemeral_pub_bytes, nonce, ciphertext)
        pub_key.verify(signature, signed_data)
        return True
    except (InvalidSignature, Exception):
        return False


def _build_sign_target(
    filename:           str,
    ephemeral_pub_bytes: bytes,
    nonce:              bytes,
    ciphertext:         bytes,
) -> bytes:
    """Canonical signed payload: u16 filename len + name + 32-byte eph + 12-byte nonce + ciphertext."""
    fname_bytes = filename.encode("utf-8")
    return (
        len(fname_bytes).to_bytes(2, "big")
        + fname_bytes
        + ephemeral_pub_bytes
        + nonce
        + ciphertext
    )


def _save_ed25519_pair(private_key: Ed25519PrivateKey) -> str:
    """Write Ed25519 PKCS#8 + SPKI PEM files; return public PEM text."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _ED25519_PRIVATE_FILE.write_bytes(private_pem)
    _ED25519_PUBLIC_FILE.write_bytes(public_pem)
    return public_pem.decode("utf-8")


def _save_x25519_pair(private_key: X25519PrivateKey) -> str:
    """Write X25519 PKCS#8 + SPKI PEM files; return public PEM text."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _X25519_PRIVATE_FILE.write_bytes(private_pem)
    _X25519_PUBLIC_FILE.write_bytes(public_pem)
    return public_pem.decode("utf-8")


def _load_ed25519_private() -> Ed25519PrivateKey:
    """Load Ed25519 private key from disk or raise if wrong type."""
    key = load_pem_private_key(_ED25519_PRIVATE_FILE.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Stored signing key is not Ed25519 – delete identity/ and restart")
    return key


def _load_x25519_private() -> X25519PrivateKey:
    """Load X25519 private key from disk or raise if wrong type."""
    key = load_pem_private_key(_X25519_PRIVATE_FILE.read_bytes(), password=None)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError("Stored encryption key is not X25519 – delete identity/ and restart")
    return key


def rotate_keys(old_identity: "LocalIdentity") -> "LocalIdentity":
    """Generate new Ed25519/X25519 pairs on disk and return a new LocalIdentity (old_identity unchanged)."""
    new_signing_priv = Ed25519PrivateKey.generate()
    new_signing_pub_pem = _save_ed25519_pair(new_signing_priv)

    new_enc_priv = X25519PrivateKey.generate()
    new_enc_pub_pem = _save_x25519_pair(new_enc_priv)

    new_fingerprint = compute_fingerprint(new_signing_pub_pem)

    return LocalIdentity(
        signing_private_key=new_signing_priv,
        signing_public_key_pem=new_signing_pub_pem,
        fingerprint=new_fingerprint,
        encryption_private_key=new_enc_priv,
        encryption_public_key_pem=new_enc_pub_pem,
    )


def sign_key_rotation(
    old_signing_key:       Ed25519PrivateKey,
    old_fingerprint:       str,
    new_public_key_pem:    str,
    new_encryption_key_pem: str,
    new_fingerprint:       str,
) -> bytes:
    """Sign KEY_ROTATION payload with the old Ed25519 private key."""
    data = _build_rotation_sign_target(
        old_fingerprint, new_public_key_pem, new_encryption_key_pem, new_fingerprint
    )
    return old_signing_key.sign(data)


def verify_key_rotation(
    old_public_key_pem:    str,
    old_fingerprint:       str,
    new_public_key_pem:    str,
    new_encryption_key_pem: str,
    new_fingerprint:       str,
    signature:             bytes,
) -> bool:
    """Verify KEY_ROTATION against the stored old public key."""
    try:
        pub_key = load_pem_public_key(old_public_key_pem.encode("utf-8"))
        data = _build_rotation_sign_target(
            old_fingerprint, new_public_key_pem, new_encryption_key_pem, new_fingerprint
        )
        pub_key.verify(signature, data)  # type: ignore[arg-type]
        return True
    except (InvalidSignature, Exception):
        return False


def _build_rotation_sign_target(
    old_fingerprint:       str,
    new_public_key_pem:    str,
    new_encryption_key_pem: str,
    new_fingerprint:       str,
) -> bytes:
    """Bytes signed for rotation: KEY_ROTATION\\0 fields separated by \\0."""
    return (
        b"KEY_ROTATION\x00"
        + old_fingerprint.encode("utf-8")       + b"\x00"
        + new_public_key_pem.encode("utf-8")    + b"\x00"
        + new_encryption_key_pem.encode("utf-8") + b"\x00"
        + new_fingerprint.encode("utf-8")
    )
