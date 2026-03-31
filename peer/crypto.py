"""
crypto.py – Cryptographic identity and file-transfer helpers for P2P Secure Share

─────────────────────────────────────────────────────────────────────────────
Security properties provided by this module
─────────────────────────────────────────────────────────────────────────────

  CONFIDENTIALITY  – AES-256-GCM encrypts every file in transit.
                     Only the intended receiver (holder of the X25519 private
                     key) can reconstruct the symmetric key and decrypt.

  INTEGRITY        – AES-256-GCM's 128-bit authentication tag detects any
                     modification to the ciphertext before decryption.

  AUTHENTICATION   – The sender signs the transfer metadata (filename, keys,
                     nonce, ciphertext) using their long-term Ed25519 private
                     key.  The receiver verifies the signature using the
                     sender's Ed25519 public key stored in their contact list.

  PERFECT FORWARD  – The sender generates a FRESH ephemeral X25519 key pair
  SECRECY (PFS)      for EVERY file transfer.  The symmetric key is derived
                     from ECDH(sender_ephemeral_private, receiver_static_public).
                     Because the ephemeral private key is never stored, an
                     attacker who later compromises the sender's long-term
                     Ed25519 key cannot decrypt past transfers.  Compromising
                     the receiver's long-term X25519 key would still expose
                     those sessions; full double-ephemeral PFS (like TLS 1.3)
                     would require a second round-trip and is a future upgrade.

─────────────────────────────────────────────────────────────────────────────
Key roles (two key types per peer)
─────────────────────────────────────────────────────────────────────────────

  Ed25519   SIGNING KEY  (long-term)
    Purpose : authenticate the sender of a file transfer
    Private : only ever on disk in identity/private_key.pem
    Public  : shared via IDENTITY_EXCHANGE, stored in contacts

  X25519    ENCRYPTION KEY  (long-term static + per-transfer ephemeral)
    Purpose : derive the per-transfer AES session key via ECDH
    Static  : on disk in identity/x25519_private_key.pem (shared via IDENTITY_EXCHANGE)
    Ephemeral: generated fresh per transfer (never stored)

─────────────────────────────────────────────────────────────────────────────
Java interoperability notes
─────────────────────────────────────────────────────────────────────────────

  Ed25519 keys are stored as PKCS#8 (private) and SubjectPublicKeyInfo / X.509
  (public) PEM, readable by Java 15+ via:
    KeyFactory.getInstance("Ed25519")
    new PKCS8EncodedKeySpec(...)  /  new X509EncodedKeySpec(...)

  X25519 keys use the same PEM format, readable via:
    KeyFactory.getInstance("XDH")
    new PKCS8EncodedKeySpec(...)  /  new X509EncodedKeySpec(...)

  Ephemeral public keys inside FILE_TRANSFER messages are transmitted as
  raw 32 bytes (base64-encoded).  A Java client recovers the key with:
    new XECPublicKeySpec(new BigInteger(1, rawBytes), NamedParameterSpec.X25519)
  or by prepending the 12-byte SubjectPublicKeyInfo header for X25519 and
  using X509EncodedKeySpec.

  The signed-data byte layout is documented in _build_sign_target() so any
  language can replicate it deterministically.
"""

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


# ── Key storage paths ─────────────────────────────────────────────────────────
# All persistent keys live in identity/ at the project root.
# This directory is in .gitignore so private keys are never committed.

_IDENTITY_DIR           = Path("identity")
_ED25519_PRIVATE_FILE   = _IDENTITY_DIR / "private_key.pem"
_ED25519_PUBLIC_FILE    = _IDENTITY_DIR / "public_key.pem"
_X25519_PRIVATE_FILE    = _IDENTITY_DIR / "x25519_private_key.pem"
_X25519_PUBLIC_FILE     = _IDENTITY_DIR / "x25519_public_key.pem"

# HKDF context string – binds derived keys to this application and version.
# A Java client must use the same bytes: "P2P-SecureShare-v1-file".getBytes("UTF-8")
_HKDF_INFO = b"P2P-SecureShare-v1-file"


# ── LocalIdentity dataclass ───────────────────────────────────────────────────

@dataclass
class LocalIdentity:
    """
    All key material for this local peer.

    signing_private_key      – Ed25519 private key; used to sign outgoing transfers
    signing_public_key_pem   – Ed25519 public key as PEM string; shared with peers
    fingerprint              – SHA-256 fingerprint of the Ed25519 public key
    encryption_private_key   – X25519 private key; used to decrypt incoming files
    encryption_public_key_pem – X25519 public key as PEM string; shared with peers
    """
    signing_private_key:       Ed25519PrivateKey
    signing_public_key_pem:    str
    fingerprint:               str
    encryption_private_key:    X25519PrivateKey
    encryption_public_key_pem: str


# ── Key lifecycle ─────────────────────────────────────────────────────────────

def load_or_generate_keys() -> LocalIdentity:
    """
    Load the local peer's key material from disk, or generate it on first run.

    Ed25519 and X25519 keys are each stored as PKCS#8 PEM (private) and
    SubjectPublicKeyInfo PEM (public) under identity/.

    On first run  : generates both key pairs, saves them, returns identity.
    On later runs : loads saved keys – identity is stable across restarts.
    """
    _IDENTITY_DIR.mkdir(parents=True, exist_ok=True)

    # ── Ed25519 signing key pair ─────────────────────────────────────────────
    if _ED25519_PRIVATE_FILE.exists() and _ED25519_PUBLIC_FILE.exists():
        signing_priv = _load_ed25519_private()
        signing_pub_pem = _ED25519_PUBLIC_FILE.read_text(encoding="utf-8")
    else:
        signing_priv = Ed25519PrivateKey.generate()
        signing_pub_pem = _save_ed25519_pair(signing_priv)

    # ── X25519 encryption key pair ───────────────────────────────────────────
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


# ── Fingerprinting ────────────────────────────────────────────────────────────

def compute_fingerprint(public_key_pem: str) -> str:
    """
    Derive a SHA-256 fingerprint from a PEM Ed25519 public key.

    Steps:
      1. Load the PEM → public key object.
      2. Re-export as DER (SubjectPublicKeyInfo binary) – canonical form
         that both Python and Java produce identically.
      3. Compute SHA-256 over the DER bytes.
      4. Format as uppercase colon-separated hex pairs (SSH fingerprint style).

    Java equivalent:
      byte[] der = edPubKey.getEncoded();   // SubjectPublicKeyInfo DER
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(der);       // same bytes → same fingerprint
    """
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
    """Split a 32-pair fingerprint into two readable lines of 16 pairs each."""
    parts = fingerprint.split(":")
    row1 = ":".join(parts[:16])
    row2 = ":".join(parts[16:])
    return f"  {row1}\n  {row2}"


# ── X25519 key helpers ────────────────────────────────────────────────────────

def generate_ephemeral_x25519() -> X25519PrivateKey:
    """
    Generate a fresh ephemeral X25519 key pair for ONE file transfer.

    [PERFECT FORWARD SECRECY]
    The returned key is used for one transfer and then discarded.  The
    caller must NOT store this key anywhere – it lives only in RAM for the
    duration of the transfer.  Because it is never written to disk, an
    attacker who later reads the disk cannot reconstruct past session keys.
    """
    return X25519PrivateKey.generate()


def x25519_public_key_to_raw(key: X25519PrivateKey) -> bytes:
    """Return the X25519 public key as raw 32 bytes (for embedding in JSON)."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_raw_from_pem(pem: str) -> bytes:
    """
    Convert a SubjectPublicKeyInfo PEM X25519 public key to raw 32 bytes.

    The raw form is sent inside FILE_TRANSFER JSON.  The receiver reconstructs
    the key with X25519PublicKey.from_public_bytes(rawBytes).

    Java equivalent:
      byte[] raw = ((XECPublicKey)xdhPubKey).getU().toByteArray();
      // Note: BigInteger.toByteArray() may prepend a 0x00 sign byte; strip it
      // if raw.length == 33 and raw[0] == 0. X25519 always fits in 32 bytes.
    """
    pub_key = load_pem_public_key(pem.encode("utf-8"))
    return pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ── Shared-key derivation (ECDH + HKDF) ──────────────────────────────────────

def ecdh_derive_key(local_private: X25519PrivateKey, peer_raw_public: bytes) -> bytes:
    """
    Perform X25519 ECDH and derive a 32-byte AES-256 session key with HKDF-SHA256.

    [CONFIDENTIALITY + PERFECT FORWARD SECRECY]
    This function is called by BOTH sides of the exchange:

      Sender  (encrypting):
        local_private  = fresh ephemeral X25519 private key (discarded after transfer)
        peer_raw_public = receiver's long-term X25519 public key (from contacts)

      Receiver (decrypting):
        local_private  = receiver's own long-term X25519 private key
        peer_raw_public = the sender's ephemeral X25519 public key (from FILE_TRANSFER payload)

    ECDH commutativity guarantees both sides compute the same shared secret:
      ECDH(sender_eph_priv, receiver_pub) == ECDH(receiver_priv, sender_eph_pub)

    HKDF-SHA256 stretches the raw 32-byte Diffie-Hellman output into a key
    that is safe to use directly with AES.  The `info` parameter binds the
    derived key to this application and version, preventing cross-protocol
    key reuse.

    Java equivalent:
      KeyAgreement ka = KeyAgreement.getInstance("XDH");
      ka.init(localPrivateKey);
      ka.doPhase(peerPublicKey, true);
      byte[] sharedSecret = ka.generateSecret();
      // Then HKDF-SHA256 with info="P2P-SecureShare-v1-file".getBytes("UTF-8")
    """
    peer_public = X25519PublicKey.from_public_bytes(peer_raw_public)
    shared_secret = local_private.exchange(peer_public)

    # HKDF-SHA256: deterministic key derivation (RFC 5869)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 32 bytes = AES-256
        salt=None,          # no salt; the ephemeral key already provides randomness
        info=_HKDF_INFO,
    ).derive(shared_secret)
    return key


# ── AES-256-GCM encrypt / decrypt ─────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    [CONFIDENTIALITY + INTEGRITY]
    AES-GCM is an authenticated-encryption scheme:
      • The ciphertext is unreadable without the key (confidentiality).
      • The 128-bit GCM authentication tag is appended to the ciphertext
        (included in the returned bytes).  Any tampering with the ciphertext
        causes decryption to raise InvalidTag (integrity).

    Returns
    -------
    nonce      – 12 random bytes (96-bit nonce; recommended for AES-GCM)
    ciphertext – encrypted bytes + 16-byte authentication tag

    Java equivalent:
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
      byte[] ciphertext = cipher.doFinal(plaintext);
      // ciphertext already includes the 16-byte tag at the end
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and verify the authentication tag.

    [CONFIDENTIALITY + INTEGRITY]
    Raises cryptography.exceptions.InvalidTag if the tag does not match
    (i.e. the ciphertext has been tampered with, or the wrong key was used).
    Callers should treat this as a security error.

    Java equivalent:
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
      byte[] plaintext = cipher.doFinal(ciphertext);
      // throws AEADBadTagException on tag mismatch
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# ── Ed25519 sign / verify ─────────────────────────────────────────────────────

def sign_transfer(
    signing_key:        Ed25519PrivateKey,
    filename:           str,
    ephemeral_pub_bytes: bytes,
    nonce:              bytes,
    ciphertext:         bytes,
) -> bytes:
    """
    Sign a file transfer to authenticate the sender.

    [AUTHENTICATION]
    The signature covers: filename, ephemeral public key, nonce, and ciphertext.
    This prevents an attacker from:
      • Swapping the filename to make the receiver save a file under a different name.
      • Substituting the ephemeral public key to redirect to a different session.
      • Replaying or modifying the ciphertext.

    Returns 64 raw bytes (Ed25519 signature).

    Java equivalent:
      Signature sig = Signature.getInstance("Ed25519");
      sig.initSign(ed25519PrivateKey);
      sig.update(buildSignTarget(filename, ephKey, nonce, ciphertext));
      byte[] signature = sig.sign();
    """
    return signing_key.sign(_build_sign_target(filename, ephemeral_pub_bytes, nonce, ciphertext))


def verify_transfer_signature(
    signing_public_key_pem: str,
    filename:               str,
    ephemeral_pub_bytes:    bytes,
    nonce:                  bytes,
    ciphertext:             bytes,
    signature:              bytes,
) -> bool:
    """
    Verify the Ed25519 signature on a received file transfer.

    [AUTHENTICATION]
    Returns True if the signature is valid for the given data and key.
    Returns False if the signature is invalid or the key is wrong type.

    Call this BEFORE decrypting.  If verification fails, discard the transfer
    immediately – it may have been tampered with or sent by an impostor.

    Java equivalent:
      Signature sig = Signature.getInstance("Ed25519");
      sig.initVerify(ed25519PublicKey);
      sig.update(buildSignTarget(filename, ephKey, nonce, ciphertext));
      boolean valid = sig.verify(signatureBytes);
    """
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
    """
    Build the canonical byte string that is signed and verified.

    Layout (deterministic, reproducible in any language):
      [2 bytes]  length of filename in UTF-8 bytes (big-endian unsigned short)
      [N bytes]  filename in UTF-8
      [32 bytes] ephemeral X25519 public key (raw bytes, always 32 for X25519)
      [12 bytes] AES-GCM nonce (always 12 bytes)
      [M bytes]  AES-GCM ciphertext (includes 16-byte authentication tag)

    The 2-byte length prefix on the filename prevents boundary-confusion
    attacks where an attacker could craft an input that parses ambiguously.

    Java equivalent (buildSignTarget helper method):
      ByteBuffer buf = ByteBuffer.allocate(2 + fnameBytes.length + 32 + 12 + ciphertext.length);
      buf.putShort((short) fnameBytes.length);
      buf.put(fnameBytes);
      buf.put(ephemeralPublicKeyBytes);   // 32 bytes
      buf.put(nonce);                     // 12 bytes
      buf.put(ciphertext);
      return buf.array();
    """
    fname_bytes = filename.encode("utf-8")
    return (
        len(fname_bytes).to_bytes(2, "big")
        + fname_bytes
        + ephemeral_pub_bytes   # always 32 bytes for X25519
        + nonce                 # always 12 bytes for AES-GCM
        + ciphertext
    )


# ── Private helpers ───────────────────────────────────────────────────────────

def _save_ed25519_pair(private_key: Ed25519PrivateKey) -> str:
    """Persist an Ed25519 key pair and return the public key PEM string."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,       # Java: PKCS8EncodedKeySpec
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Java: X509EncodedKeySpec
    )
    _ED25519_PRIVATE_FILE.write_bytes(private_pem)
    _ED25519_PUBLIC_FILE.write_bytes(public_pem)
    return public_pem.decode("utf-8")


def _save_x25519_pair(private_key: X25519PrivateKey) -> str:
    """Persist an X25519 key pair and return the public key PEM string."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,       # Java: PKCS8EncodedKeySpec (XDH)
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Java: X509EncodedKeySpec (XDH)
    )
    _X25519_PRIVATE_FILE.write_bytes(private_pem)
    _X25519_PUBLIC_FILE.write_bytes(public_pem)
    return public_pem.decode("utf-8")


def _load_ed25519_private() -> Ed25519PrivateKey:
    """Load and validate the Ed25519 private key from disk."""
    key = load_pem_private_key(_ED25519_PRIVATE_FILE.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Stored signing key is not Ed25519 – delete identity/ and restart")
    return key


def _load_x25519_private() -> X25519PrivateKey:
    """Load and validate the X25519 private key from disk."""
    key = load_pem_private_key(_X25519_PRIVATE_FILE.read_bytes(), password=None)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError("Stored encryption key is not X25519 – delete identity/ and restart")
    return key


# ─────────────────────────────────────────────────────────────────────────────
# Key rotation helpers (Requirement 6)
# ─────────────────────────────────────────────────────────────────────────────

def rotate_keys(old_identity: "LocalIdentity") -> "LocalIdentity":
    """
    Generate a brand-new Ed25519 + X25519 key pair and save them to identity/.

    The old identity object is accepted as a parameter (used by the caller to
    sign the KEY_ROTATION announcement) but is NOT modified here – this function
    only writes the new keys to disk and returns a fresh LocalIdentity.

    After calling this the caller should:
      1. Build and send KEY_ROTATION notifications to online contacts using
         sign_key_rotation() with old_identity.signing_private_key.
      2. Replace the in-memory identity reference and update server/client keys
         via their update_identity() methods.

    Requirement: "Allow users to migrate to a new key if their old one is
    compromised.  Existing contacts should be notified."
    """
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
    """
    Sign a key rotation announcement with the OLD private key.

    The signature lets contacts verify that the rotation was authorised by the
    true key holder – an attacker who only has the new key cannot forge this.

    Returns raw Ed25519 signature bytes (64 bytes).

    [AUTHENTICATION] Only the holder of the old private key can produce a
    valid signature over these fields.
    """
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
    """
    Verify a KEY_ROTATION signature using the contact's previously stored
    (old) Ed25519 public key.

    Returns True only if the signature is valid, False on any failure.
    A False result means the rotation message must be rejected (Req 10).
    """
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
    """
    Build the canonical byte string that is signed / verified for key rotation.

    Null-byte delimiters separate every field so no field can bleed into
    another (prevents length-extension and field-substitution attacks).

    Java equivalent (concatenate in this exact order):
        "KEY_ROTATION\\0" + old_fingerprint + "\\0" + new_public_key_pem
        + "\\0" + new_encryption_key_pem + "\\0" + new_fingerprint
    """
    return (
        b"KEY_ROTATION\x00"
        + old_fingerprint.encode("utf-8")       + b"\x00"
        + new_public_key_pem.encode("utf-8")    + b"\x00"
        + new_encryption_key_pem.encode("utf-8") + b"\x00"
        + new_fingerprint.encode("utf-8")
    )
