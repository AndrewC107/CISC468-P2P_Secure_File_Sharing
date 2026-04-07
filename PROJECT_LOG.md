# CISC 468 P2P Secure File Sharing — Full Project Log

**Purpose:** Architecture and protocol reference for this repository: layout, wire format, cryptography, runtime behaviour, on-disk data, and tests. Use it alongside the source when reviewing or extending the project.

**Stack:** Python 3 reference implementation (`main.py`, package `peer/`); interoperable Java 17 client (`java-client/`, Maven, Gson, JCA). **Working directory** for both must be the **repository root** (or a copy such as `alice-peer/`) so relative paths `identity/`, `contacts/`, `storage/` resolve consistently.

---

## 1. Repository layout (complete file inventory)

### 1.1 Root

| Path | Role |
|------|------|
| `main.py` | Python entrypoint: interactive CLI, wires discovery, server, client, menus |
| `requirements.txt` | `cryptography>=42`, `pytest>=7.4` |
| `README.md` | Short run/test instructions + requirement mapping |
| `PROJECT_LOG.md` | This file |

### 1.2 Python package `peer/`

| File | Role |
|------|------|
| `config.py` | `DISCOVERY_PORT=5001`, `BROADCAST_ADDRESS`, `BROADCAST_INTERVAL=5`, `DEFAULT_TCP_PORT=5000`, `TCP_BUFFER_SIZE`, `PEER_TIMEOUT`, `SHARED_DIR`, `DOWNLOADS_DIR` |
| `models.py` | `Message` dataclass; `PeerInfo` dataclass |
| `protocol.py` | `MessageType` string constants; `validate_message`; NDJSON encode/decode |
| `utils.py` | `recv_line`, `get_local_ip`, `generate_peer_id` |
| `crypto.py` | Ed25519/X25519 identity, fingerprints, ECDH+HKDF, AES-GCM, transfer signatures, key rotation sign/verify |
| `contacts.py` | Load/save `contacts/contacts.json`; trust flag; fingerprint-based merge on peer restart |
| `catalog.py` | In-memory + `contacts/file_catalog.json` file catalog for offline alternate-source downloads |
| `storage.py` | `StorageKey`: PBKDF2-HMAC-SHA256 (600k iter), salt in `identity/storage_salt.bin`, AES-GCM at rest |
| `files.py` | Shared/downloads listing, import, secure save, SHA-256 of plaintext for lists |
| `discovery.py` | UDP broadcast/listen + `add_peer` for TCP-learned peers |
| `client.py` | `PeerClient`: TCP NDJSON requests, file transfer receive, identity, key rotation broadcast |
| `server.py` | `PeerServer`: TCP accept loop, consent queue, encrypt/sign outbound transfers, verify inbound |

### 1.3 Java `java-client/`

| Path | Role |
|------|------|
| `pom.xml` | `groupId` cisc468, `artifactId` p2p-secure-share-java, Java **release 17**, Gson 2.11, JUnit 5; `exec-maven-plugin` `mainClass` `cisc468.p2p.Main`, **`workingDirectory` `${project.basedir}/..`** (repo root) |
| `src/main/java/cisc468/p2p/Config.java` | Mirrors Python paths/constants; `p2p.basedir` system property override |
| `Message.java`, `MessageType.java` | Wire message model + type strings |
| `ProtocolJson.java` | Gson NDJSON encode/decode; field names **snake_case** (`sender_id`, etc.) |
| `SocketUtil.java` | Read one NDJSON line from socket |
| `NetUtil.java` | Local IP helper |
| `PemUtil.java` | PEM read/write |
| `HkdfSha256.java` | HKDF-SHA256 (matches Python) |
| `CryptoService.java` | Full crypto parity + **X25519 raw 32-byte little-endian** for wire/interop |
| `LocalIdentity.java`, `LocalPeerContext.java` | In-memory identity + advertised peer fields |
| `ContactRecord.java`, `ContactsFile.java`, `ContactStore.java` | JSON contacts persistence |
| `FileCatalog.java` | Catalog load/save/update (same JSON shape as Python) |
| `FileStore.java` | Shared/downloads I/O, listing with SHA-256, `.enc` handling |
| `StorageKey.java` | PBKDF2 + at-rest format matching Python |
| `PeerInfo.java` | Discovered peer row |
| `PeerDiscovery.java` | UDP threads + TCP callback pattern like Python |
| `PeerClient.java` | Outbound TCP operations |
| `PeerServer.java` | Inbound TCP dispatch, consent, encryption, verification |
| `PendingConsentRequest.java` | Blocking consent with timeout |
| `Main.java` | CLI menu 0–12, queues, lifecycle |

### 1.4 Tests `tests/`

| File | Focus |
|------|--------|
| `test_protocol.py` | NDJSON framing, validation, roundtrips |
| `test_crypto_integration.py` | Identity, ECDH, AES-GCM, Ed25519, contacts encryption_key |
| `test_storage.py` | StorageKey, tamper detection, file helpers |
| `test_catalog.py` | Catalog update, expected hash, alternate peers, integrity on receive |
| `test_key_rotation.py` | Rotation sign/verify, server handler, contact updates |

### 1.5 Sample / demo trees (not all may be tracked)

- `alice-peer/`, `bob-peer/`, `carl/` — per-peer working copies with own `storage/shared/` sample files (`AlicesFile.txt`, `BobsFile.txt`, `CarlsFile.txt`).
- `test-assets/sample_import_file.txt` — test data.

---

## 2. Runtime configuration

### 2.1 Ports

- **UDP discovery:** all peers bind **`0.0.0.0:5001`** with **`SO_REUSEADDR`** so multiple local processes can share the port.
- **TCP:** each peer listens on user-chosen port (default **5000**). Python may use CLI; Java prompts at startup.

### 2.2 Base directory

- **Python:** paths are relative to **current working directory** when launching `main.py`.
- **Java:** `Config.fromUserDir()` uses `Path.of("").toAbsolutePath()` unless **`-Dp2p.basedir=...`** is set (absolute/normalized path to peer root).

### 2.3 Directory layout (on disk)

```
identity/
  private_key.pem              # Ed25519 signing private (PKCS#8 PEM)
  public_key.pem               # Ed25519 public (SPKI PEM)
  x25519_private_key.pem       # X25519 static private
  x25519_public_key.pem        # X25519 static public
  storage_salt.bin             # 16 random bytes for PBKDF2 (at rest)

contacts/
  contacts.json                  # trust store + keys
  file_catalog.json              # remembered file lists + sha256 per offering peer

storage/
  shared/                        # files offered to others (may include .enc imports)
  downloads/                     # received files (typically .enc when storage key set)
```

---

## 3. Wire protocol: NDJSON over TCP

### 3.1 Framing

- Each logical message is **one JSON object** serialized as UTF-8, terminated by **`\n`** (newline).
- Receivers read until `\n`, then `json.loads` / Gson parse.
- **No** length prefix; **no** embedded raw newlines inside the JSON object (payloads use base64 for binary).

### 3.2 Envelope: every message

Required top-level fields (Python `validate_message`):

- `type` — string, one of `MessageType`
- `sender_id` — string UUID (new per process run unless restored—actually **new UUID each run** in both apps)
- `sender_name` — display name
- `sender_port` — **integer** TCP port
- `payload` — JSON object (dict); may be empty `{}`

Additional fields present in practice:

- `msg_id` — UUID string
- `timestamp` — float seconds (Python `time.time()`; Java `System.currentTimeMillis()/1000.0`)

### 3.3 `MessageType` values (exact strings)

| Constant | String value |
|----------|----------------|
| HELLO | `hello` |
| HELLO_ACK | `hello_ack` |
| CHAT | `chat` |
| BYE | `bye` |
| FILE_OFFER | `file_offer` |
| FILE_LIST_REQUEST | `file_list_request` |
| FILE_LIST_RESPONSE | `file_list_response` |
| FILE_REQUEST | `file_request` |
| FILE_TRANSFER | `file_transfer` |
| FILE_REJECTED | `file_rejected` |
| IDENTITY_EXCHANGE | `identity_exchange` |
| IDENTITY_ACK | `identity_ack` |
| KEY_ROTATION | `key_rotation` |

CHAT/BYE/FILE_OFFER are defined for extensibility; the **core secure file-sharing flow** uses HELLO, file list/request/transfer/rejected, identity, key rotation.

### 3.4 Payload contracts (by type)

**HELLO / HELLO_ACK**

- `payload`: typically `{}`
- HELLO elicits HELLO_ACK carrying same envelope fields as any reply.

**FILE_LIST_REQUEST**

- `payload`: `{}`
- Response: **FILE_LIST_RESPONSE** with `payload.files` = JSON array of objects:
  - `filename` (string)
  - `size` (int, bytes)
  - `sha256` (hex string of **plaintext** file content; may be missing from old clients—then catalog treats as empty and skips integrity check for fallback)

**FILE_REQUEST**

- `payload.filename` — string name under sender’s `storage/shared/`

**FILE_REJECTED**

- `payload.filename`, `payload.reason` — human-readable decline reason

**FILE_TRANSFER** — two modes:

1. **Legacy/plain:** `payload.encrypted` false/absent, `payload.data` base64(plaintext bytes).
2. **Secure (normal path):** `payload.encrypted` **true**, plus:
   - `ephemeral_public_key` — base64(**32 raw X25519 public key bytes**)
   - `nonce` — base64(12-byte AES-GCM nonce)
   - `ciphertext` — base64(AES-GCM ciphertext **including 16-byte auth tag**)
   - `signature` — base64(64-byte **Ed25519** signature)
   - `original_size` — plaintext length (int)
   - `filename` — string

**IDENTITY_EXCHANGE** (initiator → responder)

- `public_key` — Ed25519 SPKI PEM string
- `encryption_key` — X25519 SPKI PEM string  
- `fingerprint` — SHA-256 fingerprint string (format below)

**IDENTITY_ACK** (responder → initiator)

- `peer_id`, `peer_name` — redundant with envelope but included
- `public_key`, `encryption_key`, `fingerprint` — responder’s keys

**KEY_ROTATION** (fire-and-forget; no response required in protocol)

- `old_fingerprint`
- `new_public_key` — new Ed25519 PEM
- `new_encryption_key` — new X25519 PEM
- `new_fingerprint`
- `signature` — base64(Ed25519 over canonical rotation blob, signed with **old** Ed25519 private key)

---

## 4. UDP discovery (parallel to TCP)

### 4.1 Announcement payload (JSON, UTF-8, UDP datagram)

```json
{"peer_id":"<uuid>","peer_name":"<name>","tcp_port":<int>}
```

### 4.2 Send schedule

Every **5 seconds**, send to:

1. `255.255.255.255:5001` (LAN broadcast)
2. `127.0.0.1:5001` (loopback unicast — **critical on Windows** because broadcast may not reach another local process)

### 4.3 Symmetric discovery problem (Windows)

Multiple processes may bind UDP 5001 with `SO_REUSEADDR`; **Windows may deliver incoming broadcasts to only one socket**. Therefore:

- On **first UDP sighting** of a new `peer_id`, the app invokes **`on_peer_found`**, which sends **TCP HELLO** to `ip:tcp_port` from the datagram.
- The peer receiving HELLO **registers the sender** via **`add_peer`** and returns **HELLO_ACK**.
- The initiator reads ACK and registers the peer. **Both sides** end up in each other’s tables even if UDP was one-way.

### 4.4 Self-filter

Ignore UDP packets where `peer_id` equals **local** `peer_id` (do **not** filter by IP—breaks multiple local peers on 127.0.0.1).

---

## 5. Cryptography (detailed)

### 5.1 Two long-term key pairs per peer

| Key | Algorithm | Role |
|-----|-----------|------|
| Signing | **Ed25519** | Authenticate file transfers; sign key rotation |
| Encryption | **X25519** (ECDH) | Static public key shared in contacts; used with **ephemeral** X25519 for each file |

### 5.2 Fingerprint

- Compute **SHA-256** over **SubjectPublicKeyInfo DER** of the **Ed25519 public key** (same bytes from Python `cryptography` and Java `PublicKey.getEncoded()`).
- Represent as **uppercase hex** with **colons** every two hex chars (64 hex chars → 32 octet groups), e.g. `3A:F1:...`.

### 5.3 File transfer: confidentiality, integrity, authentication, PFS

**Sender (server after consent):**

1. Read **plaintext** from `storage/shared/<filename>`.
2. Generate **ephemeral X25519** key pair; discard private after use.
3. `peer_raw =` 32-byte **raw** encoding of ephemeral **public** key.  
   - Python: `Encoding.Raw`, `PublicFormat.Raw`.  
   - Java: `XECPublicKey.getU()` mapped to **32-byte little-endian** (interop fix vs BigInteger big-endian quirks).
4. Load receiver’s **static X25519 public** from contacts (PEM → raw 32 on sender side for ECDH input as appropriate in each language).
5. **ECDH** → shared secret → **HKDF-SHA256** with `salt=None`, `info = UTF-8 bytes of` **`P2P-SecureShare-v1-file`** → **32-byte AES-256 key**.
6. **AES-256-GCM**: random **12-byte** nonce; ciphertext includes **128-bit tag**.
7. **Ed25519 sign** over canonical **sign target** (next section).
8. Send **FILE_TRANSFER** with base64 fields.

**Receiver:**

1. Verify **Ed25519** signature using sender’s **Ed25519 public** from contacts **before** decrypting. On failure: discard, warn.
2. ECDH(receiver **static X25519 private**, sender **ephemeral raw public**) → same HKDF → AES-GCM decrypt. **AEADBadTagException** / `InvalidTag` → discard, warn.

### 5.4 Transfer sign target (byte-exact, cross-language)

Concatenation in order:

1. **2 bytes**: unsigned big-endian length of **filename UTF-8** (`len` ≤ 65535).
2. **N bytes**: filename UTF-8.
3. **32 bytes**: ephemeral X25519 public (raw).
4. **12 bytes**: AES-GCM nonce.
5. **M bytes**: AES-GCM ciphertext (includes tag).

### 5.5 Key rotation sign target

Exact byte sequence:

```
b"KEY_ROTATION\x00"
+ utf8(old_fingerprint) + b"\x00"
+ utf8(new_public_key_pem) + b"\x00"
+ utf8(new_encryption_key_pem) + b"\x00"
+ utf8(new_fingerprint)
```

Signed with **old** Ed25519 private key; verified with **old** Ed25519 public from contact record matching `old_fingerprint` (lookup by fingerprint).

### 5.6 At-rest storage (Requirement 9)

- **PBKDF2WithHmacSHA256**, **600,000** iterations, **16-byte** random salt → `identity/storage_salt.bin`.
- **AES-256-GCM** per file: `nonce (12) || ciphertext+tag`.
- Downloads saved as `.enc` when storage key is configured.

---

## 6. Trust and contacts

### 6.1 `contacts.json` shape

Top-level: `{ "contacts": [ ... ] }`

Each contact:

- `peer_id` (string)
- `peer_name` (string)
- `public_key` (Ed25519 PEM)
- `encryption_key` (X25519 PEM)
- `fingerprint` (string)
- `trusted` (boolean)

### 6.2 TOFU model

- **IDENTITY_EXCHANGE** causes save with **`trusted: false`** until user sets trust (menu) after out-of-band fingerprint check.
- **`save_contact` / `saveContact` merge rule:** match by `peer_id` first; else match by **fingerprint** and **refresh `peer_id`** (handles peer restart with new session UUID, same long-term keys).

### 6.3 Encrypted file send prerequisite

Server rejects (FILE_REJECTED) if contact has no **`encryption_key`**—user must run **identity exchange** first.

---

## 7. Consent (Requirement 3)

- Incoming **FILE_REQUEST** enqueues **`PendingConsentRequest`** (Python `queue.Queue`, Java `LinkedBlockingQueue`).
- Server thread **blocks** until main thread calls **`resolve(accepted)`** or timeout (~25–30s).
- Main thread must **never** let background threads call interactive input; menus drain **notifications** and **consents** at safe points (Python docstring in `main.py` explains the two-queue design).

---

## 8. Offline alternate source (Requirement 5)

- On each **FILE_LIST_RESPONSE**, **catalog.update** stores per-`peer_id` map: `filename → { peer_name, size, sha256 }`, persisted to **`contacts/file_catalog.json`**.
- **`request_file`**: if TCP to primary fails (`ConnectionRefused` / timeout / OSError), and catalog has expected **sha256**, search **other online peers** advertising same **filename + sha256**.
- After download from alternate, **re-hash plaintext**; if mismatch, **discard** and error (Requirement 10).

---

## 9. CLI menus (aligned)

### 9.1 Java `Main.java` menu

| # | Action |
|---|--------|
| 1 | Show discovered peers |
| 2 | Show my shared files |
| 3 | Send HELLO to peer |
| 4 | Request file list |
| 5 | Request file (with offline catalog + alternate logic) |
| 6 | Exchange identity |
| 7 | Show my fingerprint |
| 8 | Show contacts |
| 9 | Trust contact |
| 10 | Rotate keys + notify online peers |
| 11 | Import file to share |
| 12 | Show downloaded files |
| 0 | Exit |

### 9.2 Python `main.py`

Same feature set in the same spirit (option numbers may align; verify `main.py` if presenting—structure mirrors Java with discovery, server, client, consent, notifications).

---

## 10. Logging / UX notes

- **Python** client prints use symbols like `→`, `✓`, `✗` in some paths.
- **Java** uses **ASCII** markers (`[OK]`, `[ERR]`, `->`, `<-`) to avoid Windows console encoding issues.

---

## 11. Threading model (Python server)

- **Cached thread pool** (or similar) accepts TCP connections; each connection: read one line, dispatch, maybe write one line.
- **Discovery:** two daemons — UDP send loop, UDP recv loop.
- **Main thread:** menu loop + consent resolution + notification drain.

Java mirrors this: cached pool in `PeerServer`, daemon discovery threads, main menu thread.

---

## 12. Test counts (as of last full run)

- **pytest** `tests/`: **88** tests (protocol, crypto, storage, catalog, key rotation, server rotation handler, etc.).
- **Maven Surefire** (Java): **5** tests — `CryptoServiceTest`, `HkdfSha256Test`, `ProtocolJsonTest`.

Typical commands (Windows PowerShell):

```powershell
python -m pytest tests -v
mvn -f java-client/pom.xml test
```

---

## 13. Known interoperability details (for debugging)

1. **X25519 raw encoding:** Java must use **little-endian 32-byte** `u` coordinate when building `XECPublicKeySpec` from wire bytes, to match Python/cryptography **Raw** encoding.
2. **Gson** uses **lower_case_with_underscores** for Java field names to match Python JSON keys (`sender_id`, not `senderId`).
3. **FILE_LIST_RESPONSE** must include **`sha256`** for alternate-peer integrity path to work; Java `FileStore` computes SHA-256 of **decrypted/plain** shared file bytes when listing.

---

## 14. Security properties summary

| Property | Mechanism |
|----------|-----------|
| Confidentiality in transit | AES-256-GCM |
| Integrity in transit | GCM tag + signature over ciphertext |
| Authenticity of sender | Ed25519 over canonical transfer bytes |
| PFS (partial) | Fresh ephemeral X25519 per transfer; not full double-ephemeral TLS-style |
| Trust | Explicit `trusted` after OOB fingerprint verify |
| At rest | PBKDF2 + AES-GCM (passphrase-derived key) |
| Key migration | Signed KEY_ROTATION with old key |

---

## 15. What is NOT in scope / caveats

- No global PKI; fingerprints are **TOFU + OOB verify**.
- If a peer gets a **new `peer_id`** without identity re-exchange, **FILE_REQUEST** lookup by `sender_id` alone can fail until **IDENTITY_EXCHANGE** refreshes the row (fingerprint merge handles re-exchange).
- UDP discovery is **local network** only; no NAT traversal.

---

*End of PROJECT_LOG.md.*
