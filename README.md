# CISC 468 — P2P Secure File Sharing

Interoperable **Python** reference peer (`main.py`, `peer/`) and **Java** client (`java-client/`). Same NDJSON protocol, shared `identity/`, `contacts/`, and `storage/` layout when run from the repository root.

## Prerequisites

- **Python 3.10+** — `pip install -r requirements.txt`
- **JDK 17+** and **Maven 3.9+** — for the Java client

## Run

**Python peer** (from repo root; uses `./identity`, `./contacts`, `./storage`):

```text
python main.py
```

**Java peer** (working directory is the parent of `java-client/` per `pom.xml`):

```text
mvn -f java-client/pom.xml compile exec:java
```

Place files to share in `storage/shared/`. For two local instances, use different TCP ports when prompted.

## Tests

```text
python -m pytest tests -q
mvn -f java-client/pom.xml test
```

## Assignment requirements (mapping)

| # | Requirement | Where it lives |
|---|----------------|----------------|
| 1 | Peer discovery | `peer/discovery.py`, `PeerDiscovery.java` (UDP announce + TCP HELLO) |
| 2 | Mutual authentication after verification | Identity exchange + fingerprint; trust in contacts |
| 3 | Consent before file transfer | `PendingConsentRequest` / consent queue (Python + Java) |
| 4 | File list without prior consent | `FILE_LIST_REQUEST` / `handleFileListRequest` |
| 5 | Offline verification / alternate channel | Fingerprint display + catalog hashes (`FileCatalog`, `peer/catalog.py`) |
| 6 | Key migration + notify peers | `KEY_ROTATION` + signed rotation payload |
| 7 | Confidentiality & integrity in transit | AES-256-GCM + Ed25519 transfer signature |
| 8 | Perfect forward secrecy | Ephemeral X25519 per file transfer |
| 9 | Encrypted storage at rest | `StorageKey` (PBKDF2 + AES-GCM on disk) |
| 10 | Clear errors on failure | CLI `[ERR]` / `FILE_REJECTED` reasons |
| 11 | Automated tests | `tests/` (pytest), `java-client/src/test/java/` (JUnit 5) |
