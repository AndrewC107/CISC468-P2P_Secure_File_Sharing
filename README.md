# CISC 468 — P2P Secure File Sharing

Interoperable **Python** reference peer (`main.py`, `peer/`) and **Java** client (`java-client/`). Same NDJSON protocol. **Data paths** (`identity/`, `contacts/`, `storage/`) are resolved relative to the process working directory (Python) or the Java base directory (see below)—they are not tied to where `main.py` lives.

## Prerequisites

- **Python 3.10+** — `pip install -r requirements.txt`
- **JDK 17+** and **Maven 3.9+** — for the Java client

## Run

Paths like `identity/`, `contacts/`, and `storage/` are created **relative to the current working directory** (Python) or **`p2p.basedir`** (Java). For two peers on one machine, use **`alice-peer/`** and **`bob-peer/`** so each process has its own data; the repo includes sample files under each `storage/shared/`.

`main.py` lives in the **repository root**, so from `alice-peer` or `bob-peer` you run **`../main.py`**, not `main.py` in that folder.

Use **'Single peer'** whenever you are using multiple devices. If you want to test over a single device, then follow the **'Alice'** or **'Bob'** commands.

### Python

**Single peer**:

```text
cd <repository-root>
python main.py
```

**Alice**:

```text
cd alice-peer
python ../main.py
```

**Bob**:

```text
cd bob-peer
python ../main.py
```

Make sure to use **different TCP ports** when prompted (e.g. `5000` and `5100`). Place files to share in `storage/shared/` inside that peer’s directory (or use the import menu option).

### Java

Maven’s `exec:java` uses **`workingDirectory`** = parent of `java-client/` (the repository root). To put data under **`alice-peer/`** or **`bob-peer/`**, pass **`p2p.basedir`** (see `Config.fromUserDir()` in `Config.java`). Run these from the **repository root**:

**Default** (same layout as `python main.py` from root):

```text
cd <repository-root>
mvn -f java-client/pom.xml compile exec:java
```

**Alice**:

```text
cd <repository-root>
mvn -f java-client/pom.xml compile exec:java "-Dexec.jvmArgs=-Dp2p.basedir=alice-peer"
```

**Bob**:

```text
cd <repository-root>
mvn -f java-client/pom.xml compile exec:java "-Dexec.jvmArgs=-Dp2p.basedir=bob-peer"
```

On Unix shells you can often omit the extra quotes: `-Dexec.jvmArgs=-Dp2p.basedir=alice-peer`.

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
