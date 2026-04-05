"""
main.py – Interactive command-line interface for P2P Secure Share

Run two instances in separate terminals to test on one machine:

    Terminal 1:  python main.py      (e.g. Alice on port 5000)
    Terminal 2:  python main.py      (e.g. Bob   on port 5100)

How symmetric discovery works
──────────────────────────────
1. UDP broadcast: each peer announces itself every 5 s to both
   255.255.255.255 (LAN) and 127.0.0.1 (localhost fallback).
2. On Windows, only ONE process receives a UDP broadcast when multiple
   processes share the same port.  So UDP alone is unreliable.
3. TCP HELLO handshake: whenever a peer is discovered via UDP, we
   immediately send a TCP HELLO.  The receiver replies with HELLO_ACK
   and BOTH sides call discovery.add_peer().  This guarantees both peers
   end up in each other's table regardless of which UDP direction worked.

File sharing
────────────
Drop files you want to share into  storage/shared/  before starting, OR
use menu option 11 (Import file to share) to add an encrypted copy.
Received files land in  storage/downloads/  (encrypted at rest).

Storage passphrase (Requirement 9)
────────────────────────────────────
You are prompted for a passphrase at startup.  All received files are
stored encrypted on disk (AES-256-GCM, key derived via PBKDF2-SHA256).
The passphrase is never stored – only the PBKDF2 salt is saved in
identity/storage_salt.bin.  Use the same passphrase every run.

Terminal UX design – two queues, one main thread
─────────────────────────────────────────────────
Background server threads must NOT call print() or input() while the
main thread is blocked on input(), or output gets interleaved.

Two queues solve this cleanly:

  notification_queue
    Server threads push any string they would normally print() here.
    The main loop drains it BEFORE rendering the menu, so notifications
    always appear on clean lines above the menu, never after "Your choice:".

  consent_queue
    When a remote peer requests a file, the server thread enqueues a
    PendingConsentRequest and blocks on an Event.  The main loop handles
    it (shows a clean yes/no prompt) before each menu render, then calls
    req.resolve(accepted) to unblock the server thread.

This guarantees input() is only ever called from the main thread and all
print() output from background threads is deferred to menu boundaries.
"""

import getpass
import logging
import queue
import threading

from peer import catalog
from peer import contacts as contact_store
from peer.client import PeerClient
from peer.config import DEFAULT_TCP_PORT, DOWNLOADS_DIR, SHARED_DIR
from peer.crypto import (
    format_fingerprint_for_display,
    load_or_generate_keys,
    rotate_keys,
)
from peer.discovery import PeerDiscovery
from peer.files import (
    ensure_storage_dirs,
    import_file_to_shared,
    list_downloaded_files,
    list_shared_files,
)
from peer.models import Message, PeerInfo
from peer.protocol import MessageType
from peer.server import PeerServer, PendingConsentRequest
from peer.storage import StorageKey
from peer.utils import generate_peer_id, get_local_ip

# ── Note on key deletion ───────────────────────────────────────────────────────
# If you want to test fresh key generation, delete the identity/ folder.
# Contacts that stored old keys will need to be refreshed via IDENTITY_EXCHANGE.
# ──────────────────────────────────────────────────────────────────────────────

# Keep background thread logger.info() calls silent; print() handles UI output.
logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")


# ─────────────────────────────────────────────────────────────────────────────
# Startup prompt
# ─────────────────────────────────────────────────────────────────────────────

def prompt_startup() -> tuple[str, int, StorageKey]:
    """
    Ask for display name, TCP port, and storage passphrase.

    The passphrase is used to derive the AES-256 key that protects received
    files at rest (Requirement 9).  The same passphrase must be used on every
    launch so previously saved files can be decrypted.

    Returns (name, port, storage_key).
    """
    print()
    print("=" * 52)
    print("   P2P Secure Share")
    print("=" * 52)
    name       = input("  Your name   [Peer]  : ").strip() or "Peer"
    port_input = input(f"  TCP port    [{DEFAULT_TCP_PORT}]  : ").strip()
    port       = int(port_input) if port_input.isdigit() else DEFAULT_TCP_PORT

    print()
    print("  Storage passphrase (protects received files at rest).")
    print("  Use the SAME passphrase every launch.  Leave empty to skip")
    print("  at-rest encryption (not recommended for sensitive data).")
    try:
        passphrase = getpass.getpass("  Passphrase: ")
    except Exception:
        passphrase = input("  Passphrase: ").strip()

    if passphrase:
        storage_key = StorageKey.derive(passphrase)
        print("  Storage key derived  ✓")
    else:
        storage_key = None
        print("  WARNING: No passphrase – received files will NOT be encrypted at rest.")

    return name, port, storage_key


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_size(size_bytes: int) -> str:
    """Return a human-readable file size (e.g. '42 B', '1.4 KB', '3.2 MB')."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.1f} GB"


# ─────────────────────────────────────────────────────────────────────────────
# Consent handling (file transfer requests from remote peers)
# ─────────────────────────────────────────────────────────────────────────────

def handle_pending_consents(consent_queue: queue.Queue) -> None:
    """
    Drain and process every pending file-transfer consent request.

    Called at the TOP of each menu loop iteration, BEFORE print_menu() and
    BEFORE the input() call for the menu choice.  This ensures:
      • The user always sees a clean "[REQUEST]" prompt with no other text
        in progress on the same line.
      • The normal menu is only shown AFTER all pending requests are handled.
      • input() is never called from a background thread (see module docstring).

    Handles multiple simultaneous requests (rare but possible) by looping
    until the queue is empty.
    """
    while True:
        try:
            req: PendingConsentRequest = consent_queue.get_nowait()
        except queue.Empty:
            break

        if req.timed_out:
            print(
                f"\n  (request from {req.peer_name} for '{req.filename}'"
                f" expired before you could respond)\n"
            )
            continue

        print()
        print("  ┌─────────────────────────────────────────")
        print(f"  │  [REQUEST] {req.peer_name} wants \"{req.filename}\"")
        print(f"  │  from {req.peer_ip}:{req.peer_port}")
        print("  └─────────────────────────────────────────")
        answer = input("  Accept? (y/n): ").strip().lower()

        if answer == "y":
            print(f"  ✓  Accepted – sending '{req.filename}' to {req.peer_name}…")
            req.resolve(True)
        else:
            print(f"  ✗  Declined – '{req.filename}' will not be sent.")
            req.resolve(False)

        print()


# ─────────────────────────────────────────────────────────────────────────────
# Menu helpers
# ─────────────────────────────────────────────────────────────────────────────

def print_menu() -> None:
    print("─" * 44)
    print("  MENU")
    print("─" * 44)
    print("  1  –  Show discovered peers")
    print("  2  –  Show my shared files")
    print("  3  –  Send HELLO to a peer")
    print("  4  –  Request file list from a peer")
    print("  5  –  Request a file from a peer")
    print("  ─" * 21)
    print("  6  –  Exchange identity with a peer")
    print("  7  –  Show my fingerprint")
    print("  8  –  Show contacts")
    print("  9  –  Trust a contact")
    print("  ─" * 21)
    print("  10 –  Rotate my keys (key migration)")
    print("  11 –  Import a file to share")
    print("  12 –  Show downloaded files")
    print("  ─" * 21)
    print("  0  –  Exit")
    print("─" * 44)


def pick_peer(discovery: PeerDiscovery) -> PeerInfo | None:
    """Return a peer to act on: auto-select if only one, prompt if many."""
    peers = list(discovery.get_peers().values())
    if not peers:
        print("  No peers discovered yet – wait a moment and try again.")
        return None
    if len(peers) == 1:
        p = peers[0]
        print(f"  Auto-selecting only peer: {p.peer_name}  ({p.ip}:{p.port})")
        return p
    print("  Discovered peers:")
    for i, p in enumerate(peers, start=1):
        print(f"    {i}.  {p.peer_name:15}  {p.ip}:{p.port}")
    choice = input("  Enter number: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(peers):
        return peers[int(choice) - 1]
    print("  Invalid choice.")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Menu actions
# ─────────────────────────────────────────────────────────────────────────────

def action_show_peers(discovery: PeerDiscovery) -> None:
    """Menu 1 – list every peer currently in the discovery table."""
    peers = discovery.get_peers()
    if not peers:
        print("  No peers discovered yet.")
        return
    print(f"  {len(peers)} peer(s) on the network:")
    for p in peers.values():
        print(
            f"    •  {p.peer_name:15}"
            f"  addr: {p.ip}:{p.port}"
            f"  id: {p.peer_id[:8]}…"
        )


def action_show_shared_files(storage_key: StorageKey | None = None) -> None:
    """Menu 2 – display the files in this peer's shared folder."""
    files = list_shared_files(storage_key)
    if not files:
        print(f"  No files in {SHARED_DIR}/")
        print( "  Drop plain files there, or use menu 11 to import an encrypted copy.")
        return
    print(f"  {len(files)} file(s) in {SHARED_DIR}/:")
    for i, f in enumerate(files, start=1):
        sha_part = f"  sha256:{f['sha256'][:12]}…" if f.get("sha256") else ""
        print(f"    {i}.  {f['filename']:30}  {_fmt_size(f['size'])}{sha_part}")


def action_send_hello(discovery: PeerDiscovery, client: PeerClient) -> None:
    """Menu 3 – send a HELLO greeting to a chosen peer."""
    peer = pick_peer(discovery)
    if peer is not None:
        client.send_hello(peer.ip, peer.port)


def action_request_file_list(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """
    Menu 4 – fetch and display the chosen peer's shared file list.

    Also updates the file catalog so offline fallback (Req 5) has up-to-date
    hash information for that peer.
    """
    peer = pick_peer(discovery)
    if peer is None:
        return
    files = client.request_file_list(peer.ip, peer.port)
    if files is not None:
        catalog.update(peer.peer_id, peer.peer_name, files)


def action_request_file(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """
    Menu 5 – request a specific file from a peer.

    Flow:
      1. Pick a peer.
      2. Fetch their file list and update the catalog.
      3. Let the user choose a file by number.
      4. Send FILE_REQUEST and wait for FILE_TRANSFER or FILE_REJECTED.
      5. If the peer is offline, offer to download from an alternate source
         with hash-based integrity verification (Requirement 5).
    """
    peer = pick_peer(discovery)
    if peer is None:
        return

    files = client.request_file_list(peer.ip, peer.port)
    if files is None:
        # Peer offline already at the file-list stage – still allow fallback
        # if we have a cached catalog entry for them.
        cached = [
            {"filename": fn, **meta}
            for fn, meta in catalog._catalog.get(peer.peer_id, {}).items()
        ]
        if cached:
            print(
                f"\n  ✗ {peer.peer_name} is offline.  Showing cached file list:\n"
            )
            for i, f in enumerate(cached, start=1):
                sha_part = f"  sha256:{f['sha256'][:12]}…" if f.get("sha256") else ""
                print(f"    {i}.  {f['filename']:30}  {sha_part}")
            files = [{"filename": e["filename"], "sha256": e.get("sha256", "")} for e in cached]
        else:
            print("  Could not retrieve file list – cannot continue.")
            return
    else:
        catalog.update(peer.peer_id, peer.peer_name, files)

    if not files:
        print(f"  {peer.peer_name} has no shared files.")
        return

    choice = input("  Enter file number to request: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(files)):
        print("  Invalid choice.")
        return

    chosen      = files[int(choice) - 1]
    filename    = chosen["filename"]
    sha256_hint = chosen.get("sha256") or catalog.get_expected_hash(peer.peer_id, filename)

    client.request_file(
        peer.ip, peer.port, filename,
        expected_sha256=sha256_hint,
        original_peer_id=peer.peer_id,
        get_peers=discovery.get_peers,
    )


def action_exchange_identity(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """
    Menu 6 – send IDENTITY_EXCHANGE to a chosen peer.

    This initiates the mutual authentication handshake:
      • We send our Ed25519 signing key, X25519 encryption key, and fingerprint.
      • The peer replies with their own (IDENTITY_ACK).
      • Both sides save each other in their contact store.
      • After exchange, encrypted file transfer becomes available with that peer.

    After the exchange, use 'Trust a contact' (menu 9) to mark the peer
    as verified once you have compared fingerprints out-of-band.
    """
    peer = pick_peer(discovery)
    if peer is not None:
        client.send_identity_exchange(peer.ip, peer.port)


def action_show_my_fingerprint(local_peer: PeerInfo) -> None:
    """
    Menu 7 – display this peer's public-key fingerprint.

    Share this string out-of-band so others can verify they're talking to you.
    """
    if local_peer.fingerprint is None:
        print("  Identity keys not loaded – restart the app.")
        return
    print()
    print("  My public-key fingerprint (SHA-256):")
    print(format_fingerprint_for_display(local_peer.fingerprint))
    print()
    print("  Share this fingerprint with other peers so they can verify")
    print("  your identity out-of-band (phone call, in person, etc.).")


def action_show_contacts() -> None:
    """
    Menu 8 – list all saved contacts with their trust status.
    """
    contacts = contact_store.list_contacts()
    if not contacts:
        print("  No contacts yet.")
        print("  Use 'Exchange identity' (menu 6) to populate this list.")
        return
    print(f"  {len(contacts)} contact(s):")
    for i, c in enumerate(contacts, start=1):
        trust_label = "✓ trusted" if c.get("trusted") else "  unverified"
        print(f"  {i:2}.  [{trust_label}]  {c['peer_name']:15}  {c['peer_id'][:8]}…")
        print(f"         Fingerprint: {c['fingerprint']}")


def action_trust_contact() -> None:
    """
    Menu 9 – mark a contact as trusted after out-of-band fingerprint verification.
    """
    contacts = contact_store.list_contacts()
    unverified = [c for c in contacts if not c.get("trusted")]
    if not unverified:
        print("  No unverified contacts to trust.")
        return

    print(f"  {len(unverified)} unverified contact(s):")
    for i, c in enumerate(unverified, start=1):
        print(f"  {i:2}.  {c['peer_name']:15}  {c['peer_id'][:8]}…")
        print(f"         Fingerprint: {c['fingerprint']}")

    choice = input("  Enter contact number to trust (or Enter to cancel): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(unverified)):
        print("  Cancelled.")
        return

    target = unverified[int(choice) - 1]
    print()
    print(f"  You are about to trust:  {target['peer_name']}")
    print(f"  Fingerprint:")
    print(format_fingerprint_for_display(target["fingerprint"]))
    print()
    print("  Confirm that this fingerprint matches what you received out-of-band")
    print("  (e.g. over a phone call or in person).")
    confirm = input("  Mark as trusted? (y/n): ").strip().lower()

    if confirm == "y":
        contact_store.set_trusted(target["peer_id"], trusted=True)
        print(f"  ✓ {target['peer_name']} is now marked as trusted.")
    else:
        print("  Trust not granted.")


def action_rotate_keys(
    local_peer: PeerInfo,
    server:     PeerServer,
    client:     PeerClient,
    discovery:  PeerDiscovery,
    identity_ref: list,
) -> None:
    """
    Menu 10 – generate new long-term keys and notify online contacts.

    Requirement 6: "Allow users to migrate to a new key if their old one is
    compromised.  Existing contacts should be notified, and any necessary steps
    should be taken to re-establish authenticated and secure communication."

    Rotation flow:
      1. Generate new Ed25519 + X25519 key pairs and save them to identity/.
      2. Sign a KEY_ROTATION message with the OLD private key and send it to
         all currently online contacts.  The signature lets them verify the
         rotation is authorised before updating their contact record.
      3. Update local state (local_peer, server, client) with the new keys.

    Contacts that are currently offline will receive no notification.  When
    they come back online and you exchange identities again, they will receive
    your new keys naturally.
    """
    print()
    print("  ┌─────────────────────────────────────────────────────")
    print("  │  KEY ROTATION")
    print("  │  This generates a new long-term Ed25519 + X25519 key pair.")
    print("  │  All currently online contacts will be notified automatically.")
    print("  │  You will need to re-verify your fingerprint with each contact.")
    print("  └─────────────────────────────────────────────────────")
    confirm = input("  Proceed with key rotation? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Rotation cancelled.")
        return

    old_identity = identity_ref[0]

    # Step 1: generate new keys and save to identity/
    new_identity = rotate_keys(old_identity)
    print(f"\n  ✓ New keys generated.")
    print(f"  New fingerprint:")
    print(format_fingerprint_for_display(new_identity.fingerprint))

    # Step 2: notify all currently online known contacts
    online_peers   = discovery.get_peers()
    all_contacts   = contact_store.list_contacts()
    contact_ids    = {c["peer_id"] for c in all_contacts}
    notified_count = 0

    for peer in online_peers.values():
        if peer.peer_id in contact_ids:
            ok = client.send_key_rotation(peer.ip, peer.port, old_identity, new_identity)
            if ok:
                print(f"  → KEY_ROTATION sent to {peer.peer_name}")
                notified_count += 1
            else:
                print(f"  ✗ Could not reach {peer.peer_name} (they are in contacts but offline now)")

    if notified_count == 0:
        print("  (No online contacts found to notify.)")

    # Step 3: update in-memory state so new transfers use the new keys
    identity_ref[0] = new_identity

    local_peer.public_key     = new_identity.signing_public_key_pem
    local_peer.encryption_key = new_identity.encryption_public_key_pem
    local_peer.fingerprint    = new_identity.fingerprint

    server.update_identity(
        new_identity.signing_private_key,
        new_identity.encryption_private_key,
    )
    client.update_identity(new_identity)

    print(
        f"\n  ✓ Key rotation complete.\n"
        f"  Contacts that were offline were not notified automatically.\n"
        f"  Re-run 'Exchange identity' with them after they come back online.\n"
        f"  You should also re-verify your NEW fingerprint with all contacts.\n"
    )


def action_import_file(storage_key: StorageKey | None) -> None:
    """
    Menu 11 – import an external file into storage/shared/ (optionally encrypted).

    When a storage key is active the file is stored encrypted (.enc) so that
    anyone who accesses the filesystem cannot read it without the passphrase.
    """
    print("  Enter the full path of the file you want to share.")
    print("  (Type 'cancel' to abort)")
    path = input("  File path: ").strip()
    if path.lower() == "cancel" or not path:
        print("  Cancelled.")
        return
    try:
        dest = import_file_to_shared(path, storage_key)
        enc_note = " (encrypted at rest)" if storage_key else ""
        print(f"  ✓ File imported to {dest}{enc_note}")
    except FileNotFoundError as exc:
        print(f"  ✗ {exc}")
    except Exception as exc:
        print(f"  ✗ Import failed: {exc}")


def action_show_downloaded_files(storage_key: StorageKey | None) -> None:
    """Menu 12 – list files saved to storage/downloads/ (decrypted names)."""
    files = list_downloaded_files(storage_key)
    if not files:
        print(f"  No files in {DOWNLOADS_DIR}/")
        return
    print(f"  {len(files)} downloaded file(s) in {DOWNLOADS_DIR}/:")
    for i, f in enumerate(files, start=1):
        print(f"    {i}.  {f['filename']:30}  {_fmt_size(f['size'])}")
    if storage_key:
        print("  (files are encrypted at rest)")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── 1. Startup ───────────────────────────────────────────────────────────
    ensure_storage_dirs()

    # Load (or generate on first run) both the Ed25519 signing key pair and
    # the X25519 encryption key pair.  Private keys stay on disk in identity/.
    # Public keys and the fingerprint are shared via IDENTITY_EXCHANGE.
    identity = load_or_generate_keys()

    name, port, storage_key = prompt_startup()

    local_peer = PeerInfo(
        peer_id=generate_peer_id(),
        peer_name=name,
        ip=get_local_ip(),
        port=port,
        public_key=identity.signing_public_key_pem,
        encryption_key=identity.encryption_public_key_pem,
        fingerprint=identity.fingerprint,
    )
    print(f"\n  Name       : {local_peer.peer_name}")
    print(f"  ID         : {local_peer.peer_id}")
    print(f"  Addr       : {local_peer.ip}:{local_peer.port}")
    print(f"  Shared     : {SHARED_DIR}/")
    print(f"  Downloads  : {DOWNLOADS_DIR}/")
    print(f"  Signing key (Ed25519) fingerprint:")
    print(format_fingerprint_for_display(identity.fingerprint))

    # ── 2. Create the shared queues and service objects ───────────────────────
    consent_queue:      queue.Queue = queue.Queue()
    notification_queue: queue.Queue = queue.Queue()

    server    = PeerServer(
        host="0.0.0.0",
        port=port,
        local_peer=local_peer,
        consent_queue=consent_queue,
        notification_queue=notification_queue,
        signing_private_key=identity.signing_private_key,
        encryption_private_key=identity.encryption_private_key,
        storage_key=storage_key,
    )
    discovery = PeerDiscovery(local_peer=local_peer)
    client    = PeerClient(
        local_peer=local_peer,
        encryption_private_key=identity.encryption_private_key,
        storage_key=storage_key,
    )

    # Mutable wrapper so action_rotate_keys() can rebind identity in-place.
    identity_ref = [identity]

    # ── 3. Define callbacks as closures (capture discovery + client) ──────────

    def on_peer_found(peer: PeerInfo) -> None:
        """
        Called by discovery when a BRAND-NEW peer is heard on UDP.
        Spawns a thread to send TCP HELLO immediately (symmetric-discovery fix).
        """
        def _hello_task() -> None:
            ack = client.send_hello(peer.ip, peer.port)
            if ack is not None:
                discovery.add_peer(PeerInfo(
                    peer_id=ack.sender_id,
                    peer_name=ack.sender_name,
                    ip=peer.ip,
                    port=ack.sender_port,
                ))
        threading.Thread(target=_hello_task, daemon=True, name="hello-task").start()

    def on_message_received(message: Message, addr: tuple[str, int]) -> None:
        """
        Called by PeerServer for every received TCP message.
        Registers the sender as a peer on HELLO or HELLO_ACK.
        """
        if message.type in (MessageType.HELLO, MessageType.HELLO_ACK):
            discovery.add_peer(PeerInfo(
                peer_id=message.sender_id,
                peer_name=message.sender_name,
                ip=addr[0],
                port=message.sender_port,
            ))

    # ── 4. Wire callbacks and start services ──────────────────────────────────
    server.on_message       = on_message_received
    discovery.on_peer_found = on_peer_found

    server.start()
    discovery.start()

    print()
    print("  Services started. Other peers will appear automatically.")
    print("  File requests will prompt you here before the menu.")

    # ── 5. Interactive menu loop ──────────────────────────────────────────────
    try:
        while True:
            # Drain background notifications first so they appear BEFORE the
            # menu, never interleaved with "Your choice:" prompts.
            while not notification_queue.empty():
                try:
                    print(notification_queue.get_nowait())
                except queue.Empty:
                    break

            handle_pending_consents(consent_queue)

            print()
            print_menu()
            choice = input("  Your choice: ").strip()

            if choice == "1":
                action_show_peers(discovery)
            elif choice == "2":
                action_show_shared_files(storage_key)
            elif choice == "3":
                action_send_hello(discovery, client)
            elif choice == "4":
                action_request_file_list(discovery, client)
            elif choice == "5":
                action_request_file(discovery, client)
            elif choice == "6":
                action_exchange_identity(discovery, client)
            elif choice == "7":
                action_show_my_fingerprint(local_peer)
            elif choice == "8":
                action_show_contacts()
            elif choice == "9":
                action_trust_contact()
            elif choice == "10":
                action_rotate_keys(local_peer, server, client, discovery, identity_ref)
                identity = identity_ref[0]
            elif choice == "11":
                action_import_file(storage_key)
            elif choice == "12":
                action_show_downloaded_files(storage_key)
            elif choice == "0":
                print("  Goodbye!")
                break
            else:
                print("  Please enter 0–12.")

    except KeyboardInterrupt:
        print("\n  Interrupted.")
    finally:
        discovery.stop()
        server.stop()
        print("  Shutdown complete.")


if __name__ == "__main__":
    main()
