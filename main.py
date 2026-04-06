# main.py – Interactive CLI for the Python peer (matches java-client Main flow).
# UDP discovery plus TCP HELLO keeps peer tables in sync on Windows/LAN.
# Background threads use notification_queue and consent_queue so stdin/stdout stay clean.

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

# Delete identity/ to regenerate keys; contacts may need a new IDENTITY_EXCHANGE.
logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")


def prompt_startup() -> tuple[str, int, StorageKey | None]:
    """Prompt for name, TCP port, and optional storage passphrase; returns (name, port, storage_key)."""
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


def _fmt_size(size_bytes: int) -> str:
    """Format a byte count for display (B / KB / MB / GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.1f} GB"


def handle_pending_consents(consent_queue: queue.Queue) -> None:
    """Drain the consent queue and prompt accept/decline on the main thread only."""
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
    """Pick one discovered peer from the table (auto if there is only one)."""
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


def action_show_peers(discovery: PeerDiscovery) -> None:
    """Menu 1: print the discovery peer table."""
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
    """Menu 2: list files in storage/shared."""
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
    """Menu 3: send HELLO to a chosen peer."""
    peer = pick_peer(discovery)
    if peer is not None:
        client.send_hello(peer.ip, peer.port)


def action_request_file_list(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """Menu 4: request FILE_LIST and refresh the local file catalog."""
    peer = pick_peer(discovery)
    if peer is None:
        return
    files = client.request_file_list(peer.ip, peer.port)
    if files is not None:
        catalog.update(peer.peer_id, peer.peer_name, files)


def action_request_file(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """Menu 5: pick a peer and file, send FILE_REQUEST; client may use catalog fallback if offline."""
    peer = pick_peer(discovery)
    if peer is None:
        return

    files = client.request_file_list(peer.ip, peer.port)
    if files is None:
        cached = catalog.get_peer_files(peer.peer_id)
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
    """Menu 6: run IDENTITY_EXCHANGE / IDENTITY_ACK and save the peer to contacts."""
    peer = pick_peer(discovery)
    if peer is not None:
        client.send_identity_exchange(peer.ip, peer.port)


def action_show_my_fingerprint(local_peer: PeerInfo) -> None:
    """Menu 7: print this peer's signing-key fingerprint for out-of-band verification."""
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
    """Menu 8: list contacts and trust flags."""
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
    """Menu 9: mark an unverified contact as trusted after confirming their fingerprint."""
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
    """Menu 10: rotate Ed25519/X25519 keys, notify online contacts with signed KEY_ROTATION, refresh runtime state."""
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

    new_identity = rotate_keys(old_identity)
    print(f"\n  ✓ New keys generated.")
    print(f"  New fingerprint:")
    print(format_fingerprint_for_display(new_identity.fingerprint))

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
    """Menu 11: copy a file into storage/shared, encrypting with storage_key when set."""
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
    """Menu 12: list storage/downloads (decrypts .enc names when possible)."""
    files = list_downloaded_files(storage_key)
    if not files:
        print(f"  No files in {DOWNLOADS_DIR}/")
        return
    print(f"  {len(files)} downloaded file(s) in {DOWNLOADS_DIR}/:")
    for i, f in enumerate(files, start=1):
        print(f"    {i}.  {f['filename']:30}  {_fmt_size(f['size'])}")
    if storage_key:
        print("  (files are encrypted at rest)")


def main() -> None:
    ensure_storage_dirs()

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

    identity_ref = [identity]

    def on_peer_found(peer: PeerInfo) -> None:
        """On new UDP peer, send TCP HELLO in a thread so both sides learn each other."""
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
        """Register the remote peer from HELLO / HELLO_ACK payloads."""
        if message.type in (MessageType.HELLO, MessageType.HELLO_ACK):
            discovery.add_peer(PeerInfo(
                peer_id=message.sender_id,
                peer_name=message.sender_name,
                ip=addr[0],
                port=message.sender_port,
            ))

    server.on_message       = on_message_received
    discovery.on_peer_found = on_peer_found

    server.start()
    discovery.start()

    print()
    print("  Services started. Other peers will appear automatically.")
    print("  File requests will prompt you here before the menu.")

    try:
        while True:
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
