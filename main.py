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
Drop files you want to share into  storage/shared/  before starting.
Received files land in  storage/downloads/  automatically.

File transfer consent (terminal UX design)
──────────────────────────────────────────
When a remote peer requests a file, the server thread must NOT call
input() directly.  Two threads calling input() simultaneously causes
messy overlapping prompts because the OS can only deliver keystrokes to
one reader at a time (see PendingConsentRequest in server.py for details).

Instead:
  • Server thread  → enqueues a PendingConsentRequest, blocks on an Event.
  • Main loop      → checks the queue before every menu render;
                     if a request is waiting, shows a clean prompt,
                     then calls req.resolve(accepted) to unblock the server.
  • Server thread  → receives the decision, reads the file, sends response.

This guarantees that input() is only ever called from the main thread,
so prompts are always clean and never overlap.
"""

import logging
import queue
import threading

from peer.client import PeerClient
from peer.config import DEFAULT_TCP_PORT, DOWNLOADS_DIR, SHARED_DIR
from peer.discovery import PeerDiscovery
from peer.files import ensure_storage_dirs, list_shared_files
from peer.models import Message, PeerInfo
from peer.protocol import MessageType
from peer.server import PeerServer, PendingConsentRequest
from peer.utils import generate_peer_id, get_local_ip

# Keep background thread logger.info() calls silent; print() handles UI output.
logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")


# ─────────────────────────────────────────────────────────────────────────────
# Startup prompt
# ─────────────────────────────────────────────────────────────────────────────

def prompt_startup() -> tuple[str, int]:
    """Ask the user for a display name and TCP port."""
    print()
    print("=" * 52)
    print("   P2P Secure Share")
    print("=" * 52)
    name       = input("  Your name   [Peer]  : ").strip() or "Peer"
    port_input = input(f"  TCP port    [{DEFAULT_TCP_PORT}]  : ").strip()
    port       = int(port_input) if port_input.isdigit() else DEFAULT_TCP_PORT
    return name, port


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
            break   # no more pending requests – proceed to normal menu

        # A request might already be resolved if the server thread timed out
        # (25 s) before the main loop got here.  Showing a stale prompt would
        # confuse the user, so skip it with a brief notice.
        if req.timed_out:
            print(
                f"\n  (request from {req.peer_name} for '{req.filename}'"
                f" expired before you could respond)\n"
            )
            continue

        # ── Show the consent prompt ────────────────────────────────────────────
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

        # Small visual separator before the next request or the menu
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
    print("  6  –  Exit")
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


def action_show_shared_files() -> None:
    """Menu 2 – display the files in this peer's shared folder."""
    files = list_shared_files()
    if not files:
        print(f"  No files in {SHARED_DIR}/")
        print( "  Drop files there to make them available to other peers.")
        return
    print(f"  {len(files)} file(s) in {SHARED_DIR}/:")
    for i, f in enumerate(files, start=1):
        size_kb = f["size"] / 1024
        print(f"    {i}.  {f['filename']:30}  {size_kb:.1f} KB")


def action_send_hello(discovery: PeerDiscovery, client: PeerClient) -> None:
    """Menu 3 – send a HELLO greeting to a chosen peer."""
    peer = pick_peer(discovery)
    if peer is not None:
        client.send_hello(peer.ip, peer.port)


def action_request_file_list(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """Menu 4 – fetch and display the chosen peer's shared file list."""
    peer = pick_peer(discovery)
    if peer is not None:
        client.request_file_list(peer.ip, peer.port)


def action_request_file(
    discovery: PeerDiscovery, client: PeerClient
) -> None:
    """
    Menu 5 – request a specific file from a peer.

    Flow:
      1. Pick a peer.
      2. Fetch their file list.
      3. Let the user choose a file by number.
      4. Send FILE_REQUEST and wait for FILE_TRANSFER or FILE_REJECTED.
    """
    peer = pick_peer(discovery)
    if peer is None:
        return

    files = client.request_file_list(peer.ip, peer.port)
    if files is None:
        print("  Could not retrieve file list – cannot continue.")
        return
    if not files:
        print(f"  {peer.peer_name} has no shared files.")
        return

    choice = input("  Enter file number to request: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(files)):
        print("  Invalid choice.")
        return

    filename = files[int(choice) - 1]["filename"]
    client.request_file(peer.ip, peer.port, filename)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── 1. Startup ───────────────────────────────────────────────────────────
    ensure_storage_dirs()   # create storage/shared/ and storage/downloads/

    name, port = prompt_startup()

    local_peer = PeerInfo(
        peer_id=generate_peer_id(),
        peer_name=name,
        ip=get_local_ip(),
        port=port,
    )
    print(f"\n  Name     : {local_peer.peer_name}")
    print(f"  ID       : {local_peer.peer_id}")
    print(f"  Addr     : {local_peer.ip}:{local_peer.port}")
    print(f"  Shared   : {SHARED_DIR}/")
    print(f"  Downloads: {DOWNLOADS_DIR}/")

    # ── 2. Create the shared consent queue and service objects ────────────────
    #
    # consent_queue is the bridge between the server's TCP threads and the
    # main CLI thread.  The server enqueues PendingConsentRequest objects;
    # handle_pending_consents() resolves them by calling req.resolve().
    consent_queue: queue.Queue = queue.Queue()

    server    = PeerServer(
        host="0.0.0.0",
        port=port,
        local_peer=local_peer,
        consent_queue=consent_queue,
    )
    discovery = PeerDiscovery(local_peer=local_peer)
    client    = PeerClient(local_peer=local_peer)

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
            # ── Handle any pending file-request consents FIRST ─────────────────
            # This must come before print_menu() and the input() call so that:
            #   a) the consent prompt is shown on a clean line, and
            #   b) normal menu output does not print over an in-progress prompt.
            handle_pending_consents(consent_queue)

            # ── Show menu and read choice ──────────────────────────────────────
            print()
            print_menu()
            choice = input("  Your choice: ").strip()

            if choice == "1":
                action_show_peers(discovery)
            elif choice == "2":
                action_show_shared_files()
            elif choice == "3":
                action_send_hello(discovery, client)
            elif choice == "4":
                action_request_file_list(discovery, client)
            elif choice == "5":
                action_request_file(discovery, client)
            elif choice == "6":
                print("  Goodbye!")
                break
            else:
                print("  Please enter 1–6.")

    except KeyboardInterrupt:
        print("\n  Interrupted.")
    finally:
        discovery.stop()
        server.stop()
        print("  Shutdown complete.")


if __name__ == "__main__":
    main()
