# ────────────────────────────────────────────────────────────────────────────
# discovery.py – Local peer discovery via UDP  (Phase 3 / reliability fix)
#
# Why discovery was asymmetric on Windows
# ────────────────────────────────────────
# When two processes both bind the same UDP port with SO_REUSEADDR, Windows
# routes incoming packets to only ONE of them (typically the most recently
# bound socket).  So if Alice starts first and Bob starts second, Bob ends
# up receiving all broadcasts while Alice receives none.  The result is that
# Bob discovers Alice but Alice never discovers Bob through UDP alone.
#
# How we fix it – TCP HELLO handshake
# ─────────────────────────────────────
# Whenever a peer is discovered via UDP, the discovering peer immediately
# sends a TCP HELLO to the new peer's TCP port (via the on_peer_found
# callback set up in main.py).  The receiving peer:
#   • logs the sender as a new peer in ITS own table (via on_message callback)
#   • replies with HELLO_ACK on the same connection
# The original sender reads the ACK and registers the replier in ITS table.
# This guarantees both sides learn about each other even when UDP is one-way.
#
# add_peer() public method
# ─────────────────────────
# PeerDiscovery now exposes add_peer() so main.py can register a peer that
# was learned through TCP rather than UDP (e.g. from a received HELLO or ACK).
#
# Logging policy
# ──────────────
# • "New peer discovered"   → always printed  (important event)
# • "Peer registered via TCP" → printed when TCP adds a peer UDP missed
# • Heartbeat refreshes    → silent  (too noisy to print every 5 s)
# • Every sent packet      → silent  (too noisy)
# • Every received packet  → silent  (too noisy)
# ────────────────────────────────────────────────────────────────────────────

import json
import logging
import socket
import threading
import time
from typing import Callable

from peer.config import BROADCAST_ADDRESS, BROADCAST_INTERVAL, DISCOVERY_PORT
from peer.models import PeerInfo

logger = logging.getLogger(__name__)

# Unicast target for localhost fallback.
# On Windows, 255.255.255.255 is NOT looped back to other local sockets, so
# we also send directly to 127.0.0.1 to reach peers on the same machine.
_LOCALHOST = "127.0.0.1"


class PeerDiscovery:
    """
    Discovers peers on the local network using UDP.

    Two daemon threads run continuously:
      discovery-tx  – broadcasts our presence every BROADCAST_INTERVAL seconds
      discovery-rx  – listens for announcements from other peers

    Symmetric discovery is guaranteed by the TCP HELLO handshake that
    main.py triggers via the on_peer_found callback (see module docstring).

    Public API
    ----------
    start()                – begin broadcasting and listening (non-blocking)
    stop()                 – signal both threads to exit
    get_peers()            – snapshot of all known peers
    add_peer(peer)         – register a peer learned through TCP (not UDP)
    """

    def __init__(
        self,
        local_peer: PeerInfo,
        on_peer_found: Callable[[PeerInfo], None] | None = None,
    ) -> None:
        """
        local_peer    – PeerInfo describing this running node
        on_peer_found – optional callback(peer) fired for every BRAND-NEW peer.
                        Called from outside the internal lock so it is safe to
                        do I/O (e.g. send a TCP HELLO) inside the callback.
        """
        self.local_peer    = local_peer
        self.on_peer_found = on_peer_found

        self._peers:   dict[str, PeerInfo] = {}
        self._lock:    threading.Lock       = threading.Lock()
        self._running: bool                 = False

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Spawn broadcast and listener daemon threads."""
        self._running = True
        threading.Thread(
            target=self._broadcast_loop, daemon=True, name="discovery-tx"
        ).start()
        threading.Thread(
            target=self._listen_loop, daemon=True, name="discovery-rx"
        ).start()
        print(
            f"  [discovery] '{self.local_peer.peer_name}' started –"
            f" UDP port {DISCOVERY_PORT}, interval {BROADCAST_INTERVAL}s"
        )

    def stop(self) -> None:
        """Ask both threads to exit at their next iteration."""
        self._running = False

    def get_peers(self) -> dict[str, PeerInfo]:
        """Return a thread-safe snapshot of the known peer table."""
        with self._lock:
            return dict(self._peers)

    def add_peer(self, peer: PeerInfo) -> None:
        """
        Register a peer learned through a TCP message (HELLO or HELLO_ACK).

        This is the TCP fallback that makes discovery symmetric:
          • If UDP delivered our broadcast to them but not theirs to us,
            their HELLO gives us the info we need to add them.
          • If they're already in the table (UDP worked both ways), we just
            refresh last_seen silently.

        Does NOT fire on_peer_found to avoid infinite HELLO loops.
        """
        with self._lock:
            if peer.peer_id == self.local_peer.peer_id:
                return  # never add ourselves
            if peer.peer_id in self._peers:
                self._peers[peer.peer_id].last_seen = time.time()
            else:
                self._peers[peer.peer_id] = peer
                # Print only when TCP discovers a peer that UDP missed
                print(
                    f"\n  ✦ [{self.local_peer.peer_name}]"
                    f" Peer registered via TCP: '{peer.peer_name}'"
                    f" @ {peer.ip}:{peer.port}\n"
                )

    # ── Broadcast thread ──────────────────────────────────────────────────────

    def _broadcast_loop(self) -> None:
        """
        Send our announcement every BROADCAST_INTERVAL seconds to:
          1. 255.255.255.255 – reaches peers on other machines (LAN broadcast)
          2. 127.0.0.1       – reaches peers on this machine (loopback unicast)

        We send to both because Windows does not loop broadcast packets back
        to other local sockets.  Sending to 127.0.0.1 explicitly fixes that.
        """
        announcement: bytes = json.dumps({
            "peer_id":   self.local_peer.peer_id,
            "peer_name": self.local_peer.peer_name,
            "tcp_port":  self.local_peer.port,
        }).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            while self._running:
                for destination in (BROADCAST_ADDRESS, _LOCALHOST):
                    try:
                        sock.sendto(announcement, (destination, DISCOVERY_PORT))
                    except OSError as exc:
                        logger.warning(f"[discovery-tx] send to {destination} failed: {exc}")
                time.sleep(BROADCAST_INTERVAL)
        finally:
            sock.close()

    # ── Listener thread ───────────────────────────────────────────────────────

    def _listen_loop(self) -> None:
        """
        Receive UDP packets on DISCOVERY_PORT and update the peer table.

        Self-filtering is done by peer_id comparison only – NOT by IP address.
        Filtering by IP would wrongly drop packets from a different process
        on 127.0.0.1, breaking same-machine discovery.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # SO_REUSEADDR lets multiple processes bind the same UDP port so both
        # peers on one machine can listen simultaneously.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind(("0.0.0.0", DISCOVERY_PORT))
        sock.settimeout(1.0)   # unblocks every second to check _running

        try:
            while self._running:
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    continue

                # ── Parse ──────────────────────────────────────────────────────
                try:
                    info: dict = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    logger.warning(f"[discovery-rx] bad JSON from {addr}")
                    continue

                # ── Ignore own packets (by peer_id, not by IP) ─────────────────
                if info.get("peer_id") == self.local_peer.peer_id:
                    continue

                peer_id: str = info["peer_id"]
                is_new_peer  = False
                new_peer     = None

                # ── Update peer table ──────────────────────────────────────────
                with self._lock:
                    if peer_id in self._peers:
                        # Heartbeat refresh – silent, no print needed
                        self._peers[peer_id].last_seen = time.time()
                    else:
                        new_peer = PeerInfo(
                            peer_id=peer_id,
                            peer_name=info["peer_name"],
                            ip=addr[0],           # use actual source IP
                            port=info["tcp_port"],
                        )
                        self._peers[peer_id] = new_peer
                        is_new_peer = True

                # ── Fire callback OUTSIDE the lock ─────────────────────────────
                # We release the lock before calling on_peer_found so that
                # the callback (which may send a TCP HELLO) doesn't hold the
                # lock while doing network I/O.
                if is_new_peer and new_peer is not None:
                    print(
                        f"\n  ✦ [{self.local_peer.peer_name}]"
                        f" New peer discovered via UDP: '{new_peer.peer_name}'"
                        f" @ {new_peer.ip}:{new_peer.port}\n"
                    )
                    if self.on_peer_found is not None:
                        self.on_peer_found(new_peer)
        finally:
            sock.close()
