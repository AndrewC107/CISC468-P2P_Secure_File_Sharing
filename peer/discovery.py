# ────────────────────────────────────────────────────────────────────────────
# discovery.py – Local peer discovery via UDP broadcast
#
# How it works:
#   1. Every BROADCAST_INTERVAL seconds we shout our presence onto the LAN
#      by sending a UDP datagram to the broadcast address.
#   2. Simultaneously we listen on the same port for broadcasts from others.
#   3. When we hear a new peer, we call the on_peer_found callback so the rest
#      of the application can react (e.g. store the peer, send a hello, etc.)
# ────────────────────────────────────────────────────────────────────────────

import json
import logging
import socket
import threading
import time

from peer.config import BROADCAST_ADDRESS, BROADCAST_INTERVAL, DISCOVERY_PORT
from peer.models import Peer

logger = logging.getLogger(__name__)


class PeerDiscovery:
    """Announces this peer on the LAN and discovers other peers."""

    def __init__(self, local_peer: Peer, on_peer_found: callable) -> None:
        """
        local_peer    – the Peer object representing this running instance
        on_peer_found – function(peer: Peer) called when a new peer is heard
        """
        self.local_peer = local_peer
        self.on_peer_found = on_peer_found
        self._running = False

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the broadcast and listener threads (both run as daemons)."""
        self._running = True
        threading.Thread(target=self._broadcast_loop, daemon=True, name="discovery-tx").start()
        threading.Thread(target=self._listen_loop,    daemon=True, name="discovery-rx").start()
        logger.info("Peer discovery started.")

    def stop(self) -> None:
        """Signal both threads to stop at their next iteration."""
        self._running = False

    # ── Internal threads ────────────────────────────────────────────────────

    def _broadcast_loop(self) -> None:
        """Periodically broadcast our presence to the LAN."""
        # Build the announcement payload once; it never changes while running
        announcement = json.dumps({
            "peer_id": self.local_peer.peer_id,
            "host":    self.local_peer.host,
            "port":    self.local_peer.port,
            "name":    self.local_peer.name,
        }).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            while self._running:
                try:
                    sock.sendto(announcement, (BROADCAST_ADDRESS, DISCOVERY_PORT))
                    logger.debug(f"Broadcast sent from '{self.local_peer.name}'")
                except OSError as exc:
                    logger.error(f"Broadcast send failed: {exc}")
                time.sleep(BROADCAST_INTERVAL)
        finally:
            sock.close()

    def _listen_loop(self) -> None:
        """Listen for UDP announcements from other peers on the LAN."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(1.0)  # Short timeout so we can check self._running regularly

        try:
            while self._running:
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    continue  # Loop back and check self._running

                try:
                    info = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    logger.warning(f"Received malformed discovery packet from {addr}")
                    continue

                # Ignore our own broadcasts
                if info.get("peer_id") == self.local_peer.peer_id:
                    continue

                discovered = Peer(
                    peer_id=info["peer_id"],
                    host=addr[0],          # Use the actual source IP, not what they claim
                    port=info["port"],
                    name=info["name"],
                )
                self.on_peer_found(discovered)
        finally:
            sock.close()
