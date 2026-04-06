# ─────────────────────────────────────────────────────────────────────────────
# discovery.py – UDP peer announcements + peer table (TCP HELLO fills gaps on Windows)
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import socket
import threading
import time
from typing import Callable

from peer.config import BROADCAST_ADDRESS, BROADCAST_INTERVAL, DISCOVERY_PORT
from peer.models import PeerInfo

logger = logging.getLogger(__name__)

_LOCALHOST = "127.0.0.1"


class PeerDiscovery:
    """Broadcast and listen on UDP; optional on_peer_found callback for new peers."""

    def __init__(
        self,
        local_peer: PeerInfo,
        on_peer_found: Callable[[PeerInfo], None] | None = None,
    ) -> None:
        self.local_peer    = local_peer
        self.on_peer_found = on_peer_found
        self._peers:   dict[str, PeerInfo] = {}
        self._lock:    threading.Lock       = threading.Lock()
        self._running: bool                 = False

    def start(self) -> None:
        """Start UDP send and receive daemon threads."""
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
        """Stop loops at next iteration."""
        self._running = False

    def get_peers(self) -> dict[str, PeerInfo]:
        """Copy of the current peer_id → PeerInfo map."""
        with self._lock:
            return dict(self._peers)

    def add_peer(self, peer: PeerInfo) -> None:
        """Register or refresh a peer learned from TCP (does not fire on_peer_found)."""
        with self._lock:
            if peer.peer_id == self.local_peer.peer_id:
                return
            if peer.peer_id in self._peers:
                self._peers[peer.peer_id].last_seen = time.time()
            else:
                self._peers[peer.peer_id] = peer
                print(
                    f"\n  ✦ [{self.local_peer.peer_name}]"
                    f" Peer registered via TCP: '{peer.peer_name}'"
                    f" @ {peer.ip}:{peer.port}\n"
                )

    def _broadcast_loop(self) -> None:
        """Periodically announce this peer on broadcast and loopback."""
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

    def _listen_loop(self) -> None:
        """Receive UDP announcements and update the table; filter self by peer_id only."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", DISCOVERY_PORT))
        sock.settimeout(1.0)

        try:
            while self._running:
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    continue

                try:
                    info: dict = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    logger.warning(f"[discovery-rx] bad JSON from {addr}")
                    continue

                if info.get("peer_id") == self.local_peer.peer_id:
                    continue

                peer_id: str = info["peer_id"]
                is_new_peer  = False
                new_peer     = None

                with self._lock:
                    if peer_id in self._peers:
                        self._peers[peer_id].last_seen = time.time()
                    else:
                        new_peer = PeerInfo(
                            peer_id=peer_id,
                            peer_name=info["peer_name"],
                            ip=addr[0],
                            port=info["tcp_port"],
                        )
                        self._peers[peer_id] = new_peer
                        is_new_peer = True

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
