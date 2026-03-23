"""
main.py – Entry point for the P2P Secure Share client.

Usage (run two terminals simultaneously):

    python main.py --name Alice --port 5000
    python main.py --name Bob   --port 5100

Alice and Bob will discover each other via UDP broadcast and then
exchange hello messages over TCP every 10 seconds.
"""

import argparse
import logging
import time

from peer.client import PeerClient
from peer.config import DEFAULT_TCP_PORT
from peer.discovery import PeerDiscovery
from peer.models import Message, Peer
from peer.protocol import MessageType
from peer.server import PeerServer
from peer.utils import generate_peer_id, get_local_ip

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger(__name__)

# ── Shared state ─────────────────────────────────────────────────────────────
# Simple dict mapping peer_id → Peer for all peers we've discovered so far.
known_peers: dict[str, Peer] = {}


# ── Callbacks ────────────────────────────────────────────────────────────────

def on_peer_found(peer: Peer) -> None:
    """Called by PeerDiscovery when a new peer announces itself on the LAN."""
    if peer.peer_id not in known_peers:
        known_peers[peer.peer_id] = peer
        logger.info(f"Discovered peer '{peer.name}' at {peer.host}:{peer.port}")
    else:
        # Update last_seen timestamp so we know the peer is still alive
        known_peers[peer.peer_id].last_seen = peer.last_seen


def on_message_received(message: Message, addr: tuple[str, int]) -> None:
    """Called by PeerServer whenever a TCP message arrives."""
    logger.info(
        f"[{message.msg_type.upper()}] from {message.sender_id[:8]}… "
        f"payload={message.payload}"
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="P2P Secure Share – Phase 1")
    parser.add_argument("--name", default="Peer",          help="Display name for this node")
    parser.add_argument("--port", type=int, default=DEFAULT_TCP_PORT, help="TCP port to listen on")
    args = parser.parse_args()

    # Build the local peer identity
    local_ip = get_local_ip()
    local_peer = Peer(
        peer_id=generate_peer_id(),
        host=local_ip,
        port=args.port,
        name=args.name,
    )
    logger.info(f"Starting as '{local_peer.name}' | id={local_peer.peer_id} | {local_ip}:{args.port}")

    # Start TCP server – receives messages from other peers
    server = PeerServer(host="0.0.0.0", port=args.port, on_message=on_message_received)
    server.start()

    # Start UDP discovery – announces us and listens for others
    discovery = PeerDiscovery(local_peer=local_peer, on_peer_found=on_peer_found)
    discovery.start()

    client = PeerClient()

    logger.info("Ready. Press Ctrl+C to quit.")

    try:
        while True:
            time.sleep(10)

            # Say hello to every peer we know about
            for peer in list(known_peers.values()):
                hello = Message(
                    msg_type=MessageType.HELLO,
                    sender_id=local_peer.peer_id,
                    payload={"text": f"Hello from {local_peer.name}!"},
                )
                client.send_message(peer, hello)

    except KeyboardInterrupt:
        logger.info("Shutting down…")
        discovery.stop()
        server.stop()


if __name__ == "__main__":
    main()
