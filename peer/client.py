# ────────────────────────────────────────────────────────────────────
# client.py – Sends a TCP message to a remote peer
#
# Keeps things simple: open a connection, send one message, close it.
# ────────────────────────────────────────────────────────────────────

import logging
import socket

from peer.models import Message, Peer
from peer.protocol import encode_message

logger = logging.getLogger(__name__)

# Seconds to wait for a connection or send to complete before giving up
_CONNECT_TIMEOUT = 5


class PeerClient:
    """Delivers a single Message to a target Peer over TCP."""

    def send_message(self, target: Peer, message: Message) -> bool:
        """
        Connect to target, send message, then close the connection.

        Returns True if the message was sent successfully, False otherwise.
        The caller does not need to handle exceptions.
        """
        try:
            with socket.create_connection(
                (target.host, target.port), timeout=_CONNECT_TIMEOUT
            ) as sock:
                sock.sendall(encode_message(message))
                logger.info(
                    f"Sent '{message.msg_type}' to {target.name} "
                    f"({target.host}:{target.port})"
                )
                return True
        except OSError as exc:
            logger.error(f"Could not reach {target.name} at {target.host}:{target.port} – {exc}")
            return False
