# ───────────────────────────────────────────────────────────────────────
# server.py – TCP server that accepts incoming messages from other peers
#
# Design decisions:
#   - Each connection is handled in its own daemon thread so the accept
#     loop is never blocked by slow peers.
#   - We read exactly one message per connection (simple request model).
#     This is enough for Phase 1; persistent connections come later.
# ───────────────────────────────────────────────────────────────────────

import logging
import socket
import threading
from typing import Callable

from peer.config import TCP_BUFFER_SIZE
from peer.models import Message
from peer.protocol import decode_message

logger = logging.getLogger(__name__)


class PeerServer:
    """Listens on a TCP port and dispatches received messages to a callback."""

    def __init__(
        self,
        host: str,
        port: int,
        on_message: Callable[[Message, tuple[str, int]], None],
    ) -> None:
        """
        host       – address to bind to; use "0.0.0.0" to accept on all interfaces
        port       – TCP port to listen on
        on_message – function(message, addr) called for every received message
        """
        self.host = host
        self.port = port
        self.on_message = on_message
        self._running = False
        self._server_socket: socket.socket | None = None

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the socket and start the accept loop in a daemon thread."""
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # Allows the loop to check self._running
        logger.info(f"TCP server listening on {self.host}:{self.port}")
        threading.Thread(target=self._accept_loop, daemon=True, name="tcp-server").start()

    def stop(self) -> None:
        """Signal the server to stop accepting new connections."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()

    # ── Internal ────────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        """Main loop: wait for connections, spawn a thread for each one."""
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
            except socket.timeout:
                continue  # Check self._running and loop back
            except OSError:
                break     # Socket was closed by stop()

            threading.Thread(
                target=self._handle_connection,
                args=(conn, addr),
                daemon=True,
                name=f"tcp-conn-{addr[1]}",
            ).start()

    def _handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        """Read one message from the connection, decode it, and fire the callback."""
        try:
            data = conn.recv(TCP_BUFFER_SIZE)
            if data:
                message = decode_message(data)
                logger.info(f"Received '{message.msg_type}' from {addr[0]}:{addr[1]}")
                self.on_message(message, addr)
        except Exception as exc:
            logger.error(f"Error handling connection from {addr}: {exc}")
        finally:
            conn.close()
