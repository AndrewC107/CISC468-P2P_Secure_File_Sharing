# ─────────────────────────────────────────────
# config.py – Shared constants for the P2P node
# ─────────────────────────────────────────────

# UDP broadcast settings used by peer discovery
DISCOVERY_PORT = 5001           # All peers listen on this port for announcements
BROADCAST_ADDRESS = "255.255.255.255"  # LAN-wide broadcast address
BROADCAST_INTERVAL = 5          # Seconds between each presence broadcast

# TCP settings used by the server and client
DEFAULT_TCP_PORT = 5000         # Default port; override with --port at runtime
TCP_BUFFER_SIZE = 4096          # Max bytes read in a single recv() call

# A peer is considered gone if not heard from within this window
PEER_TIMEOUT = 30               # Seconds

# File storage – relative to wherever main.py is launched (project root)
SHARED_DIR    = "storage/shared"     # Files this peer is willing to share
DOWNLOADS_DIR = "storage/downloads"  # Files received from other peers
