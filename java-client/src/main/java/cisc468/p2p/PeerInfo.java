// ─────────────────────────────────────────────────────────────────────────────
// PeerInfo – discovered peer (matches peer/models.py PeerInfo fields we use)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

public final class PeerInfo {
    public final String peerId;
    public final String peerName;
    public final String ip;
    public final int port;
    public volatile double lastSeen;

    public PeerInfo(String peerId, String peerName, String ip, int port) {
        this.peerId = peerId;
        this.peerName = peerName;
        this.ip = ip;
        this.port = port;
        this.lastSeen = System.currentTimeMillis() / 1000.0;
    }
}
