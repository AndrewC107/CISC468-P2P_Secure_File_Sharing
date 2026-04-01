// ─────────────────────────────────────────────────────────────────────────────
// LocalPeerContext – this process identity for outbound messages
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

public final class LocalPeerContext {
    public String peerId;
    public String peerName;
    public String ip;
    public int port;
    public String signingPublicKeyPem;
    public String encryptionPublicKeyPem;
    public String fingerprint;

    public LocalPeerContext(
            String peerId,
            String peerName,
            String ip,
            int port,
            String signingPublicKeyPem,
            String encryptionPublicKeyPem,
            String fingerprint) {
        this.peerId = peerId;
        this.peerName = peerName;
        this.ip = ip;
        this.port = port;
        this.signingPublicKeyPem = signingPublicKeyPem;
        this.encryptionPublicKeyPem = encryptionPublicKeyPem;
        this.fingerprint = fingerprint;
    }
}
