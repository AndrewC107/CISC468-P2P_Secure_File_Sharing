// ─────────────────────────────────────────────────────────────────────────────
// LocalPeerContext – this process identity for outbound messages
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

public final class LocalPeerContext {
    public final String peerId;
    public final String peerName;
    public final String ip;
    public final int port;
    public final String signingPublicKeyPem;
    public final String encryptionPublicKeyPem;
    public final String fingerprint;

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
