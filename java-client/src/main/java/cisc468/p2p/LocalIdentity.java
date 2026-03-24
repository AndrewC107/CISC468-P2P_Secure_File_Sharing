// ─────────────────────────────────────────────────────────────────────────────
// LocalIdentity – mirrors peer/crypto.py LocalIdentity
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.security.PrivateKey;
import java.security.PublicKey;

public final class LocalIdentity {
    private final PrivateKey signingPrivateKey;
    private final String signingPublicKeyPem;
    private final String fingerprint;
    private final PrivateKey encryptionPrivateKey;
    private final String encryptionPublicKeyPem;
    private final PublicKey signingPublicKey;
    private final PublicKey encryptionPublicKey;

    public LocalIdentity(
            PrivateKey signingPrivateKey,
            PublicKey signingPublicKey,
            String signingPublicKeyPem,
            String fingerprint,
            PrivateKey encryptionPrivateKey,
            PublicKey encryptionPublicKey,
            String encryptionPublicKeyPem) {
        this.signingPrivateKey = signingPrivateKey;
        this.signingPublicKey = signingPublicKey;
        this.signingPublicKeyPem = signingPublicKeyPem;
        this.fingerprint = fingerprint;
        this.encryptionPrivateKey = encryptionPrivateKey;
        this.encryptionPublicKey = encryptionPublicKey;
        this.encryptionPublicKeyPem = encryptionPublicKeyPem;
    }

    public PrivateKey signingPrivateKey() {
        return signingPrivateKey;
    }

    public PublicKey signingPublicKey() {
        return signingPublicKey;
    }

    public String signingPublicKeyPem() {
        return signingPublicKeyPem;
    }

    public String fingerprint() {
        return fingerprint;
    }

    public PrivateKey encryptionPrivateKey() {
        return encryptionPrivateKey;
    }

    public PublicKey encryptionPublicKey() {
        return encryptionPublicKey;
    }

    public String encryptionPublicKeyPem() {
        return encryptionPublicKeyPem;
    }
}
