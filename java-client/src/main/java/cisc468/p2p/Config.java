// ─────────────────────────────────────────────────────────────────────────────
// Config.java – Shared constants (must match peer/config.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.nio.file.Path;

public final class Config {

    public static final int DISCOVERY_PORT = 5001;
    public static final String BROADCAST_ADDRESS = "255.255.255.255";
    public static final int BROADCAST_INTERVAL_SECONDS = 5;
    public static final int DEFAULT_TCP_PORT = 5000;
    public static final int TCP_BUFFER_SIZE = 4096;
    public static final int PEER_TIMEOUT_SECONDS = 30;

    public static final String SHARED_DIR = "storage/shared";
    public static final String DOWNLOADS_DIR = "storage/downloads";
    public static final String IDENTITY_DIR = "identity";
    public static final String CONTACTS_DIR = "contacts";

    /** HKDF info – byte-for-byte identical to peer/crypto.py _HKDF_INFO */
    public static final byte[] HKDF_INFO = "P2P-SecureShare-v1-file".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final Path baseDir;

    public Config(Path baseDir) {
        this.baseDir = baseDir;
    }

    public static Config fromUserDir() {
        String override = System.getProperty("p2p.basedir");
        if (override != null && !override.isBlank()) {
            return new Config(Path.of(override).toAbsolutePath().normalize());
        }
        return new Config(Path.of("").toAbsolutePath().normalize());
    }

    public Path baseDir() {
        return baseDir;
    }

    public Path sharedDir() {
        return baseDir.resolve(SHARED_DIR);
    }

    public Path downloadsDir() {
        return baseDir.resolve(DOWNLOADS_DIR);
    }

    public Path identityDir() {
        return baseDir.resolve(IDENTITY_DIR);
    }

    public Path contactsDir() {
        return baseDir.resolve(CONTACTS_DIR);
    }

    public Path contactsFile() {
        return contactsDir().resolve("contacts.json");
    }

    public Path ed25519PrivatePem() {
        return identityDir().resolve("private_key.pem");
    }

    public Path ed25519PublicPem() {
        return identityDir().resolve("public_key.pem");
    }

    public Path x25519PrivatePem() {
        return identityDir().resolve("x25519_private_key.pem");
    }

    public Path x25519PublicPem() {
        return identityDir().resolve("x25519_public_key.pem");
    }
}
