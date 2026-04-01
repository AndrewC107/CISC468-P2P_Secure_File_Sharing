package cisc468.p2p;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.security.SecureRandom;

public final class StorageKey {

    private static final int PBKDF2_ITER = 600_000;
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;

    private final byte[] rawKey;

    private StorageKey(byte[] rawKey) {
        if (rawKey.length != 32) {
            throw new IllegalArgumentException("StorageKey requires 32-byte key");
        }
        this.rawKey = rawKey;
    }

    public static StorageKey derive(Config config, String passphrase) throws Exception {
        byte[] salt = loadOrCreateSalt(config);
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITER, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new StorageKey(key);
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] out = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
        return out;
    }

    public byte[] decrypt(byte[] blob) throws Exception {
        int min = NONCE_LEN + (TAG_BITS / 8);
        if (blob.length < min) {
            throw new IllegalArgumentException("Encrypted blob too short");
        }
        byte[] nonce = java.util.Arrays.copyOfRange(blob, 0, NONCE_LEN);
        byte[] ciphertext = java.util.Arrays.copyOfRange(blob, NONCE_LEN, blob.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        return cipher.doFinal(ciphertext);
    }

    private static byte[] loadOrCreateSalt(Config config) throws Exception {
        var path = config.storageSaltFile();
        Files.createDirectories(path.getParent());
        if (Files.isRegularFile(path)) {
            return Files.readAllBytes(path);
        }
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        Files.write(path, salt);
        return salt;
    }
}
