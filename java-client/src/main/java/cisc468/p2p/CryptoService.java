// ─────────────────────────────────────────────────────────────────────────────
// CryptoService – Ed25519 / X25519 / AES-256-GCM / HKDF (matches peer/crypto.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

public final class CryptoService {

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_LEN = 12;
    private static final int X25519_RAW_LEN = 32;

    private final SecureRandom random = new SecureRandom();

    public CryptoService() {}

    public LocalIdentity loadOrGenerateKeys(Config cfg) throws Exception {
        Path idDir = cfg.identityDir();
        Files.createDirectories(idDir);

        PrivateKey signPriv;
        PublicKey signPub;
        String signPubPem;
        if (Files.isRegularFile(cfg.ed25519PrivatePem()) && Files.isRegularFile(cfg.ed25519PublicPem())) {
            signPriv = loadEd25519Private(cfg.ed25519PrivatePem());
            signPubPem = Files.readString(cfg.ed25519PublicPem(), StandardCharsets.UTF_8);
            signPub = loadEd25519PublicFromPem(signPubPem);
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair pair = kpg.generateKeyPair();
            signPriv = pair.getPrivate();
            signPub = pair.getPublic();
            PemUtil.writePem(cfg.ed25519PrivatePem(), "PRIVATE KEY", signPriv.getEncoded());
            PemUtil.writePem(cfg.ed25519PublicPem(), "PUBLIC KEY", signPub.getEncoded());
            signPubPem = Files.readString(cfg.ed25519PublicPem(), StandardCharsets.UTF_8);
        }

        PrivateKey encPriv;
        PublicKey encPub;
        String encPubPem;
        if (Files.isRegularFile(cfg.x25519PrivatePem()) && Files.isRegularFile(cfg.x25519PublicPem())) {
            encPriv = loadX25519Private(cfg.x25519PrivatePem());
            encPubPem = Files.readString(cfg.x25519PublicPem(), StandardCharsets.UTF_8);
            encPub = loadX25519PublicFromPem(encPubPem);
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
            kpg.initialize(NamedParameterSpec.X25519);
            KeyPair pair = kpg.generateKeyPair();
            encPriv = pair.getPrivate();
            encPub = pair.getPublic();
            PemUtil.writePem(cfg.x25519PrivatePem(), "PRIVATE KEY", encPriv.getEncoded());
            PemUtil.writePem(cfg.x25519PublicPem(), "PUBLIC KEY", encPub.getEncoded());
            encPubPem = Files.readString(cfg.x25519PublicPem(), StandardCharsets.UTF_8);
        }

        String fp = computeFingerprint(signPub);
        return new LocalIdentity(signPriv, signPub, signPubPem, fp, encPriv, encPub, encPubPem);
    }

    public PrivateKey loadEd25519Private(Path pem) throws Exception {
        byte[] der = PemUtil.readDerFromPem(pem);
        PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        if (!(key instanceof EdECPrivateKey)) {
            throw new IllegalArgumentException("Stored signing key is not Ed25519");
        }
        return key;
    }

    public PublicKey loadEd25519PublicFromPem(String pem) throws Exception {
        byte[] der = PemUtil.parsePemDer(pem);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    public PrivateKey loadX25519Private(Path pem) throws Exception {
        byte[] der = PemUtil.readDerFromPem(pem);
        PrivateKey key = KeyFactory.getInstance("XDH").generatePrivate(new PKCS8EncodedKeySpec(der));
        if (!(key instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Stored encryption key is not X25519");
        }
        return key;
    }

    public PublicKey loadX25519PublicFromPem(String pem) throws Exception {
        byte[] der = PemUtil.parsePemDer(pem);
        return KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(der));
    }

    /** SHA-256(SPKI DER) as uppercase colon-separated hex – matches peer/crypto.py */
    public String computeFingerprint(PublicKey ed25519Public) throws Exception {
        byte[] der = ed25519Public.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(der);
        String hex = HexFormat.of().withUpperCase().formatHex(digest);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(hex, i, i + 2);
        }
        return sb.toString();
    }

    public KeyPair generateEphemeralX25519() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(NamedParameterSpec.X25519);
        return kpg.generateKeyPair();
    }

    public byte[] x25519PublicKeyRaw(PublicKey x25519Public) {
        XECPublicKey x = (XECPublicKey) x25519Public;
        return unsignedBigIntToFixed32(x.getU());
    }

    public byte[] x25519PublicRawFromPem(String pem) throws Exception {
        PublicKey pub = loadX25519PublicFromPem(pem);
        return x25519PublicKeyRaw(pub);
    }

    public byte[] ecdhDeriveKey(PrivateKey localPrivate, byte[] peerRawPublic32) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("XDH");
        BigInteger u = new BigInteger(1, peerRawPublic32);
        XECPublicKeySpec spec = new XECPublicKeySpec(NamedParameterSpec.X25519, u);
        PublicKey peerPublic = kf.generatePublic(spec);

        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(localPrivate);
        ka.doPhase(peerPublic, true);
        byte[] sharedSecret = ka.generateSecret();
        return HkdfSha256.derive(sharedSecret, null, Config.HKDF_INFO, 32);
    }

    public record AesGcmPacket(byte[] nonce, byte[] ciphertext) {}

    public AesGcmPacket aesGcmEncrypt(byte[] aesKey32, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LEN];
        random.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey32, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        byte[] ciphertext = cipher.doFinal(plaintext);
        return new AesGcmPacket(nonce, ciphertext);
    }

    public byte[] aesGcmDecrypt(byte[] aesKey32, byte[] nonce, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey32, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(ciphertext);
    }

    public byte[] signTransfer(
            PrivateKey ed25519Private,
            String filename,
            byte[] ephemeralPub32,
            byte[] nonce12,
            byte[] ciphertext) throws Exception {
        byte[] target = buildSignTarget(filename, ephemeralPub32, nonce12, ciphertext);
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(ed25519Private);
        sig.update(target);
        return sig.sign();
    }

    public boolean verifyTransferSignature(
            String ed25519PublicKeyPem,
            String filename,
            byte[] ephemeralPub32,
            byte[] nonce12,
            byte[] ciphertext,
            byte[] signature) {
        try {
            PublicKey pub = loadEd25519PublicFromPem(ed25519PublicKeyPem);
            byte[] target = buildSignTarget(filename, ephemeralPub32, nonce12, ciphertext);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(target);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] buildSignTarget(
            String filename,
            byte[] ephemeralPub32,
            byte[] nonce12,
            byte[] ciphertext) throws Exception {
        byte[] fname = filename.getBytes(StandardCharsets.UTF_8);
        if (fname.length > 0xFFFF) {
            throw new IllegalArgumentException("filename too long");
        }
        if (ephemeralPub32.length != X25519_RAW_LEN || nonce12.length != GCM_NONCE_LEN) {
            throw new IllegalArgumentException("unexpected key/nonce length");
        }
        ByteBuffer buf = ByteBuffer.allocate(2 + fname.length + X25519_RAW_LEN + GCM_NONCE_LEN + ciphertext.length);
        buf.putShort((short) fname.length);
        buf.put(fname);
        buf.put(ephemeralPub32);
        buf.put(nonce12);
        buf.put(ciphertext);
        return buf.array();
    }

    private static byte[] unsignedBigIntToFixed32(BigInteger u) {
        byte[] tb = u.toByteArray();
        if (tb.length == 33 && tb[0] == 0) {
            return Arrays.copyOfRange(tb, 1, 33);
        }
        if (tb.length > 32) {
            return Arrays.copyOfRange(tb, tb.length - 32, tb.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(tb, 0, out, 32 - tb.length, tb.length);
        return out;
    }

    public static String formatFingerprintForDisplay(String fingerprint) {
        String[] parts = fingerprint.split(":");
        if (parts.length < 32) {
            return "  " + fingerprint;
        }
        String row1 = String.join(":", Arrays.copyOfRange(parts, 0, 16));
        String row2 = String.join(":", Arrays.copyOfRange(parts, 16, 32));
        return "  " + row1 + "\n  " + row2;
    }
}
