package cisc468.p2p;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoServiceTest {

    @Test
    void ecdhCommutativity() throws Exception {
        CryptoService crypto = new CryptoService();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(NamedParameterSpec.X25519);
        KeyPair alice = kpg.generateKeyPair();
        KeyPair ephemeral = kpg.generateKeyPair();
        byte[] ephRaw = crypto.x25519PublicKeyRaw(ephemeral.getPublic());
        byte[] aliceRaw = crypto.x25519PublicKeyRaw(alice.getPublic());

        byte[] senderKey = crypto.ecdhDeriveKey(ephemeral.getPrivate(), aliceRaw);
        byte[] receiverKey = crypto.ecdhDeriveKey(alice.getPrivate(), ephRaw);
        assertArrayEquals(senderKey, receiverKey);
    }

    @Test
    void aesGcmRoundTripAndTamper() throws Exception {
        CryptoService crypto = new CryptoService();
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 7);
        byte[] plain = "Hello, secure P2P world!".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        CryptoService.AesGcmPacket p = crypto.aesGcmEncrypt(key, plain);
        byte[] back = crypto.aesGcmDecrypt(key, p.nonce(), p.ciphertext());
        assertArrayEquals(plain, back);
        byte[] bad = p.ciphertext().clone();
        bad[0] ^= (byte) 0xFF;
        byte[] badFinal = bad;
        assertThrows(AEADBadTagException.class, () -> crypto.aesGcmDecrypt(key, p.nonce(), badFinal));
    }

    @Test
    void ed25519SignVerifyAndFilenameBinding() throws Exception {
        CryptoService crypto = new CryptoService();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        KeyPairGenerator xdh = KeyPairGenerator.getInstance("XDH");
        xdh.initialize(NamedParameterSpec.X25519);
        KeyPair eph = xdh.generateKeyPair();
        byte[] ephRaw = crypto.x25519PublicKeyRaw(eph.getPublic());
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 3);
        CryptoService.AesGcmPacket packet = crypto.aesGcmEncrypt(key, new byte[] {1, 2, 3});

        String fname = "report.pdf";
        byte[] sig = crypto.signTransfer(kp.getPrivate(), fname, ephRaw, packet.nonce(), packet.ciphertext());
        java.nio.file.Path tmp = java.nio.file.Files.createTempFile("edtest", ".pem");
        PemUtil.writePem(tmp, "PUBLIC KEY", kp.getPublic().getEncoded());
        String pem = java.nio.file.Files.readString(tmp, java.nio.charset.StandardCharsets.UTF_8);

        assertTrue(crypto.verifyTransferSignature(pem, fname, ephRaw, packet.nonce(), packet.ciphertext(), sig));
        assertFalse(
                crypto.verifyTransferSignature(
                        pem, "other.bin", ephRaw, packet.nonce(), packet.ciphertext(), sig));
    }
}
