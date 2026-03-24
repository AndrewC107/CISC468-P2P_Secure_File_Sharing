package cisc468.p2p;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HkdfSha256Test {

    /** Same inputs as: python -c "… HKDF(…, salt=None, info=b'P2P-SecureShare-v1-file').derive(bytes([1])*32)" */
    @Test
    void hkdfMatchesPythonCryptography() throws GeneralSecurityException {
        byte[] ikm = new byte[32];
        java.util.Arrays.fill(ikm, (byte) 1);
        byte[] key = HkdfSha256.derive(ikm, null, Config.HKDF_INFO, 32);
        String hex = HexFormat.of().formatHex(key);
        assertEquals("00f3049a233a24a650624d2ed1d0803a06378adda38f9913cd520f5a08964860", hex);
    }
}
