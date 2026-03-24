// ─────────────────────────────────────────────────────────────────────────────
// HkdfSha256 – RFC 5869 HKDF-SHA256; salt=null matches cryptography HKDF(salt=None)
//              (HashLen octets of zero used as salt)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class HkdfSha256 {

    private static final int HASH_LEN = 32;

    private HkdfSha256() {}

    public static byte[] derive(byte[] ikm, byte[] saltOrNull, byte[] info, int length) throws GeneralSecurityException {
        byte[] salt = saltOrNull;
        if (salt == null) {
            salt = new byte[HASH_LEN]; // zeros – matches Python cryptography
        }
        byte[] prk = hmacSha256(salt, ikm);
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < length) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(t);
            mac.update(info != null ? info : new byte[0]);
            mac.update((byte) counter);
            t = mac.doFinal();
            int take = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, okm, pos, take);
            pos += take;
            counter++;
        }
        Arrays.fill(t, (byte) 0);
        return okm;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
