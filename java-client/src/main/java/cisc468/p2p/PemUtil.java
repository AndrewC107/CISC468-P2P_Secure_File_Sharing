// ─────────────────────────────────────────────────────────────────────────────
// PemUtil – PKCS#8 / SPKI PEM read/write compatible with Python cryptography PEMs
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class PemUtil {

    private PemUtil() {}

    public static byte[] readDerFromPem(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8);
        return parsePemDer(pem);
    }

    public static byte[] parsePemDer(String pem) {
        String[] lines = pem.split("\\R");
        StringBuilder b64 = new StringBuilder();
        for (String line : lines) {
            String t = line.strip();
            if (t.isEmpty() || t.startsWith("-----")) {
                continue;
            }
            b64.append(t);
        }
        return Base64.getMimeDecoder().decode(b64.toString());
    }

    public static void writePem(Path path, String label, byte[] der) throws Exception {
        String header = "-----BEGIN " + label + "-----";
        String footer = "-----END " + label + "-----";
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der);
        String body = header + "\n" + encoded + "\n" + footer + "\n";
        Files.createDirectories(path.getParent());
        Files.writeString(path, body, StandardCharsets.UTF_8);
    }

    /** Strip to single PEM block if multiple concatenated (not expected here). */
    public static List<byte[]> parseAllDerBlocks(String pem) {
        List<byte[]> out = new ArrayList<>();
        String[] parts = pem.split("-----BEGIN ");
        for (String p : parts) {
            if (p.isBlank()) {
                continue;
            }
            int end = p.indexOf("-----END ");
            if (end < 0) {
                continue;
            }
            String block = "-----BEGIN " + p.substring(0, end + 9);
            int footerStart = p.indexOf('\n', end);
            if (footerStart > 0) {
                block = "-----BEGIN " + p.substring(0, footerStart);
            }
            out.add(parsePemDer(block));
        }
        return out;
    }
}
