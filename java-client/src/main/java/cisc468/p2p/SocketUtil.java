// ─────────────────────────────────────────────────────────────────────────────
// SocketUtil – recv_line matches peer/utils.py recv_line (NDJSON framing)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public final class SocketUtil {

    private SocketUtil() {}

    /** Read until '\n' or EOF. Returns bytes read including '\n' if present. */
    public static byte[] recvLine(Socket socket) throws IOException {
        return recvLine(socket.getInputStream());
    }

    public static byte[] recvLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] one = new byte[1];
        while (true) {
            int n = in.read(one);
            if (n < 0) {
                break;
            }
            buf.write(one[0]);
            if (one[0] == '\n') {
                break;
            }
        }
        return buf.toByteArray();
    }
}
