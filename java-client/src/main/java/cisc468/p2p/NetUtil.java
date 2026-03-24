// ─────────────────────────────────────────────────────────────────────────────
// NetUtil – get_local_ip matches peer/utils.py
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.net.DatagramSocket;
import java.net.InetAddress;

public final class NetUtil {

    private NetUtil() {}

    public static String getLocalIp() {
        try (DatagramSocket s = new DatagramSocket()) {
            s.connect(InetAddress.getByName("8.8.8.8"), 80);
            return s.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }
}
