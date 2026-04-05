// ─────────────────────────────────────────────────────────────────────────────
// PeerDiscovery – UDP discovery (matches peer/discovery.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public final class PeerDiscovery {

    private static final Gson GSON = new Gson();

    private final LocalPeerContext local;
    private final Consumer<PeerInfo> onPeerFound;
    private final Map<String, PeerInfo> peers = new ConcurrentHashMap<>();
    private volatile boolean running;
    private Thread txThread;
    private Thread rxThread;

    public PeerDiscovery(LocalPeerContext local, Consumer<PeerInfo> onPeerFound) {
        this.local = local;
        this.onPeerFound = onPeerFound;
    }

    public void start() {
        running = true;
        txThread = new Thread(this::broadcastLoop, "discovery-tx");
        txThread.setDaemon(true);
        rxThread = new Thread(this::listenLoop, "discovery-rx");
        rxThread.setDaemon(true);
        txThread.start();
        rxThread.start();
        System.out.printf(
                "  [discovery] '%s' started - UDP port %d, interval %ds%n",
                local.peerName, Config.DISCOVERY_PORT, Config.BROADCAST_INTERVAL_SECONDS);
    }

    public void stop() {
        running = false;
    }

    public Map<String, PeerInfo> getPeers() {
        return Collections.unmodifiableMap(new ConcurrentHashMap<>(peers));
    }

    public void addPeer(PeerInfo p) {
        if (p.peerId.equals(local.peerId)) {
            return;
        }
        peers.compute(p.peerId, (id, existing) -> {
            if (existing != null) {
                existing.lastSeen = System.currentTimeMillis() / 1000.0;
                return existing;
            }
            System.out.printf(
                    "%n  [NEW] [%s] Peer registered via TCP: '%s' @ %s:%d%n%n",
                    local.peerName, p.peerName, p.ip, p.port);
            return p;
        });
    }

    private void broadcastLoop() {
        JsonObject ann = new JsonObject();
        ann.addProperty("peer_id", local.peerId);
        ann.addProperty("peer_name", local.peerName);
        ann.addProperty("tcp_port", local.port);
        byte[] payload = GSON.toJson(ann).getBytes(StandardCharsets.UTF_8);
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setBroadcast(true);
            while (running) {
                for (String dest : new String[] {Config.BROADCAST_ADDRESS, "127.0.0.1"}) {
                    try {
                        DatagramPacket pkt = new DatagramPacket(
                                payload,
                                payload.length,
                                InetAddress.getByName(dest),
                                Config.DISCOVERY_PORT);
                        sock.send(pkt);
                    } catch (Exception e) {
                        // ignore single destination failures
                    }
                }
                Thread.sleep(Config.BROADCAST_INTERVAL_SECONDS * 1000L);
            }
        } catch (Exception e) {
            if (running) {
                System.err.println("  [discovery-tx] stopped: " + e.getMessage());
            }
        }
    }

    private void listenLoop() {
        try (DatagramSocket sock = new DatagramSocket(null)) {
            sock.setReuseAddress(true);
            sock.bind(new java.net.InetSocketAddress("0.0.0.0", Config.DISCOVERY_PORT));
            sock.setSoTimeout(1000);
            byte[] buf = new byte[1024];
            while (running) {
                try {
                    DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                    sock.receive(pkt);
                    JsonObject info = GSON.fromJson(
                            new String(pkt.getData(), 0, pkt.getLength(), StandardCharsets.UTF_8),
                            JsonObject.class);
                    if (info == null) {
                        continue;
                    }
                    if (local.peerId.equals(info.get("peer_id").getAsString())) {
                        continue;
                    }
                    String peerId = info.get("peer_id").getAsString();
                    String peerName = info.get("peer_name").getAsString();
                    int tcpPort = info.get("tcp_port").getAsInt();
                    String ip = pkt.getAddress().getHostAddress();

                    PeerInfo newPeer = new PeerInfo(peerId, peerName, ip, tcpPort);
                    boolean[] isNew = {false};
                    peers.compute(peerId, (id, existing) -> {
                        if (existing != null) {
                            existing.lastSeen = System.currentTimeMillis() / 1000.0;
                            return existing;
                        }
                        isNew[0] = true;
                        return newPeer;
                    });
                    if (isNew[0] && onPeerFound != null) {
                        System.out.printf(
                                "%n  [NEW] [%s] New peer discovered via UDP: '%s' @ %s:%d%n%n",
                                local.peerName, peerName, ip, tcpPort);
                        onPeerFound.accept(newPeer);
                    }
                } catch (java.net.SocketTimeoutException ignored) {
                    // check running
                } catch (Exception e) {
                    if (running) {
                        // bad packet
                    }
                }
            }
        } catch (Exception e) {
            if (running) {
                System.err.println("  [discovery-rx] stopped: " + e.getMessage());
            }
        }
    }
}
