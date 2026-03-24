// ─────────────────────────────────────────────────────────────────────────────
// Main.java – Interactive CLI (mirrors main.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Run from the repository root so {@code identity/}, {@code contacts/}, and {@code storage/} align
 * with the Python peer:
 *
 * <pre>
 *   cd &lt;repo-root&gt;
 *   mvn -f java-client exec:java
 * </pre>
 *
 * Override base directory: {@code -Dp2p.basedir=C:\path\to\repo}
 */
public final class Main {

    private Main() {}

    public static void main(String[] args) throws Exception {
        Config config = Config.fromUserDir();
        CryptoService crypto = new CryptoService();
        LocalIdentity identity = crypto.loadOrGenerateKeys(config);
        FileStore files = new FileStore(config);
        files.ensureStorageDirs();
        ContactStore contacts = new ContactStore(config);

        try (Scanner scanner = new Scanner(System.in, java.nio.charset.StandardCharsets.UTF_8)) {
            System.out.println();
            System.out.println("=".repeat(52));
            System.out.println("   P2P Secure Share (Java)");
            System.out.println("=".repeat(52));
            System.out.print("  Your name   [Peer]  : ");
            String name = scanner.nextLine().strip();
            if (name.isEmpty()) {
                name = "Peer";
            }
            System.out.print("  TCP port    [" + Config.DEFAULT_TCP_PORT + "]  : ");
            String portLine = scanner.nextLine().strip();
            int port =
                    portLine.isEmpty()
                            ? Config.DEFAULT_TCP_PORT
                            : (portLine.chars().allMatch(Character::isDigit) ? Integer.parseInt(portLine) : Config.DEFAULT_TCP_PORT);

            String peerId = UUID.randomUUID().toString();
            String ip = NetUtil.getLocalIp();
            LocalPeerContext local =
                    new LocalPeerContext(
                            peerId,
                            name,
                            ip,
                            port,
                            identity.signingPublicKeyPem(),
                            identity.encryptionPublicKeyPem(),
                            identity.fingerprint());

            System.out.printf("%n  Name       : %s%n", local.peerName);
            System.out.printf("  ID         : %s%n", local.peerId);
            System.out.printf("  Addr       : %s:%d%n", local.ip, local.port);
            System.out.printf("  Shared     : %s/%n", Config.SHARED_DIR);
            System.out.printf("  Downloads  : %s/%n", Config.DOWNLOADS_DIR);
            System.out.println("  Signing key (Ed25519) fingerprint:");
            System.out.println(CryptoService.formatFingerprintForDisplay(local.fingerprint));

            LinkedBlockingQueue<PendingConsentRequest> consentQueue = new LinkedBlockingQueue<>();
            PeerClient client = new PeerClient(local, contacts, crypto, files);

            final PeerDiscovery[] discoveryRef = new PeerDiscovery[1];
            discoveryRef[0] =
                    new PeerDiscovery(
                            local,
                            p ->
                                    new Thread(
                                                    () -> {
                                                        Message ack = client.sendHello(p.ip, p.port);
                                                        if (ack != null) {
                                                            discoveryRef[0].addPeer(
                                                                    new PeerInfo(
                                                                            ack.sender_id,
                                                                            ack.sender_name,
                                                                            p.ip,
                                                                            ack.sender_port));
                                                        }
                                                    },
                                                    "hello-task")
                                            .start());
            PeerDiscovery discovery = discoveryRef[0];

            PeerServer server =
                    new PeerServer(
                            local,
                            identity,
                            contacts,
                            crypto,
                            files,
                            consentQueue,
                            (msg, remoteIp) -> {
                                if (MessageType.HELLO.equals(msg.type)
                                        || MessageType.HELLO_ACK.equals(msg.type)) {
                                    discovery.addPeer(
                                            new PeerInfo(
                                                    msg.sender_id, msg.sender_name, remoteIp, msg.sender_port));
                                }
                            });

            server.start();
            discovery.start();

            System.out.println();
            System.out.println("  Services started. Other peers will appear automatically.");
            System.out.println("  File requests will prompt you here before the menu.");

            try {
                menuLoop(scanner, discovery, client, local, contacts, consentQueue, identity, files);
            } finally {
                discovery.stop();
                server.close();
                System.out.println("  Shutdown complete.");
            }
        }
    }

    private static void menuLoop(
            Scanner scanner,
            PeerDiscovery discovery,
            PeerClient client,
            LocalPeerContext local,
            ContactStore contacts,
            LinkedBlockingQueue<PendingConsentRequest> consentQueue,
            LocalIdentity identity,
            FileStore files)
            throws Exception {
        while (true) {
            handlePendingConsents(scanner, consentQueue);
            System.out.println();
            printMenu();
            System.out.print("  Your choice: ");
            String choice = scanner.nextLine().strip();
            switch (choice) {
                case "1" -> actionShowPeers(discovery);
                case "2" -> actionShowSharedFiles(files);
                case "3" -> actionSendHello(scanner, discovery, client, local);
                case "4" -> actionRequestFileList(scanner, discovery, client, local);
                case "5" -> actionRequestFile(scanner, discovery, client, local, identity);
                case "6" -> actionExchangeIdentity(scanner, discovery, client, local);
                case "7" -> actionShowFingerprint(local);
                case "8" -> actionShowContacts(local, contacts);
                case "9" -> actionTrustContact(scanner, local, contacts);
                case "0" -> {
                    System.out.println("  Goodbye!");
                    return;
                }
                default -> System.out.println("  Please enter 0–9.");
            }
        }
    }

    private static void handlePendingConsents(Scanner scanner, LinkedBlockingQueue<PendingConsentRequest> queue) {
        while (true) {
            PendingConsentRequest req = queue.poll();
            if (req == null) {
                break;
            }
            if (req.timedOut()) {
                System.out.printf(
                        "%n  (request from %s for '%s' expired before you could respond)%n%n",
                        req.peerName, req.filename);
                continue;
            }
            System.out.println();
            System.out.println("  ┌─────────────────────────────────────────");
            System.out.printf("  │  [REQUEST] %s wants \"%s\"%n", req.peerName, req.filename);
            System.out.printf("  │  from %s:%d%n", req.peerIp, req.peerPort);
            System.out.println("  └─────────────────────────────────────────");
            System.out.print("  Accept? (y/n): ");
            String answer = scanner.nextLine().strip().toLowerCase();
            if ("y".equals(answer)) {
                System.out.printf("  ✓  Accepted – sending '%s' to %s…%n", req.filename, req.peerName);
                req.resolve(true);
            } else {
                System.out.printf("  ✗  Declined – '%s' will not be sent.%n", req.filename);
                req.resolve(false);
            }
            System.out.println();
        }
    }

    private static void printMenu() {
        System.out.println("─".repeat(44));
        System.out.println("  MENU");
        System.out.println("─".repeat(44));
        System.out.println("  1  –  Show discovered peers");
        System.out.println("  2  –  Show my shared files");
        System.out.println("  3  –  Send HELLO to a peer");
        System.out.println("  4  –  Request file list from a peer");
        System.out.println("  5  –  Request a file from a peer");
        System.out.println("  " + "─".repeat(21));
        System.out.println("  6  –  Exchange identity with a peer");
        System.out.println("  7  –  Show my fingerprint");
        System.out.println("  8  –  Show contacts");
        System.out.println("  9  –  Trust a contact");
        System.out.println("  " + "─".repeat(21));
        System.out.println("  0  –  Exit");
        System.out.println("─".repeat(44));
    }

    private static void actionShowPeers(PeerDiscovery discovery) {
        var peers = discovery.getPeers();
        if (peers.isEmpty()) {
            System.out.println("  No peers discovered yet.");
            return;
        }
        System.out.printf("  %d peer(s) on the network:%n", peers.size());
        for (PeerInfo p : peers.values()) {
            System.out.printf(
                    "    •  %-15s  addr: %s:%d  id: %s…%n",
                    p.peerName, p.ip, p.port, p.peerId.substring(0, Math.min(8, p.peerId.length())));
        }
    }

    private static void actionShowSharedFiles(FileStore files) throws Exception {
        var list = files.listSharedFiles();
        if (list.isEmpty()) {
            System.out.printf("  No files in %s/%n", Config.SHARED_DIR);
            System.out.println("  Drop files there to make them available to other peers.");
            return;
        }
        System.out.printf("  %d file(s) in %s/:%n", list.size(), Config.SHARED_DIR);
        int i = 1;
        for (FileStore.FileEntry f : list) {
            System.out.printf("  %d.  %-30s  %.1f KB%n", i++, f.filename(), f.size() / 1024.0);
        }
    }

    private static PeerInfo pickPeer(Scanner scanner, PeerDiscovery discovery, LocalPeerContext local) {
        List<PeerInfo> peers = new ArrayList<>(discovery.getPeers().values());
        if (peers.isEmpty()) {
            System.out.println("  No peers discovered yet – wait a moment and try again.");
            return null;
        }
        if (peers.size() == 1) {
            PeerInfo p = peers.get(0);
            System.out.printf("  Auto-selecting only peer: %s  (%s:%d)%n", p.peerName, p.ip, p.port);
            return p;
        }
        System.out.println("  Discovered peers:");
        for (int i = 0; i < peers.size(); i++) {
            PeerInfo p = peers.get(i);
            System.out.printf("    %d.  %-15s  %s:%d%n", i + 1, p.peerName, p.ip, p.port);
        }
        System.out.print("  Enter number: ");
        String c = scanner.nextLine().strip();
        if (c.chars().allMatch(Character::isDigit)) {
            int n = Integer.parseInt(c);
            if (n >= 1 && n <= peers.size()) {
                return peers.get(n - 1);
            }
        }
        System.out.println("  Invalid choice.");
        return null;
    }

    private static void actionSendHello(
            Scanner scanner, PeerDiscovery discovery, PeerClient client, LocalPeerContext local) {
        PeerInfo p = pickPeer(scanner, discovery, local);
        if (p != null) {
            client.sendHello(p.ip, p.port);
        }
    }

    private static void actionRequestFileList(
            Scanner scanner, PeerDiscovery discovery, PeerClient client, LocalPeerContext local) throws Exception {
        PeerInfo p = pickPeer(scanner, discovery, local);
        if (p != null) {
            client.requestFileList(p.ip, p.port);
        }
    }

    private static void actionRequestFile(
            Scanner scanner,
            PeerDiscovery discovery,
            PeerClient client,
            LocalPeerContext local,
            LocalIdentity identity)
            throws Exception {
        PeerInfo p = pickPeer(scanner, discovery, local);
        if (p == null) {
            return;
        }
        List<FileStore.FileEntry> fl = client.requestFileList(p.ip, p.port);
        if (fl == null) {
            System.out.println("  Could not retrieve file list – cannot continue.");
            return;
        }
        if (fl.isEmpty()) {
            System.out.printf("  %s has no shared files.%n", p.peerName);
            return;
        }
        System.out.print("  Enter file number to request: ");
        String c = scanner.nextLine().strip();
        if (!c.chars().allMatch(Character::isDigit)) {
            System.out.println("  Invalid choice.");
            return;
        }
        int n = Integer.parseInt(c);
        if (n < 1 || n > fl.size()) {
            System.out.println("  Invalid choice.");
            return;
        }
        String filename = fl.get(n - 1).filename();
        client.requestFile(p.ip, p.port, filename, identity.encryptionPrivateKey());
    }

    private static void actionExchangeIdentity(
            Scanner scanner, PeerDiscovery discovery, PeerClient client, LocalPeerContext local) throws Exception {
        PeerInfo p = pickPeer(scanner, discovery, local);
        if (p != null) {
            client.sendIdentityExchange(p.ip, p.port);
        }
    }

    private static void actionShowFingerprint(LocalPeerContext local) {
        System.out.println();
        System.out.println("  My public-key fingerprint (SHA-256):");
        System.out.println(CryptoService.formatFingerprintForDisplay(local.fingerprint));
        System.out.println();
        System.out.println("  Share this fingerprint with other peers so they can verify");
        System.out.println("  your identity out-of-band (phone call, in person, etc.).");
    }

    private static void actionShowContacts(LocalPeerContext local, ContactStore contacts) throws Exception {
        var list = contacts.listContacts();
        if (list.isEmpty()) {
            System.out.println("  No contacts yet.");
            System.out.println("  Use 'Exchange identity' (menu 6) to populate this list.");
            return;
        }
        System.out.printf("  %d contact(s):%n", list.size());
        int i = 1;
        for (ContactRecord c : list) {
            String trustLabel = c.trusted ? "✓ trusted" : "  unverified";
            System.out.printf(
                    "  %2d.  [%s]  %-15s  %s…%n",
                    i++,
                    trustLabel,
                    c.peerName,
                    c.peerId.substring(0, Math.min(8, c.peerId.length())));
            System.out.printf("         Fingerprint: %s%n", c.fingerprint);
        }
    }

    private static void actionTrustContact(Scanner scanner, LocalPeerContext local, ContactStore contacts)
            throws Exception {
        List<ContactRecord> all = contacts.listContacts();
        List<ContactRecord> unverified = new ArrayList<>();
        for (ContactRecord c : all) {
            if (!c.trusted) {
                unverified.add(c);
            }
        }
        if (unverified.isEmpty()) {
            System.out.println("  No unverified contacts to trust.");
            return;
        }
        System.out.printf("  %d unverified contact(s):%n", unverified.size());
        for (int i = 0; i < unverified.size(); i++) {
            ContactRecord c = unverified.get(i);
            System.out.printf("  %2d.  %-15s  %s…%n", i + 1, c.peerName, c.peerId.substring(0, Math.min(8, c.peerId.length())));
            System.out.printf("         Fingerprint: %s%n", c.fingerprint);
        }
        System.out.print("  Enter contact number to trust (or Enter to cancel): ");
        String line = scanner.nextLine().strip();
        if (!line.chars().allMatch(Character::isDigit)) {
            System.out.println("  Cancelled.");
            return;
        }
        int n = Integer.parseInt(line);
        if (n < 1 || n > unverified.size()) {
            System.out.println("  Cancelled.");
            return;
        }
        ContactRecord target = unverified.get(n - 1);
        System.out.println();
        System.out.printf("  You are about to trust:  %s%n", target.peerName);
        System.out.println("  Fingerprint:");
        System.out.println(CryptoService.formatFingerprintForDisplay(target.fingerprint));
        System.out.println();
        System.out.println("  Confirm that this fingerprint matches what you received out-of-band");
        System.out.println("  (e.g. over a phone call or in person).");
        System.out.print("  Mark as trusted? (y/n): ");
        String confirm = scanner.nextLine().strip().toLowerCase();
        if ("y".equals(confirm)) {
            contacts.setTrusted(target.peerId, true);
            System.out.printf("  ✓ %s is now marked as trusted.%n", target.peerName);
        } else {
            System.out.println("  Trust not granted.");
        }
    }
}
