// ─────────────────────────────────────────────────────────────────────────────
// Main.java – Interactive CLI (mirrors main.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;

public final class Main {

    private Main() {}

    public static void main(String[] args) throws Exception {
        Config config = Config.fromUserDir();
        CryptoService crypto = new CryptoService();
        LocalIdentity identity = crypto.loadOrGenerateKeys(config);
        FileStore files = new FileStore(config);
        files.ensureStorageDirs();
        ContactStore contacts = new ContactStore(config);
        FileCatalog catalog = new FileCatalog(config);

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
            int port = portLine.isEmpty() ? Config.DEFAULT_TCP_PORT
                    : (portLine.chars().allMatch(Character::isDigit) ? Integer.parseInt(portLine) : Config.DEFAULT_TCP_PORT);

            System.out.println();
            System.out.println("  Storage passphrase (protects received files at rest).");
            System.out.println("  Use the SAME passphrase every launch. Leave empty to skip.");
            String passphrase = readPassphrase(scanner);
            StorageKey storageKey = null;
            if (!passphrase.isEmpty()) {
                storageKey = StorageKey.derive(config, passphrase);
                System.out.println("  Storage key derived  [OK]");
            } else {
                System.out.println("  WARNING: No passphrase - files will NOT be encrypted at rest.");
            }

            String peerId = UUID.randomUUID().toString();
            String ip = NetUtil.getLocalIp();
            LocalPeerContext local = new LocalPeerContext(
                    peerId, name, ip, port,
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
            LinkedBlockingQueue<String> notificationQueue = new LinkedBlockingQueue<>();

            final LocalIdentity[] identityRef = new LocalIdentity[] {identity};
            PeerClient client = new PeerClient(
                    local, contacts, catalog, crypto, files, identityRef[0].encryptionPrivateKey(), storageKey);

            final PeerDiscovery[] discoveryRef = new PeerDiscovery[1];
            discoveryRef[0] = new PeerDiscovery(local, p -> new Thread(() -> {
                Message ack = client.sendHello(p.ip, p.port);
                if (ack != null) {
                    discoveryRef[0].addPeer(new PeerInfo(ack.sender_id, ack.sender_name, p.ip, ack.sender_port));
                }
            }, "hello-task").start());
            PeerDiscovery discovery = discoveryRef[0];

            PeerServer server = new PeerServer(
                    local,
                    identityRef[0],
                    contacts,
                    crypto,
                    files,
                    consentQueue,
                    notificationQueue,
                    storageKey,
                    (msg, remoteIp) -> {
                        if (MessageType.HELLO.equals(msg.type) || MessageType.HELLO_ACK.equals(msg.type)) {
                            discovery.addPeer(new PeerInfo(msg.sender_id, msg.sender_name, remoteIp, msg.sender_port));
                        }
                    });

            server.start();
            discovery.start();

            System.out.println();
            System.out.println("  Services started. Other peers will appear automatically.");
            System.out.println("  File requests will prompt you here before the menu.");

            try {
                menuLoop(scanner, discovery, client, local, contacts, catalog, consentQueue, notificationQueue, identityRef, crypto, files, storageKey, config, server);
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
            FileCatalog catalog,
            LinkedBlockingQueue<PendingConsentRequest> consentQueue,
            LinkedBlockingQueue<String> notificationQueue,
            LocalIdentity[] identityRef,
            CryptoService crypto,
            FileStore files,
            StorageKey storageKey,
            Config config,
            PeerServer server) throws Exception {

        while (true) {
            while (!notificationQueue.isEmpty()) {
                String msg = notificationQueue.poll();
                if (msg != null) {
                    System.out.println(msg);
                }
            }
            handlePendingConsents(scanner, consentQueue);
            System.out.println();
            printMenu();
            System.out.print("  Your choice: ");
            String choice = scanner.nextLine().strip();

            switch (choice) {
                case "1" -> actionShowPeers(discovery);
                case "2" -> actionShowSharedFiles(files, storageKey);
                case "3" -> actionSendHello(scanner, discovery, client);
                case "4" -> actionRequestFileList(scanner, discovery, client, catalog);
                case "5" -> actionRequestFile(scanner, discovery, client, catalog);
                case "6" -> actionExchangeIdentity(scanner, discovery, client);
                case "7" -> actionShowFingerprint(local);
                case "8" -> actionShowContacts(contacts);
                case "9" -> actionTrustContact(scanner, contacts);
                case "10" -> actionRotateKeys(scanner, local, discovery, client, contacts, crypto, config, identityRef, server);
                case "11" -> actionImportFile(scanner, files, storageKey);
                case "12" -> actionShowDownloadedFiles(files, storageKey);
                case "0" -> {
                    System.out.println("  Goodbye!");
                    return;
                }
                default -> System.out.println("  Please enter 0-12.");
            }
        }
    }

    private static void handlePendingConsents(Scanner scanner, LinkedBlockingQueue<PendingConsentRequest> queue) {
        while (true) {
            PendingConsentRequest req = queue.poll();
            if (req == null) break;
            if (req.timedOut()) {
                System.out.printf("%n  (request from %s for '%s' expired before you could respond)%n%n", req.peerName, req.filename);
                continue;
            }
            System.out.println();
            System.out.println("  -----------------------------------------");
            System.out.printf("  [REQUEST] %s wants \"%s\"%n", req.peerName, req.filename);
            System.out.printf("  from %s:%d%n", req.peerIp, req.peerPort);
            System.out.println("  -----------------------------------------");
            System.out.print("  Accept? (y/n): ");
            String answer = scanner.nextLine().strip().toLowerCase();
            if ("y".equals(answer)) {
                System.out.printf("  [OK] Accepted - sending '%s' to %s...%n", req.filename, req.peerName);
                req.resolve(true);
            } else {
                System.out.printf("  [NO] Declined - '%s' will not be sent.%n", req.filename);
                req.resolve(false);
            }
            System.out.println();
        }
    }

    private static void printMenu() {
        System.out.println("-".repeat(44));
        System.out.println("  MENU");
        System.out.println("-".repeat(44));
        System.out.println("  1  -  Show discovered peers");
        System.out.println("  2  -  Show my shared files");
        System.out.println("  3  -  Send HELLO to a peer");
        System.out.println("  4  -  Request file list from a peer");
        System.out.println("  5  -  Request a file from a peer");
        System.out.println("  " + "-".repeat(21));
        System.out.println("  6  -  Exchange identity with a peer");
        System.out.println("  7  -  Show my fingerprint");
        System.out.println("  8  -  Show contacts");
        System.out.println("  9  -  Trust a contact");
        System.out.println("  " + "-".repeat(21));
        System.out.println("  10 -  Rotate my keys (key migration)");
        System.out.println("  11 -  Import a file to share");
        System.out.println("  12 -  Show downloaded files");
        System.out.println("  " + "-".repeat(21));
        System.out.println("  0  -  Exit");
        System.out.println("-".repeat(44));
    }

    private static PeerInfo pickPeer(Scanner scanner, PeerDiscovery discovery) {
        List<PeerInfo> peers = new ArrayList<>(discovery.getPeers().values());
        if (peers.isEmpty()) {
            System.out.println("  No peers discovered yet - wait a moment and try again.");
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
        String choice = scanner.nextLine().strip();
        if (choice.chars().allMatch(Character::isDigit)) {
            int n = Integer.parseInt(choice);
            if (n >= 1 && n <= peers.size()) {
                return peers.get(n - 1);
            }
        }
        System.out.println("  Invalid choice.");
        return null;
    }

    private static void actionShowPeers(PeerDiscovery discovery) {
        var peers = discovery.getPeers();
        if (peers.isEmpty()) {
            System.out.println("  No peers discovered yet.");
            return;
        }
        System.out.printf("  %d peer(s) on the network:%n", peers.size());
        for (PeerInfo p : peers.values()) {
            String shortId = p.peerId.substring(0, Math.min(8, p.peerId.length()));
            System.out.printf("    *  %-15s  addr: %s:%d  id: %s...%n", p.peerName, p.ip, p.port, shortId);
        }
    }

    private static void actionShowSharedFiles(FileStore files, StorageKey storageKey) throws Exception {
        var list = files.listSharedFiles(storageKey);
        if (list.isEmpty()) {
            System.out.printf("  No files in %s/%n", Config.SHARED_DIR);
            System.out.println("  Drop plain files there, or use menu 11 to import an encrypted copy.");
            return;
        }
        System.out.printf("  %d file(s) in %s/:%n", list.size(), Config.SHARED_DIR);
        int i = 1;
        for (FileStore.FileEntry f : list) {
            String hashPart = (f.sha256() != null && !f.sha256().isBlank())
                    ? "  sha256:" + f.sha256().substring(0, Math.min(12, f.sha256().length())) + "..."
                    : "";
            System.out.printf("    %d.  %-30s  %s%s%n", i++, f.filename(), fmtSize(f.size()), hashPart);
        }
    }

    private static void actionSendHello(Scanner scanner, PeerDiscovery discovery, PeerClient client) {
        PeerInfo p = pickPeer(scanner, discovery);
        if (p != null) client.sendHello(p.ip, p.port);
    }

    private static void actionRequestFileList(Scanner scanner, PeerDiscovery discovery, PeerClient client, FileCatalog catalog) throws Exception {
        PeerInfo p = pickPeer(scanner, discovery);
        if (p == null) return;
        List<FileStore.FileEntry> files = client.requestFileList(p.ip, p.port);
        if (files != null) {
            catalog.update(p.peerId, p.peerName, files);
        }
    }

    private static void actionRequestFile(Scanner scanner, PeerDiscovery discovery, PeerClient client, FileCatalog catalog) throws Exception {
        PeerInfo p = pickPeer(scanner, discovery);
        if (p == null) return;
        List<FileStore.FileEntry> files = client.requestFileList(p.ip, p.port);
        if (files == null) {
            files = catalog.getPeerFiles(p.peerId);
            if (!files.isEmpty()) {
                System.out.printf("%n  [ERR] %s is offline.  Showing cached file list:%n%n", p.peerName);
                int i = 1;
                for (FileStore.FileEntry f : files) {
                    String hashPart = (f.sha256() != null && !f.sha256().isBlank())
                            ? "  sha256:" + f.sha256().substring(0, Math.min(12, f.sha256().length())) + "..."
                            : "";
                    System.out.printf("    %d.  %-30s%s%n", i++, f.filename(), hashPart);
                }
            } else {
                System.out.println("  Could not retrieve file list - cannot continue.");
                return;
            }
        } else {
            catalog.update(p.peerId, p.peerName, files);
        }
        if (files.isEmpty()) {
            System.out.printf("  %s has no shared files.%n", p.peerName);
            return;
        }
        System.out.print("  Enter file number to request: ");
        String choice = scanner.nextLine().strip();
        if (!choice.chars().allMatch(Character::isDigit)) {
            System.out.println("  Invalid choice.");
            return;
        }
        int n = Integer.parseInt(choice);
        if (n < 1 || n > files.size()) {
            System.out.println("  Invalid choice.");
            return;
        }
        FileStore.FileEntry chosen = files.get(n - 1);
        String expectedHash = chosen.sha256();
        if (expectedHash == null || expectedHash.isBlank()) {
            expectedHash = catalog.getExpectedHash(p.peerId, chosen.filename());
        }
        client.requestFile(
                p.ip,
                p.port,
                chosen.filename(),
                expectedHash,
                p.peerId,
                discovery::getPeers);
    }

    private static void actionExchangeIdentity(Scanner scanner, PeerDiscovery discovery, PeerClient client) throws Exception {
        PeerInfo p = pickPeer(scanner, discovery);
        if (p != null) client.sendIdentityExchange(p.ip, p.port);
    }

    private static void actionShowFingerprint(LocalPeerContext local) {
        System.out.println();
        System.out.println("  My public-key fingerprint (SHA-256):");
        System.out.println(CryptoService.formatFingerprintForDisplay(local.fingerprint));
        System.out.println();
        System.out.println("  Share this fingerprint with other peers so they can verify");
        System.out.println("  your identity out-of-band (phone call, in person, etc.).");
    }

    private static void actionShowContacts(ContactStore contacts) throws Exception {
        var list = contacts.listContacts();
        if (list.isEmpty()) {
            System.out.println("  No contacts yet.");
            System.out.println("  Use 'Exchange identity' (menu 6) to populate this list.");
            return;
        }
        System.out.printf("  %d contact(s):%n", list.size());
        int i = 1;
        for (ContactRecord c : list) {
            String trustLabel = c.trusted ? "trusted" : "unverified";
            String shortId = c.peerId.substring(0, Math.min(8, c.peerId.length()));
            System.out.printf("  %2d.  [%s]  %-15s  %s...%n", i++, trustLabel, c.peerName, shortId);
            System.out.printf("         Fingerprint: %s%n", c.fingerprint);
        }
    }

    private static void actionTrustContact(Scanner scanner, ContactStore contacts) throws Exception {
        List<ContactRecord> all = contacts.listContacts();
        List<ContactRecord> unverified = new ArrayList<>();
        for (ContactRecord c : all) if (!c.trusted) unverified.add(c);
        if (unverified.isEmpty()) {
            System.out.println("  No unverified contacts to trust.");
            return;
        }
        System.out.printf("  %d unverified contact(s):%n", unverified.size());
        for (int i = 0; i < unverified.size(); i++) {
            ContactRecord c = unverified.get(i);
            String shortId = c.peerId.substring(0, Math.min(8, c.peerId.length()));
            System.out.printf("  %2d.  %-15s  %s...%n", i + 1, c.peerName, shortId);
            System.out.printf("         Fingerprint: %s%n", c.fingerprint);
        }
        System.out.print("  Enter contact number to trust (or Enter to cancel): ");
        String choice = scanner.nextLine().strip();
        if (choice.isBlank() || !choice.chars().allMatch(Character::isDigit)) {
            System.out.println("  Cancelled.");
            return;
        }
        int n = Integer.parseInt(choice);
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
            System.out.printf("  [OK] %s is now marked as trusted.%n", target.peerName);
        } else {
            System.out.println("  Trust not granted.");
        }
    }

    private static void actionRotateKeys(
            Scanner scanner,
            LocalPeerContext local,
            PeerDiscovery discovery,
            PeerClient client,
            ContactStore contacts,
            CryptoService crypto,
            Config config,
            LocalIdentity[] identityRef,
            PeerServer server) throws Exception {
        System.out.println();
        System.out.println("  -----------------------------------------------------");
        System.out.println("  KEY ROTATION");
        System.out.println("  This generates a new long-term Ed25519 + X25519 key pair.");
        System.out.println("  All currently online contacts will be notified automatically.");
        System.out.println("  You will need to re-verify your fingerprint with each contact.");
        System.out.println("  -----------------------------------------------------");
        System.out.print("  Proceed with key rotation? (y/n): ");
        if (!"y".equals(scanner.nextLine().strip().toLowerCase())) {
            System.out.println("  Rotation cancelled.");
            return;
        }

        LocalIdentity oldIdentity = identityRef[0];
        LocalIdentity newIdentity = crypto.rotateKeys(config);
        System.out.println("\n  [OK] New keys generated.");
        System.out.println("  New fingerprint:");
        System.out.println(CryptoService.formatFingerprintForDisplay(newIdentity.fingerprint()));

        var onlinePeers = discovery.getPeers();
        var contactList = contacts.listContacts();
        var contactIds = new java.util.HashSet<String>();
        for (ContactRecord c : contactList) contactIds.add(c.peerId);
        int notified = 0;
        for (PeerInfo peer : onlinePeers.values()) {
            if (!contactIds.contains(peer.peerId)) continue;
            boolean ok = client.sendKeyRotation(peer.ip, peer.port, oldIdentity, newIdentity);
            if (ok) {
                System.out.printf("  -> KEY_ROTATION sent to %s%n", peer.peerName);
                notified++;
            } else {
                System.out.printf("  [ERR] Could not reach %s (they are in contacts but offline now)%n", peer.peerName);
            }
        }
        if (notified == 0) {
            System.out.println("  (No online contacts found to notify.)");
        }

        identityRef[0] = newIdentity;
        local.signingPublicKeyPem = newIdentity.signingPublicKeyPem();
        local.encryptionPublicKeyPem = newIdentity.encryptionPublicKeyPem();
        local.fingerprint = newIdentity.fingerprint();
        client.updateIdentity(newIdentity);
        server.updateIdentity(newIdentity);

        System.out.println(
                "\n  [OK] Key rotation complete.\n"
                        + "  Contacts that were offline were not notified automatically.\n"
                        + "  Re-run 'Exchange identity' with them after they come back online.\n"
                        + "  You should also re-verify your NEW fingerprint with all contacts.\n");
    }

    private static void actionImportFile(Scanner scanner, FileStore files, StorageKey storageKey) {
        System.out.println("  Enter the full path of the file you want to share.");
        System.out.println("  (Type 'cancel' to abort)");
        System.out.print("  File path: ");
        String path = scanner.nextLine().strip();
        if (path.isEmpty() || "cancel".equalsIgnoreCase(path)) {
            System.out.println("  Cancelled.");
            return;
        }
        try {
            var dest = files.importFileToShared(path, storageKey);
            String encNote = storageKey != null ? " (encrypted at rest)" : "";
            System.out.printf("  [OK] File imported to %s%s%n", dest, encNote);
        } catch (Exception e) {
            System.out.printf("  [ERR] Import failed: %s%n", e.getMessage());
        }
    }

    private static void actionShowDownloadedFiles(FileStore files, StorageKey storageKey) throws Exception {
        var list = files.listDownloadedFiles(storageKey);
        if (list.isEmpty()) {
            System.out.printf("  No files in %s/%n", Config.DOWNLOADS_DIR);
            return;
        }
        System.out.printf("  %d downloaded file(s) in %s/: %n", list.size(), Config.DOWNLOADS_DIR);
        int i = 1;
        for (FileStore.FileEntry f : list) {
            System.out.printf("    %d.  %-30s  %s%n", i++, f.filename(), fmtSize(f.size()));
        }
        if (storageKey != null) {
            System.out.println("  (files are encrypted at rest)");
        }
    }

    private static String fmtSize(long sizeBytes) {
        if (sizeBytes < 1024) return sizeBytes + " B";
        if (sizeBytes < 1024L * 1024) return String.format("%.1f KB", sizeBytes / 1024.0);
        if (sizeBytes < 1024L * 1024 * 1024) return String.format("%.1f MB", sizeBytes / (1024.0 * 1024));
        return String.format("%.1f GB", sizeBytes / (1024.0 * 1024 * 1024));
    }

    private static String readPassphrase(Scanner scanner) {
        java.io.Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("  Passphrase: ");
            return chars != null ? new String(chars) : "";
        }
        // Integrated terminals sometimes run without a Console handle.
        System.out.print("  Passphrase: ");
        return scanner.nextLine();
    }
}
