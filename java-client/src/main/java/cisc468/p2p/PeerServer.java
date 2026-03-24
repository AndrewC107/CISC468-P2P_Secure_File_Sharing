// ─────────────────────────────────────────────────────────────────────────────
// PeerServer – TCP NDJSON server (matches peer/server.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.JsonObject;

import javax.crypto.AEADBadTagException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;

public final class PeerServer implements AutoCloseable {

    private static final double CONSENT_TIMEOUT_SEC = 25.0;

    private final LocalPeerContext local;
    private final LocalIdentity identity;
    private final ContactStore contacts;
    private final CryptoService crypto;
    private final FileStore files;
    private final BlockingQueue<PendingConsentRequest> consentQueue;
    private final BiConsumer<Message, String> onMessage; // (message, remoteIp)

    private volatile boolean running;
    private ServerSocket serverSocket;
    private ExecutorService pool;

    public PeerServer(
            LocalPeerContext local,
            LocalIdentity identity,
            ContactStore contacts,
            CryptoService crypto,
            FileStore files,
            BlockingQueue<PendingConsentRequest> consentQueue,
            BiConsumer<Message, String> onMessage) {
        this.local = local;
        this.identity = identity;
        this.contacts = contacts;
        this.crypto = crypto;
        this.files = files;
        this.consentQueue = consentQueue;
        this.onMessage = onMessage;
    }

    public void start() throws Exception {
        running = true;
        serverSocket = new ServerSocket(local.port);
        serverSocket.setSoTimeout(1000);
        pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "tcp-conn");
            t.setDaemon(true);
            return t;
        });
        System.out.printf("  → [%s] TCP server listening on port %d%n", local.peerName, local.port);
        Thread acceptLoop =
                new Thread(
                        () -> {
                            while (running) {
                                try {
                                    Socket conn = serverSocket.accept();
                                    pool.execute(() -> handleConnection(conn));
                                } catch (java.net.SocketTimeoutException e) {
                                    // continue
                                } catch (Exception e) {
                                    if (running) {
                                        break;
                                    }
                                }
                            }
                        },
                        "tcp-accept");
        acceptLoop.setDaemon(true);
        acceptLoop.start();
    }

    @Override
    public void close() throws Exception {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
        if (pool != null) {
            pool.shutdown();
        }
    }

    private void handleConnection(Socket conn) {
        try (conn) {
            conn.setSoTimeout(120_000);
            byte[] raw = SocketUtil.recvLine(conn);
            if (raw.length == 0) {
                return;
            }
            Message message;
            try {
                message = ProtocolJson.decodeMessage(raw);
            } catch (Exception e) {
                System.out.printf(
                        "  ✗ [%s] Invalid message from %s – %s%n",
                        local.peerName, conn.getInetAddress().getHostAddress(), e.getMessage());
                return;
            }
            printReceived(message, conn.getInetAddress().getHostAddress());
            Message response = dispatch(message, conn.getInetAddress().getHostAddress());
            if (response != null) {
                OutputStream out = conn.getOutputStream();
                out.write(ProtocolJson.encodeMessage(response));
                out.flush();
            }
            if (onMessage != null) {
                onMessage.accept(message, conn.getInetAddress().getHostAddress());
            }
        } catch (Exception e) {
            // connection error
        }
    }

    private Message dispatch(Message message, String remoteIp) throws Exception {
        return switch (message.type) {
            case MessageType.HELLO -> handleHello();
            case MessageType.FILE_LIST_REQUEST -> handleFileListRequest();
            case MessageType.FILE_REQUEST -> handleFileRequest(message, remoteIp);
            case MessageType.FILE_TRANSFER -> {
                handleFileTransfer(message);
                yield null;
            }
            case MessageType.IDENTITY_EXCHANGE -> handleIdentityExchange(message);
            default -> null;
        };
    }

    private Message handleHello() {
        return Message.create(MessageType.HELLO_ACK, local.peerId, local.peerName, local.port, new JsonObject());
    }

    private Message handleFileListRequest() throws Exception {
        JsonObject p = new JsonObject();
        p.add("files", files.listSharedFilesJson());
        return Message.create(
                MessageType.FILE_LIST_RESPONSE, local.peerId, local.peerName, local.port, p);
    }

    private Message handleFileRequest(Message message, String requesterIp) throws Exception {
        String filename = message.payload.has("filename") ? message.payload.get("filename").getAsString() : "";
        String senderId = message.sender_id;
        ContactRecord contact = contacts.getContact(senderId);
        if (contact == null || contact.encryptionKey == null || contact.encryptionKey.isBlank()) {
            return rejected(filename, "encrypted transfer requires identity exchange – ask the requester to use menu option 6 (Exchange identity) first");
        }
        if (identity.signingPrivateKey() == null) {
            return rejected(filename, "server has no signing key configured – restart the application");
        }
        if (consentQueue == null) {
            return rejected(filename, "server not configured for file transfer");
        }
        PendingConsentRequest req =
                new PendingConsentRequest(message.sender_name, senderId, requesterIp, message.sender_port, filename);
        System.out.printf(
                "%n  ⚑  [%s] %s wants to receive '%s'%n     Press Enter at the menu to accept or decline.%n%n",
                local.peerName, message.sender_name, filename);
        consentQueue.put(req);
        boolean accepted = req.waitForDecision(CONSENT_TIMEOUT_SEC);
        if (!accepted) {
            return rejected(filename, "declined by user");
        }
        byte[] plaintext = files.readSharedFileBytes(filename);
        if (plaintext == null) {
            System.out.printf("  ✗ [%s] File '%s' not found in storage/shared/%n", local.peerName, filename);
            return rejected(filename, "file not found");
        }
        try {
            var ephPair = crypto.generateEphemeralX25519();
            byte[] ephPubRaw = crypto.x25519PublicKeyRaw(ephPair.getPublic());
            byte[] receiverRaw = crypto.x25519PublicRawFromPem(contact.encryptionKey);
            byte[] aesKey = crypto.ecdhDeriveKey(ephPair.getPrivate(), receiverRaw);
            CryptoService.AesGcmPacket packet = crypto.aesGcmEncrypt(aesKey, plaintext);
            byte[] signature =
                    crypto.signTransfer(
                            identity.signingPrivateKey(),
                            filename,
                            ephPubRaw,
                            packet.nonce(),
                            packet.ciphertext());
            JsonObject p = new JsonObject();
            p.addProperty("filename", filename);
            p.addProperty("encrypted", true);
            p.addProperty("ephemeral_public_key", Base64.getEncoder().encodeToString(ephPubRaw));
            p.addProperty("nonce", Base64.getEncoder().encodeToString(packet.nonce()));
            p.addProperty("ciphertext", Base64.getEncoder().encodeToString(packet.ciphertext()));
            p.addProperty("signature", Base64.getEncoder().encodeToString(signature));
            p.addProperty("original_size", plaintext.length);
            System.out.printf("  🔒 [%s] Sending '%s' encrypted to %s%n", local.peerName, filename, message.sender_name);
            return Message.create(
                    MessageType.FILE_TRANSFER, local.peerId, local.peerName, local.port, p);
        } catch (Exception e) {
            return rejected(filename, "encryption error");
        }
    }

    private Message rejected(String filename, String reason) {
        JsonObject p = new JsonObject();
        p.addProperty("filename", filename);
        p.addProperty("reason", reason);
        return Message.create(
                MessageType.FILE_REJECTED, local.peerId, local.peerName, local.port, p);
    }

    private void handleFileTransfer(Message message) throws Exception {
        String filename = message.payload.has("filename") ? message.payload.get("filename").getAsString() : "received_file";
        boolean encrypted = message.payload.has("encrypted") && message.payload.get("encrypted").getAsBoolean();
        if (!encrypted) {
            if (!message.payload.has("data")) {
                return;
            }
            String b64 = message.payload.get("data").getAsString();
            files.writeDownload(filename, Base64.getDecoder().decode(b64));
            System.out.printf("%n  ✓ File received: '%s' saved to %s%n", filename, files.downloadsDirDisplay());
            return;
        }
        receiveEncryptedPush(message, filename);
    }

    private void receiveEncryptedPush(Message message, String filename) throws Exception {
        if (identity.encryptionPrivateKey() == null) {
            System.out.printf("  ✗ Cannot decrypt '%s' – no encryption key configured.%n", filename);
            return;
        }
        byte[] ephPub;
        byte[] nonce;
        byte[] ciphertext;
        byte[] signature;
        try {
            ephPub = Base64.getDecoder().decode(message.payload.get("ephemeral_public_key").getAsString());
            nonce = Base64.getDecoder().decode(message.payload.get("nonce").getAsString());
            ciphertext = Base64.getDecoder().decode(message.payload.get("ciphertext").getAsString());
            signature = Base64.getDecoder().decode(message.payload.get("signature").getAsString());
        } catch (Exception e) {
            System.out.printf(
                    "  ✗ Malformed encrypted FILE_TRANSFER from %s: %s%n", message.sender_name, e.getMessage());
            return;
        }
        ContactRecord contact = contacts.getContact(message.sender_id);
        if (contact == null || contact.publicKey == null || contact.publicKey.isBlank()) {
            System.out.printf(
                    "  ✗ SECURITY: Cannot verify '%s' from %s – no signing key in contacts. Exchange identities first.%n",
                    filename, message.sender_name);
            return;
        }
        if (!crypto.verifyTransferSignature(contact.publicKey, filename, ephPub, nonce, ciphertext, signature)) {
            System.out.printf(
                    "%n  ✗ SECURITY WARNING: Signature verification FAILED for '%s' from %s.%n"
                            + "     The file may have been tampered with or sent by an impostor.%n     File discarded.%n%n",
                    filename, message.sender_name);
            return;
        }
        byte[] aesKey = crypto.ecdhDeriveKey(identity.encryptionPrivateKey(), ephPub);
        byte[] plaintext;
        try {
            plaintext = crypto.aesGcmDecrypt(aesKey, nonce, ciphertext);
        } catch (AEADBadTagException e) {
            System.out.printf(
                    "%n  ✗ SECURITY WARNING: Integrity check FAILED for '%s' from %s.%n"
                            + "     The ciphertext authentication tag is invalid – data was corrupted or tampered with.%n"
                            + "     File discarded.%n%n",
                    filename, message.sender_name);
            return;
        }
        files.writeDownload(filename, plaintext);
        System.out.printf(
                "%n  ✓ 🔓 File received and decrypted: '%s' saved to %s  (%,d bytes, signature verified)%n%n",
                filename, files.downloadsDir().resolve(filename), plaintext.length);
    }

    private Message handleIdentityExchange(Message message) throws Exception {
        JsonObject pl = message.payload;
        String publicKey = pl.has("public_key") ? pl.get("public_key").getAsString() : "";
        String encryptionKey = pl.has("encryption_key") ? pl.get("encryption_key").getAsString() : "";
        String fingerprint = pl.has("fingerprint") ? pl.get("fingerprint").getAsString() : "";
        if (!publicKey.isBlank() && !fingerprint.isBlank()) {
            contacts.saveContact(
                    message.sender_id,
                    message.sender_name,
                    publicKey,
                    fingerprint,
                    false,
                    encryptionKey.isBlank() ? null : encryptionKey);
            System.out.printf(
                    "%n  ⚿  [%s] Identity received from %s – saved to contacts (unverified)%n     Fingerprint: %s%n%n",
                    local.peerName, message.sender_name, fingerprint);
        }
        JsonObject ackP = new JsonObject();
        ackP.addProperty("peer_id", local.peerId);
        ackP.addProperty("peer_name", local.peerName);
        ackP.addProperty("public_key", local.signingPublicKeyPem);
        ackP.addProperty("encryption_key", local.encryptionPublicKeyPem);
        ackP.addProperty("fingerprint", local.fingerprint);
        return Message.create(
                MessageType.IDENTITY_ACK, local.peerId, local.peerName, local.port, ackP);
    }

    private void printReceived(Message message, String host) {
        String tag = message.type.toUpperCase().replace('-', '_');
        String sender = message.sender_name + " @ " + host;
        switch (message.type) {
            case MessageType.HELLO -> System.out.printf(
                    "  ← [%s] %s from %s – sending ACK%n", local.peerName, tag, sender);
            case MessageType.HELLO_ACK -> System.out.printf("  ← [%s] %s from %s%n", local.peerName, tag, sender);
            case MessageType.FILE_LIST_REQUEST -> System.out.printf(
                    "  ← [%s] %s from %s – sending file list%n", local.peerName, tag, sender);
            case MessageType.FILE_TRANSFER -> {
                String fn = message.payload.has("filename") ? message.payload.get("filename").getAsString() : "?";
                System.out.printf("  ← [%s] %s from %s: '%s'%n", local.peerName, tag, sender, fn);
            }
            case MessageType.FILE_REJECTED -> {
                String fn = message.payload.has("filename") ? message.payload.get("filename").getAsString() : "?";
                String reason =
                        message.payload.has("reason") ? message.payload.get("reason").getAsString() : "declined";
                System.out.printf(
                        "  ← [%s] %s from %s: '%s' – %s%n", local.peerName, tag, sender, fn, reason);
            }
            case MessageType.IDENTITY_EXCHANGE -> {
                String fp = message.payload.has("fingerprint") ? message.payload.get("fingerprint").getAsString() : "?";
                System.out.printf(
                        "  ← [%s] %s from %s – sending ACK%n     Their fingerprint: %s%n",
                        local.peerName, tag, sender, fp);
            }
            case MessageType.IDENTITY_ACK -> {
                String fp = message.payload.has("fingerprint") ? message.payload.get("fingerprint").getAsString() : "?";
                System.out.printf(
                        "  ← [%s] %s from %s%n     Their fingerprint: %s%n", local.peerName, tag, sender, fp);
            }
            default -> {
                /* quiet */
            }
        }
    }
}
