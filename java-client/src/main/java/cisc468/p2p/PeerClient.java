// ─────────────────────────────────────────────────────────────────────────────
// PeerClient – outbound TCP NDJSON (matches peer/client.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.crypto.AEADBadTagException;
import java.security.PrivateKey;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public final class PeerClient {

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int FILE_TRANSFER_TIMEOUT_MS = 30_000;

    private final LocalPeerContext local;
    private final ContactStore contacts;
    private final FileCatalog catalog;
    private final CryptoService crypto;
    private final FileStore files;
    private final StorageKey storageKey;
    private volatile PrivateKey encryptionPrivateKey;
    private volatile boolean lastConnFailed;

    public PeerClient(
            LocalPeerContext local,
            ContactStore contacts,
            FileCatalog catalog,
            CryptoService crypto,
            FileStore files,
            PrivateKey encryptionPrivateKey,
            StorageKey storageKey) {
        this.local = local;
        this.contacts = contacts;
        this.catalog = catalog;
        this.crypto = crypto;
        this.files = files;
        this.encryptionPrivateKey = encryptionPrivateKey;
        this.storageKey = storageKey;
    }

    public boolean sendMessage(String peerIp, int peerPort, Message message) {
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(peerIp, peerPort), CONNECT_TIMEOUT_MS);
            sock.getOutputStream().write(ProtocolJson.encodeMessage(message));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Message sendAndRecv(String peerIp, int peerPort, Message message, int timeoutMs) {
        lastConnFailed = false;
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(peerIp, peerPort), CONNECT_TIMEOUT_MS);
            sock.setSoTimeout(timeoutMs);
            sock.getOutputStream().write(ProtocolJson.encodeMessage(message));
            byte[] raw = SocketUtil.recvLine(sock);
            if (raw.length == 0 || (raw.length == 1 && raw[0] == '\n')) {
                return null;
            }
            return ProtocolJson.decodeMessage(raw);
        } catch (Exception e) {
            lastConnFailed = true;
            System.out.printf("  [ERR] Error communicating with %s:%d - %s%n", peerIp, peerPort, e.getMessage());
            return null;
        }
    }

    public void updateIdentity(LocalIdentity newIdentity) {
        this.encryptionPrivateKey = newIdentity.encryptionPrivateKey();
    }

    public Message sendHello(String peerIp, int peerPort) {
        Message msg = Message.create(MessageType.HELLO, local.peerId, local.peerName, local.port, new JsonObject());
        System.out.printf("  -> [%s] Sending HELLO to %s:%d%n", local.peerName, peerIp, peerPort);
        Message ack = sendAndRecv(peerIp, peerPort, msg, CONNECT_TIMEOUT_MS);
        if (ack != null && MessageType.HELLO_ACK.equals(ack.type)) {
            System.out.printf("  [OK] [%s] HELLO_ACK received from %s%n", local.peerName, ack.sender_name);
            return ack;
        }
        return null;
    }

    public List<FileStore.FileEntry> requestFileList(String peerIp, int peerPort) throws Exception {
        Message req = Message.create(
                MessageType.FILE_LIST_REQUEST, local.peerId, local.peerName, local.port, new JsonObject());
        System.out.printf("  -> [%s] Requesting file list from %s:%d%n", local.peerName, peerIp, peerPort);
        Message resp = sendAndRecv(peerIp, peerPort, req, CONNECT_TIMEOUT_MS);
        if (resp == null) {
            return null;
        }
        if (!MessageType.FILE_LIST_RESPONSE.equals(resp.type)) {
            return null;
        }
        JsonArray files = resp.payload.getAsJsonArray("files");
        List<FileStore.FileEntry> out = new ArrayList<>();
        if (files != null) {
            for (var el : files) {
                JsonObject o = el.getAsJsonObject();
                String name = o.get("filename").getAsString();
                long size = o.get("size").getAsNumber().longValue();
                String sha256 = o.has("sha256") ? o.get("sha256").getAsString() : "";
                out.add(new FileStore.FileEntry(name, size, sha256));
            }
        }
        if (!out.isEmpty()) {
            System.out.printf("  [OK] [%s] %d file(s) shared by %s:%n", local.peerName, out.size(), resp.sender_name);
            int i = 1;
            for (FileStore.FileEntry f : out) {
                String hashPart = (f.sha256() != null && !f.sha256().isBlank())
                        ? "  sha256:" + f.sha256().substring(0, Math.min(12, f.sha256().length())) + "..."
                        : "";
                System.out.printf("      %d.  %s  (%s)%s%n", i++, f.filename(), fmtSize(f.size()), hashPart);
            }
        } else {
            System.out.printf("  [OK] [%s] %s has no shared files.%n", local.peerName, resp.sender_name);
        }
        return out;
    }

    public boolean requestFile(
            String peerIp,
            int peerPort,
            String filename,
            String expectedSha256,
            String originalPeerId,
            Supplier<Map<String, PeerInfo>> getPeers) throws Exception {
        JsonObject p = new JsonObject();
        p.addProperty("filename", filename);
        Message req = Message.create(
                MessageType.FILE_REQUEST, local.peerId, local.peerName, local.port, p);
        System.out.printf("  -> [%s] Requesting '%s' from %s:%d...%n", local.peerName, filename, peerIp, peerPort);
        System.out.printf("     (waiting for %s:%d to accept - up to 30 s)%n", peerIp, peerPort);
        Message resp = sendAndRecv(peerIp, peerPort, req, FILE_TRANSFER_TIMEOUT_MS);
        if (resp == null) {
            if (lastConnFailed
                    && expectedSha256 != null
                    && !expectedSha256.isBlank()
                    && originalPeerId != null
                    && getPeers != null) {
                return tryAlternateSources(filename, expectedSha256, originalPeerId, getPeers);
            }
            return false;
        }
        return processFileTransferResponse(resp, filename, expectedSha256);
    }

    private boolean processFileTransferResponse(Message resp, String filename, String expectedSha256) throws Exception {
        if (MessageType.FILE_TRANSFER.equals(resp.type)) {
            boolean encrypted = resp.payload.has("encrypted") && resp.payload.get("encrypted").getAsBoolean();
            String recvName = resp.payload.has("filename")
                    ? resp.payload.get("filename").getAsString()
                    : filename;
            if (encrypted) {
                return receiveEncryptedFile(resp, recvName, expectedSha256);
            }
            if (!resp.payload.has("data")) {
                return false;
            }
            String b64 = resp.payload.get("data").getAsString();
            files.writeDownloadSecure(recvName, Base64.getDecoder().decode(b64), storageKey);
            System.out.printf("  [OK] '%s' saved to %s%n", recvName, files.downloadsDirDisplay());
            return true;
        }
        if (MessageType.FILE_REJECTED.equals(resp.type)) {
            String reason = resp.payload.has("reason") ? resp.payload.get("reason").getAsString() : "declined";
            System.out.printf(
                    "  [ERR] %s declined to send '%s': %s%n", resp.sender_name, filename, reason);
            return false;
        }
        return false;
    }

    private boolean tryAlternateSources(
            String filename,
            String expectedSha256,
            String originalPeerId,
            Supplier<Map<String, PeerInfo>> getPeers) throws Exception {
        Map<String, PeerInfo> peers = getPeers.get();
        List<String> candidates = catalog.findAlternatePeers(
                filename,
                expectedSha256,
                originalPeerId,
                new ArrayList<>(peers.keySet()));
        if (candidates.isEmpty()) {
            System.out.printf(
                    "  [ERR] No alternate sources found for '%s'.%n     No other known peer has advertised this file with the same hash.%n",
                    filename);
            return false;
        }
        List<String> names = new ArrayList<>();
        for (String pid : candidates) {
            if (peers.containsKey(pid)) {
                names.add(peers.get(pid).peerName);
            }
        }
        System.out.printf(
                "%n  [INFO] Primary peer is offline. Alternate source(s) found:%n     %s%n     The downloaded file will be verified against the original hash.%n",
                String.join(", ", names));
        System.out.print("  Try alternate source? (y/n): ");
        String confirm = new java.util.Scanner(System.in).nextLine().strip().toLowerCase();
        if (!"y".equals(confirm)) {
            System.out.println("  Fallback cancelled.");
            return false;
        }

        for (String pid : candidates) {
            PeerInfo alt = peers.get(pid);
            if (alt == null) {
                continue;
            }
            System.out.printf("%n  -> Trying alternate source: %s @ %s:%d%n", alt.peerName, alt.ip, alt.port);
            JsonObject p = new JsonObject();
            p.addProperty("filename", filename);
            Message req = Message.create(MessageType.FILE_REQUEST, local.peerId, local.peerName, local.port, p);
            System.out.printf("     (waiting up to 30 s for %s to accept)%n", alt.peerName);
            Message resp = sendAndRecv(alt.ip, alt.port, req, FILE_TRANSFER_TIMEOUT_MS);
            if (resp == null) {
                continue;
            }
            if (processFileTransferResponse(resp, filename, expectedSha256)) {
                return true;
            }
        }
        System.out.printf("  [ERR] All alternate sources failed for '%s'.%n", filename);
        return false;
    }

    private boolean receiveEncryptedFile(Message response, String filename, String expectedSha256)
            throws Exception {
        PrivateKey encPriv = this.encryptionPrivateKey;
        if (encPriv == null) {
            System.out.printf("  [ERR] Cannot decrypt '%s' - client has no encryption key.%n", filename);
            return false;
        }
        byte[] ephPub;
        byte[] nonce;
        byte[] ciphertext;
        byte[] signature;
        try {
            ephPub = Base64.getDecoder().decode(response.payload.get("ephemeral_public_key").getAsString());
            nonce = Base64.getDecoder().decode(response.payload.get("nonce").getAsString());
            ciphertext = Base64.getDecoder().decode(response.payload.get("ciphertext").getAsString());
            signature = Base64.getDecoder().decode(response.payload.get("signature").getAsString());
        } catch (Exception e) {
            System.out.printf("  [ERR] Malformed encrypted FILE_TRANSFER for '%s': %s%n", filename, e.getMessage());
            return false;
        }
        ContactRecord contact = contacts.getContact(response.sender_id);
        if (contact == null || contact.publicKey == null || contact.publicKey.isBlank()) {
            System.out.printf(
                    "  [ERR] SECURITY: Cannot verify '%s' from %s - their signing key is not in your contacts.%n"
                            + "     Use menu option 6 (Exchange identity) with this peer first.%n",
                    filename, response.sender_name);
            return false;
        }
        if (!crypto.verifyTransferSignature(contact.publicKey, filename, ephPub, nonce, ciphertext, signature)) {
            System.out.printf(
                    "%n  [ERR] SECURITY WARNING: Signature verification FAILED for '%s' from %s.%n"
                            + "     The file may have been tampered with or sent by an impostor.%n"
                            + "     File discarded - NOT saved.%n%n",
                    filename, response.sender_name);
            return false;
        }
        System.out.printf("  [OK] Signature verified for '%s' (sender: %s)%n", filename, response.sender_name);
        byte[] aesKey = crypto.ecdhDeriveKey(encPriv, ephPub);
        byte[] plaintext;
        try {
            plaintext = crypto.aesGcmDecrypt(aesKey, nonce, ciphertext);
        } catch (AEADBadTagException e) {
            System.out.printf(
                    "%n  [ERR] SECURITY WARNING: Integrity check FAILED for '%s' from %s.%n"
                            + "     The authentication tag is invalid - the ciphertext was corrupted"
                            + " or tampered with.%n     File discarded - NOT saved.%n%n",
                    filename, response.sender_name);
            return false;
        } catch (Exception e) {
            System.out.printf("  [ERR] Decryption error for '%s': %s%n", filename, e.getMessage());
            return false;
        }

        if (expectedSha256 != null && !expectedSha256.isBlank()) {
            String actual = sha256Hex(plaintext);
            if (!actual.equals(expectedSha256)) {
                System.out.printf(
                        "%n  [ERR] SECURITY WARNING: Content hash MISMATCH for '%s'.%n     Expected : %s%n     Received : %s%n     File discarded - NOT saved.%n%n",
                        filename, expectedSha256, actual);
                return false;
            }
            System.out.println("  [OK] Content hash verified (matches original peer's advertised hash)");
        }

        Path dest = files.writeDownloadSecure(filename, plaintext, storageKey);
        long orig = response.payload.has("original_size")
                ? response.payload.get("original_size").getAsLong()
                : plaintext.length;
        String atRest = storageKey != null ? " (encrypted at rest)" : "";
        System.out.printf(
                "  [OK] '%s' decrypted and saved to %s  (%,d bytes)%s%n",
                filename, dest, orig, atRest);
        return true;
    }

    public Message sendIdentityExchange(String peerIp, int peerPort) throws Exception {
        JsonObject p = new JsonObject();
        p.addProperty("peer_id", local.peerId);
        p.addProperty("peer_name", local.peerName);
        p.addProperty("public_key", local.signingPublicKeyPem);
        p.addProperty("encryption_key", local.encryptionPublicKeyPem);
        p.addProperty("fingerprint", local.fingerprint);
        Message req = Message.create(MessageType.IDENTITY_EXCHANGE, local.peerId, local.peerName, local.port, p);
        System.out.printf("  -> [%s] Sending IDENTITY_EXCHANGE to %s:%d%n", local.peerName, peerIp, peerPort);
        Message ack = sendAndRecv(peerIp, peerPort, req, CONNECT_TIMEOUT_MS);
        if (ack == null || !MessageType.IDENTITY_ACK.equals(ack.type)) {
            System.out.printf("  [ERR] No IDENTITY_ACK received from %s:%d%n", peerIp, peerPort);
            return null;
        }
        String pub = ack.payload.has("public_key") ? ack.payload.get("public_key").getAsString() : "";
        String enc = ack.payload.has("encryption_key") ? ack.payload.get("encryption_key").getAsString() : "";
        String fp = ack.payload.has("fingerprint") ? ack.payload.get("fingerprint").getAsString() : "";
        if (!pub.isBlank() && !fp.isBlank()) {
            contacts.saveContact(ack.sender_id, ack.sender_name, pub, fp, false, enc.isBlank() ? null : enc);
            String encStatus = enc.isBlank() ? "signing key only" : "with encryption key";
            System.out.printf(
                    "  [OK] [%s] Identity exchanged with %s (%s)%n", local.peerName, ack.sender_name, encStatus);
            System.out.printf("     Their fingerprint: %s%n", fp);
            System.out.println("     Contact saved as unverified - use 'Trust a contact' to verify.");
        } else {
            System.out.printf(
                    "  [OK] [%s] IDENTITY_ACK from %s (no public key in response)%n",
                    local.peerName, ack.sender_name);
        }
        return ack;
    }

    public boolean sendKeyRotation(
            String peerIp,
            int peerPort,
            LocalIdentity oldIdentity,
            LocalIdentity newIdentity) throws Exception {
        byte[] sig = crypto.signKeyRotation(
                oldIdentity.signingPrivateKey(),
                oldIdentity.fingerprint(),
                newIdentity.signingPublicKeyPem(),
                newIdentity.encryptionPublicKeyPem(),
                newIdentity.fingerprint());

        JsonObject p = new JsonObject();
        p.addProperty("old_fingerprint", oldIdentity.fingerprint());
        p.addProperty("new_public_key", newIdentity.signingPublicKeyPem());
        p.addProperty("new_encryption_key", newIdentity.encryptionPublicKeyPem());
        p.addProperty("new_fingerprint", newIdentity.fingerprint());
        p.addProperty("signature", Base64.getEncoder().encodeToString(sig));
        Message m = Message.create(MessageType.KEY_ROTATION, local.peerId, local.peerName, local.port, p);
        return sendMessage(peerIp, peerPort, m);
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return java.util.HexFormat.of().formatHex(md.digest(data));
    }

    private static String fmtSize(long sizeBytes) {
        if (sizeBytes < 1024) {
            return sizeBytes + " B";
        }
        if (sizeBytes < 1024L * 1024) {
            return String.format("%.1f KB", sizeBytes / 1024.0);
        }
        if (sizeBytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", sizeBytes / (1024.0 * 1024));
        }
        return String.format("%.1f GB", sizeBytes / (1024.0 * 1024 * 1024));
    }
}
