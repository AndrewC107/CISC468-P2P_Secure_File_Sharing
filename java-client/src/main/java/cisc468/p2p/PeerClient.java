// ─────────────────────────────────────────────────────────────────────────────
// PeerClient – outbound TCP NDJSON (matches peer/client.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.crypto.AEADBadTagException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class PeerClient {

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int FILE_TRANSFER_TIMEOUT_MS = 30_000;

    private final LocalPeerContext local;
    private final ContactStore contacts;
    private final CryptoService crypto;
    private final FileStore files;

    public PeerClient(LocalPeerContext local, ContactStore contacts, CryptoService crypto, FileStore files) {
        this.local = local;
        this.contacts = contacts;
        this.crypto = crypto;
        this.files = files;
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
            System.out.printf("  ✗ Error communicating with %s:%d – %s%n", peerIp, peerPort, e.getMessage());
            return null;
        }
    }

    public Message sendHello(String peerIp, int peerPort) {
        Message msg = Message.create(MessageType.HELLO, local.peerId, local.peerName, local.port, new JsonObject());
        System.out.printf("  → [%s] Sending HELLO to %s:%d%n", local.peerName, peerIp, peerPort);
        Message ack = sendAndRecv(peerIp, peerPort, msg, CONNECT_TIMEOUT_MS);
        if (ack != null && MessageType.HELLO_ACK.equals(ack.type)) {
            System.out.printf("  ✓ [%s] HELLO_ACK received from %s%n", local.peerName, ack.sender_name);
            return ack;
        }
        return null;
    }

    public List<FileStore.FileEntry> requestFileList(String peerIp, int peerPort) throws Exception {
        Message req = Message.create(
                MessageType.FILE_LIST_REQUEST, local.peerId, local.peerName, local.port, new JsonObject());
        System.out.printf("  → [%s] Requesting file list from %s:%d%n", local.peerName, peerIp, peerPort);
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
                out.add(new FileStore.FileEntry(name, size));
            }
        }
        if (!out.isEmpty()) {
            System.out.printf("  ✓ [%s] %d file(s) shared by %s:%n", local.peerName, out.size(), resp.sender_name);
            int i = 1;
            for (FileStore.FileEntry f : out) {
                System.out.printf("      %d.  %s  (%s)%n", i++, f.filename(), fmtSize(f.size()));
            }
        } else {
            System.out.printf("  ✓ [%s] %s has no shared files.%n", local.peerName, resp.sender_name);
        }
        return out;
    }

    public boolean requestFile(
            String peerIp,
            int peerPort,
            String filename,
            java.security.PrivateKey encryptionPrivateKey) throws Exception {
        JsonObject p = new JsonObject();
        p.addProperty("filename", filename);
        Message req = Message.create(
                MessageType.FILE_REQUEST, local.peerId, local.peerName, local.port, p);
        System.out.printf("  → [%s] Requesting '%s' from %s:%d…%n", local.peerName, filename, peerIp, peerPort);
        System.out.printf("     (waiting for %s:%d to accept – up to 30 s)%n", peerIp, peerPort);
        Message resp = sendAndRecv(peerIp, peerPort, req, FILE_TRANSFER_TIMEOUT_MS);
        if (resp == null) {
            return false;
        }
        if (MessageType.FILE_TRANSFER.equals(resp.type)) {
            boolean encrypted = resp.payload.has("encrypted") && resp.payload.get("encrypted").getAsBoolean();
            String recvName = resp.payload.has("filename")
                    ? resp.payload.get("filename").getAsString()
                    : filename;
            if (encrypted) {
                return receiveEncryptedFile(resp, recvName, encryptionPrivateKey);
            }
            if (!resp.payload.has("data")) {
                return false;
            }
            String b64 = resp.payload.get("data").getAsString();
            files.writeDownload(recvName, Base64.getDecoder().decode(b64));
            System.out.printf("  ✓ '%s' saved to %s%n", recvName, files.downloadsDirDisplay());
            return true;
        }
        if (MessageType.FILE_REJECTED.equals(resp.type)) {
            String reason = resp.payload.has("reason") ? resp.payload.get("reason").getAsString() : "declined";
            System.out.printf(
                    "  ✗ %s declined to send '%s': %s%n", resp.sender_name, filename, reason);
            return false;
        }
        return false;
    }

    private boolean receiveEncryptedFile(Message response, String filename, java.security.PrivateKey encPriv)
            throws Exception {
        if (encPriv == null) {
            System.out.printf("  ✗ Cannot decrypt '%s' – client has no encryption key.%n", filename);
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
            System.out.printf("  ✗ Malformed encrypted FILE_TRANSFER for '%s': %s%n", filename, e.getMessage());
            return false;
        }
        ContactRecord contact = contacts.getContact(response.sender_id);
        if (contact == null || contact.publicKey == null || contact.publicKey.isBlank()) {
            System.out.printf(
                    "  ✗ SECURITY: Cannot verify '%s' from %s – their signing key is not in your contacts.%n"
                            + "     Use menu option 6 (Exchange identity) with this peer first.%n",
                    filename, response.sender_name);
            return false;
        }
        if (!crypto.verifyTransferSignature(contact.publicKey, filename, ephPub, nonce, ciphertext, signature)) {
            System.out.printf(
                    "%n  ✗ SECURITY WARNING: Signature verification FAILED for '%s' from %s.%n"
                            + "     The file may have been tampered with or sent by an impostor.%n"
                            + "     File discarded – NOT saved.%n%n",
                    filename, response.sender_name);
            return false;
        }
        System.out.printf("  ✓ Signature verified for '%s' (sender: %s)%n", filename, response.sender_name);
        byte[] aesKey = crypto.ecdhDeriveKey(encPriv, ephPub);
        byte[] plaintext;
        try {
            plaintext = crypto.aesGcmDecrypt(aesKey, nonce, ciphertext);
        } catch (AEADBadTagException e) {
            System.out.printf(
                    "%n  ✗ SECURITY WARNING: Integrity check FAILED for '%s' from %s.%n"
                            + "     The authentication tag is invalid – the ciphertext was corrupted"
                            + " or tampered with.%n     File discarded – NOT saved.%n%n",
                    filename, response.sender_name);
            return false;
        } catch (Exception e) {
            System.out.printf("  ✗ Decryption error for '%s': %s%n", filename, e.getMessage());
            return false;
        }
        files.writeDownload(filename, plaintext);
        long orig = response.payload.has("original_size")
                ? response.payload.get("original_size").getAsLong()
                : plaintext.length;
        Path dest = files.downloadsDir().resolve(filename);
        System.out.printf(
                "  ✓ 🔓 '%s' decrypted and saved to %s  (%,d bytes)%n",
                filename, dest, orig);
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
        System.out.printf("  → [%s] Sending IDENTITY_EXCHANGE to %s:%d%n", local.peerName, peerIp, peerPort);
        Message ack = sendAndRecv(peerIp, peerPort, req, CONNECT_TIMEOUT_MS);
        if (ack == null || !MessageType.IDENTITY_ACK.equals(ack.type)) {
            System.out.printf("  ✗ No IDENTITY_ACK received from %s:%d%n", peerIp, peerPort);
            return null;
        }
        String pub = ack.payload.has("public_key") ? ack.payload.get("public_key").getAsString() : "";
        String enc = ack.payload.has("encryption_key") ? ack.payload.get("encryption_key").getAsString() : "";
        String fp = ack.payload.has("fingerprint") ? ack.payload.get("fingerprint").getAsString() : "";
        if (!pub.isBlank() && !fp.isBlank()) {
            contacts.saveContact(ack.sender_id, ack.sender_name, pub, fp, false, enc.isBlank() ? null : enc);
            String encStatus = enc.isBlank() ? "signing key only" : "with encryption key";
            System.out.printf(
                    "  ✓ [%s] Identity exchanged with %s (%s)%n", local.peerName, ack.sender_name, encStatus);
            System.out.printf("     Their fingerprint: %s%n", fp);
            System.out.println("     Contact saved as unverified – use 'Trust a contact' to verify.");
        } else {
            System.out.printf(
                    "  ✓ [%s] IDENTITY_ACK from %s (no public key in response)%n",
                    local.peerName, ack.sender_name);
        }
        return ack;
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
