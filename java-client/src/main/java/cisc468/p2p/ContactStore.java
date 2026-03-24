// ─────────────────────────────────────────────────────────────────────────────
// ContactStore – persistent contacts (same file as Python peer/contacts.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public final class ContactStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Config config;

    public ContactStore(Config config) {
        this.config = config;
    }

    public synchronized ContactRecord getContact(String peerId) throws Exception {
        ContactsFile data = loadAll();
        for (ContactRecord c : data.contacts) {
            if (peerId.equals(c.peerId)) {
                return c;
            }
        }
        return null;
    }

    public synchronized List<ContactRecord> listContacts() throws Exception {
        return loadAll().contacts;
    }

    public synchronized void saveContact(
            String peerId,
            String peerName,
            String publicKey,
            String fingerprint,
            boolean trusted,
            String encryptionKeyOrNull) throws Exception {
        ContactsFile data = loadAll();
        for (ContactRecord entry : data.contacts) {
            if (peerId.equals(entry.peerId)) {
                entry.peerName = peerName;
                entry.publicKey = publicKey;
                entry.fingerprint = fingerprint;
                if (encryptionKeyOrNull != null) {
                    entry.encryptionKey = encryptionKeyOrNull;
                }
                if (!entry.trusted) {
                    entry.trusted = trusted;
                }
                saveAll(data);
                return;
            }
        }
        ContactRecord n = new ContactRecord();
        n.peerId = peerId;
        n.peerName = peerName;
        n.publicKey = publicKey;
        n.encryptionKey = encryptionKeyOrNull != null ? encryptionKeyOrNull : "";
        n.fingerprint = fingerprint;
        n.trusted = trusted;
        data.contacts.add(n);
        saveAll(data);
    }

    public synchronized boolean setTrusted(String peerId, boolean trusted) throws Exception {
        ContactsFile data = loadAll();
        for (ContactRecord entry : data.contacts) {
            if (peerId.equals(entry.peerId)) {
                entry.trusted = trusted;
                saveAll(data);
                return true;
            }
        }
        return false;
    }

    private ContactsFile loadAll() throws Exception {
        var path = config.contactsFile();
        if (!Files.isRegularFile(path)) {
            return new ContactsFile();
        }
        try {
            String json = Files.readString(path, StandardCharsets.UTF_8);
            ContactsFile parsed = GSON.fromJson(json, ContactsFile.class);
            return parsed != null ? parsed : new ContactsFile();
        } catch (Exception e) {
            return new ContactsFile();
        }
    }

    private void saveAll(ContactsFile data) throws Exception {
        Files.createDirectories(config.contactsDir());
        Files.writeString(config.contactsFile(), GSON.toJson(data), StandardCharsets.UTF_8);
    }
}
