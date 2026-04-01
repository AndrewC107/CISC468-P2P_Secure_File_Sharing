package cisc468.p2p;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class FileCatalog {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type CATALOG_TYPE = new TypeToken<Map<String, Map<String, Entry>>>() {}.getType();

    private final Config config;
    private Map<String, Map<String, Entry>> catalog;

    public FileCatalog(Config config) {
        this.config = config;
        this.catalog = load();
    }

    public synchronized void update(String peerId, String peerName, List<FileStore.FileEntry> files) {
        Map<String, Entry> entries = new HashMap<>();
        for (FileStore.FileEntry file : files) {
            entries.put(file.filename(), new Entry(peerName, file.size(), file.sha256()));
        }
        catalog.put(peerId, entries);
        persist();
    }

    public synchronized String getExpectedHash(String peerId, String filename) {
        Map<String, Entry> files = catalog.get(peerId);
        if (files == null) {
            return null;
        }
        Entry e = files.get(filename);
        if (e == null || e.sha256 == null || e.sha256.isBlank()) {
            return null;
        }
        return e.sha256;
    }

    public synchronized List<String> findAlternatePeers(
            String filename,
            String expectedSha256,
            String offlinePeerId,
            List<String> knownPeerIds) {
        List<String> out = new ArrayList<>();
        for (String pid : knownPeerIds) {
            if (pid.equals(offlinePeerId)) {
                continue;
            }
            Map<String, Entry> files = catalog.get(pid);
            if (files == null) {
                continue;
            }
            Entry e = files.get(filename);
            if (e != null && expectedSha256.equals(e.sha256)) {
                out.add(pid);
            }
        }
        return out;
    }

    public synchronized List<FileStore.FileEntry> getPeerFiles(String peerId) {
        List<FileStore.FileEntry> out = new ArrayList<>();
        Map<String, Entry> files = catalog.get(peerId);
        if (files == null) {
            return out;
        }
        for (Map.Entry<String, Entry> kv : files.entrySet()) {
            Entry e = kv.getValue();
            out.add(new FileStore.FileEntry(kv.getKey(), e.size, e.sha256));
        }
        return out;
    }

    private Map<String, Map<String, Entry>> load() {
        var path = config.catalogFile();
        if (!Files.isRegularFile(path)) {
            return new HashMap<>();
        }
        try {
            String json = Files.readString(path, StandardCharsets.UTF_8);
            Map<String, Map<String, Entry>> parsed = GSON.fromJson(json, CATALOG_TYPE);
            return parsed != null ? parsed : new HashMap<>();
        } catch (Exception e) {
            return new HashMap<>();
        }
    }

    private void persist() {
        try {
            Files.createDirectories(config.contactsDir());
            Files.writeString(config.catalogFile(), GSON.toJson(catalog), StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }

    private static final class Entry {
        String peerName;
        long size;
        String sha256;

        Entry(String peerName, long size, String sha256) {
            this.peerName = peerName;
            this.size = size;
            this.sha256 = sha256;
        }
    }
}
