// ─────────────────────────────────────────────────────────────────────────────
// FileStore – storage/shared and storage/downloads (matches peer/files.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class FileStore {

    private final Config config;

    public FileStore(Config config) {
        this.config = config;
    }

    public void ensureStorageDirs() throws IOException {
        Files.createDirectories(config.sharedDir());
        Files.createDirectories(config.downloadsDir());
    }

    public JsonArray listSharedFilesJson(StorageKey storageKey) throws Exception {
        Path shared = config.sharedDir();
        JsonArray arr = new JsonArray();
        if (!Files.isDirectory(shared)) {
            return arr;
        }
        Set<String> seenNames = new HashSet<>();
        try (Stream<Path> stream = Files.list(shared)) {
            List<Path> files = stream.filter(Files::isRegularFile).sorted().collect(Collectors.toList());
            for (Path f : files) {
                byte[] data;
                String displayName;
                if (f.getFileName().toString().endsWith(".enc")) {
                    if (storageKey == null) {
                        continue;
                    }
                    try {
                        data = storageKey.decrypt(Files.readAllBytes(f));
                    } catch (Exception e) {
                        continue;
                    }
                    displayName = f.getFileName().toString().substring(0, f.getFileName().toString().length() - 4);
                } else {
                    data = Files.readAllBytes(f);
                    displayName = f.getFileName().toString();
                }
                if (seenNames.contains(displayName)) {
                    continue;
                }
                seenNames.add(displayName);
                JsonObject o = new JsonObject();
                o.addProperty("filename", displayName);
                o.addProperty("size", data.length);
                o.addProperty("sha256", sha256Hex(data));
                arr.add(o);
            }
        }
        return arr;
    }

    public List<FileEntry> listSharedFiles(StorageKey storageKey) throws Exception {
        JsonArray arr = listSharedFilesJson(storageKey);
        List<FileEntry> out = new ArrayList<>();
        for (var el : arr) {
            JsonObject o = el.getAsJsonObject();
            out.add(new FileEntry(
                    o.get("filename").getAsString(),
                    o.get("size").getAsLong(),
                    o.has("sha256") ? o.get("sha256").getAsString() : ""));
        }
        return out;
    }

    public Path sharedFilePath(String filename) {
        return config.sharedDir().resolve(filename);
    }

    public byte[] readSharedFileBytes(String filename, StorageKey storageKey) throws Exception {
        Path enc = sharedFilePath(filename + ".enc");
        Path plain = sharedFilePath(filename);
        if (Files.isRegularFile(enc) && storageKey != null) {
            try {
                return storageKey.decrypt(Files.readAllBytes(enc));
            } catch (Exception ignored) {
            }
        }
        if (Files.isRegularFile(plain)) {
            return Files.readAllBytes(plain);
        }
        return null;
    }

    public Path importFileToShared(String sourcePath, StorageKey storageKey) throws Exception {
        ensureStorageDirs();
        Path src = Path.of(sourcePath);
        if (!Files.isRegularFile(src)) {
            throw new IOException("Source file not found: " + sourcePath);
        }
        byte[] data = Files.readAllBytes(src);
        if (storageKey != null) {
            Path dest = config.sharedDir().resolve(src.getFileName().toString() + ".enc");
            Files.write(dest, storageKey.encrypt(data));
            return dest;
        }
        Path dest = config.sharedDir().resolve(src.getFileName().toString());
        Files.write(dest, data);
        return dest;
    }

    public Path writeDownloadSecure(String filename, byte[] plaintext, StorageKey storageKey) throws Exception {
        ensureStorageDirs();
        if (storageKey != null) {
            Path dest = config.downloadsDir().resolve(filename + ".enc");
            Files.write(dest, storageKey.encrypt(plaintext));
            return dest;
        }
        Path dest = config.downloadsDir().resolve(filename);
        Files.write(dest, plaintext);
        return dest;
    }

    public List<FileEntry> listDownloadedFiles(StorageKey storageKey) throws Exception {
        Path downloads = config.downloadsDir();
        List<FileEntry> out = new ArrayList<>();
        if (!Files.isDirectory(downloads)) {
            return out;
        }
        Set<String> seen = new HashSet<>();
        try (Stream<Path> stream = Files.list(downloads)) {
            for (Path f : stream.filter(Files::isRegularFile).sorted().toList()) {
                String name = f.getFileName().toString();
                long size;
                String display;
                if (name.endsWith(".enc")) {
                    display = name.substring(0, name.length() - 4);
                    if (storageKey != null) {
                        try {
                            size = storageKey.decrypt(Files.readAllBytes(f)).length;
                        } catch (Exception e) {
                            size = Files.size(f);
                        }
                    } else {
                        size = Files.size(f);
                    }
                } else {
                    display = name;
                    size = Files.size(f);
                }
                if (!seen.contains(display)) {
                    seen.add(display);
                    out.add(new FileEntry(display, size, ""));
                }
            }
        }
        return out;
    }

    public String downloadsDirDisplay() {
        return config.downloadsDir().toString();
    }

    public Path downloadsDir() {
        return config.downloadsDir();
    }

    private static String sha256Hex(byte[] data) throws Exception {
        var md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        return java.util.HexFormat.of().formatHex(digest);
    }

    public record FileEntry(String filename, long size, String sha256) {}
}
