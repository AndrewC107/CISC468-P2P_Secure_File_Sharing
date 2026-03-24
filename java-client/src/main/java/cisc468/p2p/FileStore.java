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
import java.util.List;
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

    public JsonArray listSharedFilesJson() throws IOException {
        Path shared = config.sharedDir();
        JsonArray arr = new JsonArray();
        if (!Files.isDirectory(shared)) {
            return arr;
        }
        try (Stream<Path> stream = Files.list(shared)) {
            List<Path> files = stream.filter(Files::isRegularFile).sorted().collect(Collectors.toList());
            for (Path f : files) {
                JsonObject o = new JsonObject();
                o.addProperty("filename", f.getFileName().toString());
                o.addProperty("size", Files.size(f));
                arr.add(o);
            }
        }
        return arr;
    }

    public List<FileEntry> listSharedFiles() throws IOException {
        JsonArray arr = listSharedFilesJson();
        List<FileEntry> out = new ArrayList<>();
        for (var el : arr) {
            JsonObject o = el.getAsJsonObject();
            out.add(new FileEntry(
                    o.get("filename").getAsString(),
                    o.get("size").getAsLong()));
        }
        return out;
    }

    public Path sharedFilePath(String filename) {
        return config.sharedDir().resolve(filename);
    }

    public byte[] readSharedFileBytes(String filename) throws IOException {
        Path p = sharedFilePath(filename);
        if (!Files.isRegularFile(p)) {
            return null;
        }
        return Files.readAllBytes(p);
    }

    public void writeDownload(String filename, byte[] data) throws IOException {
        ensureStorageDirs();
        Path dest = config.downloadsDir().resolve(filename);
        Files.write(dest, data);
    }

    public String downloadsDirDisplay() {
        return config.downloadsDir().toString();
    }

    public Path downloadsDir() {
        return config.downloadsDir();
    }

    public record FileEntry(String filename, long size) {}
}
