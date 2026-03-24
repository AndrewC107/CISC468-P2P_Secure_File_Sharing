// ─────────────────────────────────────────────────────────────────────────────
// ProtocolJson – NDJSON framing (newline-terminated JSON) matching peer/protocol.py
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import java.nio.charset.StandardCharsets;

public final class ProtocolJson {

    private static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .disableHtmlEscaping()
            .create();

    private ProtocolJson() {}

    public static byte[] encodeMessage(Message message) {
        String json = GSON.toJson(message);
        return (json + "\n").getBytes(StandardCharsets.UTF_8);
    }

    public static Message decodeMessage(byte[] raw) {
        return decodeMessage(new String(raw, StandardCharsets.UTF_8));
    }

    public static Message decodeMessage(String raw) {
        String trimmed = raw.stripTrailing();
        if (trimmed.endsWith("\n")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        trimmed = trimmed.strip();
        try {
            Message m = GSON.fromJson(trimmed, Message.class);
            if (m == null) {
                throw new JsonParseException("null message");
            }
            validateWireMessage(m);
            if (m.payload == null) {
                m.payload = new JsonObject();
            }
            return m;
        } catch (JsonParseException e) {
            throw e;
        }
    }

    private static void validateWireMessage(Message m) {
        if (m.type == null) {
            throw new IllegalArgumentException("Message is missing required fields: [type]");
        }
        if (m.sender_id == null) {
            throw new IllegalArgumentException("Message is missing required fields: [sender_id]");
        }
        if (m.sender_name == null) {
            throw new IllegalArgumentException("Message is missing required fields: [sender_name]");
        }
        // sender_port: Python requires int; Gson may fail parse if wrong type
        if (m.payload == null) {
            throw new IllegalArgumentException("payload must be a JSON object (dict)");
        }
    }
}
