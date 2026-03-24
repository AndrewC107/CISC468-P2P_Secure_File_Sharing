// ─────────────────────────────────────────────────────────────────────────────
// Message – NDJSON wire object (matches peer/models.py Message)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.JsonObject;

import java.util.UUID;

public final class Message {
    public String type;
    public String sender_id;
    public String sender_name;
    public int sender_port;
    public JsonObject payload;
    public String msg_id;
    public double timestamp;

    public Message() {
        this.payload = new JsonObject();
    }

    public static Message create(
            String type,
            String senderId,
            String senderName,
            int senderPort,
            JsonObject payload) {
        Message m = new Message();
        m.type = type;
        m.sender_id = senderId;
        m.sender_name = senderName;
        m.sender_port = senderPort;
        m.payload = payload != null ? payload : new JsonObject();
        m.msg_id = UUID.randomUUID().toString();
        m.timestamp = System.currentTimeMillis() / 1000.0;
        return m;
    }

    public void validate() {
        if (type == null || sender_id == null || sender_name == null) {
            throw new IllegalArgumentException("Message missing required string fields");
        }
        if (payload == null) {
            throw new IllegalArgumentException("payload must be a JSON object");
        }
    }
}
