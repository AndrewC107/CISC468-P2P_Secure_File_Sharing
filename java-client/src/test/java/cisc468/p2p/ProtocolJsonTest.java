package cisc468.p2p;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtocolJsonTest {

    @Test
    void roundTripAndNewlineFrame() {
        JsonObject p = new JsonObject();
        p.addProperty("text", "hi");
        Message m = Message.create(MessageType.CHAT, "id-1", "Alice", 5000, p);
        byte[] wire = ProtocolJson.encodeMessage(m);
        assertTrue(wire.length > 0 && wire[wire.length - 1] == '\n');
        String framed = new String(wire, StandardCharsets.UTF_8);
        String body = framed.substring(0, framed.length() - 1);
        assertFalse(body.contains("\n"));
        Message back = ProtocolJson.decodeMessage(wire);
        assertEquals(MessageType.CHAT, back.type);
        assertEquals("Alice", back.sender_name);
        assertEquals(5000, back.sender_port);
        assertEquals("hi", back.payload.get("text").getAsString());
    }
}
