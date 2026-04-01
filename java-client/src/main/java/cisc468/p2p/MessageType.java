// ─────────────────────────────────────────────────────────────────────────────
// MessageType – String constants identical to peer/protocol.py MessageType
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

public final class MessageType {
    public static final String HELLO = "hello";
    public static final String HELLO_ACK = "hello_ack";
    public static final String CHAT = "chat";
    public static final String BYE = "bye";
    public static final String FILE_OFFER = "file_offer";
    public static final String FILE_LIST_REQUEST = "file_list_request";
    public static final String FILE_LIST_RESPONSE = "file_list_response";
    public static final String FILE_REQUEST = "file_request";
    public static final String FILE_TRANSFER = "file_transfer";
    public static final String FILE_REJECTED = "file_rejected";
    public static final String IDENTITY_EXCHANGE = "identity_exchange";
    public static final String IDENTITY_ACK = "identity_ack";
    public static final String KEY_ROTATION = "key_rotation";

    private MessageType() {}
}
