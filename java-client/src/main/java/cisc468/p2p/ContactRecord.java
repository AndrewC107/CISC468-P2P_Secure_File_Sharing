// ─────────────────────────────────────────────────────────────────────────────
// ContactRecord – one entry in contacts/contacts.json (matches peer/contacts.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import com.google.gson.annotations.SerializedName;

public final class ContactRecord {
    @SerializedName("peer_id")
    public String peerId;
    @SerializedName("peer_name")
    public String peerName;
    @SerializedName("public_key")
    public String publicKey;
    @SerializedName("encryption_key")
    public String encryptionKey;
    @SerializedName("fingerprint")
    public String fingerprint;
    public boolean trusted;
}
