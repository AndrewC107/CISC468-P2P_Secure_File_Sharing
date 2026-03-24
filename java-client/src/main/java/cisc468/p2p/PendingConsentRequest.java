// ─────────────────────────────────────────────────────────────────────────────
// PendingConsentRequest – FILE_REQUEST consent (matches peer/server.py)
// ─────────────────────────────────────────────────────────────────────────────
package cisc468.p2p;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class PendingConsentRequest {
    public final String peerName;
    public final String peerId;
    public final String peerIp;
    public final int peerPort;
    public final String filename;

    private final CountDownLatch latch = new CountDownLatch(1);
    private final AtomicBoolean accepted = new AtomicBoolean(false);
    private final AtomicBoolean timedOut = new AtomicBoolean(false);

    public PendingConsentRequest(String peerName, String peerId, String peerIp, int peerPort, String filename) {
        this.peerName = peerName;
        this.peerId = peerId;
        this.peerIp = peerIp;
        this.peerPort = peerPort;
        this.filename = filename;
    }

    public boolean timedOut() {
        return timedOut.get();
    }

    public void resolve(boolean accept) {
        accepted.set(accept);
        latch.countDown();
    }

    /** @return true if user accepted */
    public boolean waitForDecision(double timeoutSeconds) throws InterruptedException {
        boolean fired = latch.await((long) (timeoutSeconds * 1000), TimeUnit.MILLISECONDS);
        if (!fired) {
            timedOut.set(true);
        }
        return accepted.get();
    }
}
