// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.NonceCache;
import org.paztport.core.ReplyCert;
import org.paztport.core.SessionReply;
import org.paztport.core.SessionRequest;
import org.paztport.core.Sessions;
import org.paztport.core.SignedRoot;
import org.paztport.core.VerifierConfigV3;
import org.paztport.core.VerifierV3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The partner's side of the session handshake: it answers a client's request with a signed reply and remembers the
 * session it opened, for the request filter to look up. HTTP has no connection to hold a session, so each session is
 * kept by its id and records the peer that opened it: the client certificate's issuer and common name, both of which
 * the TLS layer authenticated. A call is in a session only when that same issuer and name present its id; the name
 * alone is not enough, since another CA the container trusts could issue a certificate with the same name. CAs are
 * told apart by their distinguished name, not by their key, so two CAs with identical subject names are not.
 *
 * <p>A handshake adds a session and replaces none, so replicas of one client that share a certificate each keep
 * their own up to the cap, beyond which they evict each other's least recently used sessions (a call that then
 * names an evicted session is refused, and the client opens a new one on its next call), and a client re-opening
 * never cuts off calls still in flight in its earlier session. What bounds memory instead: a peer holds at most
 * {@code maxSessionsPerPeer} sessions, its least recently used evicted when it opens one more, and a session no
 * call has used for {@code sessionIdleMs} expires. A peer can evict only its own sessions, so no client can push
 * out another's. Memory is therefore bounded by the peers the trusted CAs vouch for, times the cap. An evicted or
 * expired id is simply unknown, as one from before a restart is.
 *
 * <p>Opening, eviction and lookup all run under one {@link ReentrantLock}, so concurrent handshakes from one peer
 * can never leave it over its cap. It is a lock rather than {@code synchronized} so that a virtual thread waiting on
 * it does not pin its carrier. The handshake's signature checks and the verifier are built before the lock is
 * taken; only the bookkeeping is done under it.
 *
 * <p>Replies are signed by this side's entry service with its own key, and carry the policy key's signature over the
 * keyring and the policy key's reply certificate for that key, so the policy private key stays offline. Only the
 * key is the entry's: what a reply says is still decided by the checks below, and a reply says {@code "attested"}
 * only after them. The client accepts the signature only while the certificate has not expired, so this side must
 * be given a fresh certificate before the one it holds expires.
 *
 * <p>A session is attested only when {@link Sessions#status} says so: the client's root and keyring verify under a
 * policy key this side has pinned out of band. An attested session gets its own verifier, pinned to the client's
 * keyring and root from the handshake, with the session id as its {@code sess}, so a stamp made in one session never
 * verifies in another. Should that verifier not be buildable, the session is unsafe rather than the handshake
 * failing, because the client still has to be told. An unsafe session has no verifier, and its reply lists the
 * operations this side has switched off for it.
 */
final class PartnerSessions {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    /** A session a peer opened; {@code verifier} is null when it is unsafe. */
    record Session(String sess, boolean attested, VerifierV3 verifier) {
    }

    /** The authenticated peer a session belongs to: the client certificate's issuer, RFC 2253, and common name. */
    private record PeerKey(String issuer, String svc) {
    }

    /** A live session, its peer, and when a call last used it, by {@link #clock}; changed only under the lock. */
    private static final class Entry {
        final PeerKey peer;
        final Session session;
        long lastUsedMs;

        Entry(PeerKey peer, Session session, long lastUsedMs) {
            this.peer = peer;
            this.session = session;
            this.lastUsedMs = lastUsedMs;
        }
    }

    private final SignedRoot ownRoot;
    private final KeyringFile ownKeyring;
    private final String ownPolicyKey;
    private final PublicKey ownPolicyPublic;
    private final PrivateKey ownServiceKey;
    private final ReplyCert ownReplyCert;
    private final Set<String> pinnedClientKeys;
    private final Set<String> clientOrigins;
    private final List<String> unsafeDisabled;
    private final NonceCache nonces;
    private final LongSupplier clock;
    private final long callMaxAgeMs;
    private final long runMaxAgeMs;
    private final int maxSessionsPerPeer;
    private final long sessionIdleMs;

    private final ReentrantLock lock = new ReentrantLock();
    /** Every session kept, by id; an expired one stays until a lookup finds it or a handshake sweeps it out. */
    private final Map<String, Entry> byId = new HashMap<>();
    /** Each peer's live sessions, least recently used first: a lookup moves its session to the end. */
    private final Map<PeerKey, LinkedHashMap<String, Entry>> byPeer = new HashMap<>();

    /**
     * The caller checks first that the keyring and the certificate verify under {@code ownPolicyKey}, that
     * {@code ownServiceKey} is the key the keyring holds for {@code ownService}, and that the certificate has not
     * expired; the auto-configuration does, naming the property at fault. This refuses only a certificate that is
     * not for the keyring's key for {@code ownService}, whose replies no client could accept.
     *
     * @param ownService this side's entry service, whose key signs the replies
     * @param ownServiceKey that service's private key
     * @param ownReplyCert the policy key's certificate for that service's key
     * @param clock the time in milliseconds, which the session verifiers check stamps against and which ages an
     *     idle session
     * @param maxSessionsPerPeer how many sessions one peer may hold at once; at least 1
     * @param sessionIdleMs how long a session no call has used is kept, in milliseconds; positive
     */
    PartnerSessions(SignedRoot ownRoot, KeyringFile ownKeyring, String ownPolicyKey, String ownService,
            PrivateKey ownServiceKey, ReplyCert ownReplyCert, Set<String> pinnedClientKeys, Set<String> clientOrigins,
            List<String> unsafeDisabled, NonceCache nonces, LongSupplier clock, long callMaxAgeMs, long runMaxAgeMs,
            int maxSessionsPerPeer, long sessionIdleMs) {
        if (maxSessionsPerPeer < 1) {
            throw new IllegalArgumentException("a peer must be allowed at least one session");
        }
        if (sessionIdleMs <= 0) {
            throw new IllegalArgumentException("the idle period must be positive");
        }
        if (!ownService.equals(ownReplyCert.svc())
                || !ownReplyCert.key().equals(ownKeyring.services().get(ownService))) {
            throw new IllegalArgumentException("the reply certificate is not for this service's key in its keyring");
        }
        this.ownRoot = ownRoot;
        this.ownKeyring = ownKeyring;
        this.ownPolicyKey = ownPolicyKey;
        this.ownPolicyPublic = Crypto.decodePublicKey(Base64Url.decode(ownPolicyKey));
        this.ownServiceKey = ownServiceKey;
        this.ownReplyCert = ownReplyCert;
        this.pinnedClientKeys = Set.copyOf(pinnedClientKeys);
        this.clientOrigins = Set.copyOf(clientOrigins);
        this.unsafeDisabled = List.copyOf(unsafeDisabled);
        this.nonces = nonces;
        this.clock = clock;
        this.callMaxAgeMs = callMaxAgeMs;
        this.runMaxAgeMs = runMaxAgeMs;
        this.maxSessionsPerPeer = maxSessionsPerPeer;
        this.sessionIdleMs = sessionIdleMs;
    }

    /**
     * Opens a session for the peer {@code peerIssuer}, {@code peerSvc}, evicting that peer's least recently used
     * one if it already holds its cap, and returns the signed reply. The caller has already checked
     * {@link Sessions#opensSession}. It throws {@link IllegalArgumentException}, with every session left as it was,
     * when the request opens no session, when the peer has no issuer or no name (so no session is ever kept under
     * a missing one), or when the id is already in use, which would take a repeated server nonce.
     */
    SessionReply open(SessionRequest req, String peerIssuer, String peerSvc) {
        if (peerIssuer == null || peerIssuer.isEmpty() || peerSvc == null || peerSvc.isEmpty()) {
            throw new IllegalArgumentException("a session is opened only for a peer with an issuer and a name");
        }
        String serverNonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                ownRoot.sig(), req.nonce(), serverNonce, req.clientPolicyKey(), req.clientKeyring());
        if (sess == null) {
            throw new IllegalArgumentException("request does not open a session");
        }
        VerifierV3 verifier = null;
        if (Sessions.status(req, ownRoot, ownPolicyPublic, pinnedClientKeys).equals("attested")) {
            try {
                verifier = new VerifierV3(VerifierConfigV3.pinned(
                        new KeyringFile(req.clientKeyring(), req.clientPolicyKey(), req.clientKeyringSig()),
                        req.clientRoot(), req.clientPolicyKey(), clientOrigins, sess, nonces, clock, callMaxAgeMs,
                        runMaxAgeMs));
            } catch (IllegalArgumentException e) {
                verifier = null;
            }
        }
        boolean attested = verifier != null;
        add(new PeerKey(peerIssuer, peerSvc), new Session(sess, attested, verifier));
        TRACE.info("PAZTPORT_TRACE session peer={} status={}", LogSafe.of(peerSvc), attested ? "attested" : "unsafe");
        // The entry-key form: the status above is this side's own decision, and the entry key signs it.
        return Sessions.signReply(new SessionReply(ownRoot, ownPolicyKey, ownKeyring.services(), ownKeyring.sig(),
                ownReplyCert, serverNonce, sess, attested ? "attested" : "unsafe",
                attested ? List.of() : unsafeDisabled, null), ownServiceKey);
    }

    /**
     * Keeps {@code session} for {@code peer}: drops every expired session, refuses an id already in use, then adds
     * it and evicts the peer's least recently used sessions down to the cap. All of it under the lock, so the cap
     * holds however many handshakes one peer runs at once.
     */
    private void add(PeerKey peer, Session session) {
        lock.lock();
        try {
            long now = clock.getAsLong();
            dropExpired(now);
            if (byId.containsKey(session.sess())) {
                throw new IllegalArgumentException("session id already in use");
            }
            Entry entry = new Entry(peer, session, now);
            byId.put(session.sess(), entry);
            LinkedHashMap<String, Entry> own = byPeer.computeIfAbsent(peer, k -> new LinkedHashMap<>(16, 0.75f, true));
            own.put(session.sess(), entry);
            Iterator<Entry> oldest = own.values().iterator();
            while (own.size() > maxSessionsPerPeer) {
                byId.remove(oldest.next().session.sess());
                oldest.remove();
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * The session {@code sess} when it is live and was opened by exactly this peer, the same issuer and name, else
     * null: another peer's, one under the same name from another issuer (told apart by its distinguished name), an
     * evicted, expired or unknown id, or a peer with no certificate, issuer or name. A session found is used, so its
     * idle period starts again.
     */
    Session find(String peerIssuer, String peerSvc, String sess) {
        if (peerIssuer == null || peerIssuer.isEmpty() || peerSvc == null || peerSvc.isEmpty() || sess == null) {
            return null;
        }
        lock.lock();
        try {
            Entry entry = byId.get(sess);
            if (entry == null || !entry.peer.equals(new PeerKey(peerIssuer, peerSvc))) {
                return null;
            }
            long now = clock.getAsLong();
            if (expired(entry, now)) {
                remove(entry);
                return null;
            }
            entry.lastUsedMs = now;
            byPeer.get(entry.peer).get(sess); // marks it most recently used
            return entry.session;
        } finally {
            lock.unlock();
        }
    }

    private boolean expired(Entry entry, long now) {
        return now - entry.lastUsedMs >= sessionIdleMs;
    }

    /** Drops every expired session, and every peer left with none; under the lock. */
    private void dropExpired(long now) {
        Iterator<LinkedHashMap<String, Entry>> peers = byPeer.values().iterator();
        while (peers.hasNext()) {
            LinkedHashMap<String, Entry> own = peers.next();
            Iterator<Entry> sessions = own.values().iterator();
            while (sessions.hasNext()) {
                Entry e = sessions.next();
                if (expired(e, now)) {
                    byId.remove(e.session.sess());
                    sessions.remove();
                }
            }
            if (own.isEmpty()) {
                peers.remove();
            }
        }
    }

    /** Forgets one session, and its peer when it was the last; under the lock. */
    private void remove(Entry entry) {
        byId.remove(entry.session.sess());
        LinkedHashMap<String, Entry> own = byPeer.get(entry.peer);
        own.remove(entry.session.sess());
        if (own.isEmpty()) {
            byPeer.remove(entry.peer);
        }
    }

    /** The operations an unsafe session may not perform, as the reply lists them. */
    List<String> unsafeDisabled() {
        return unsafeDisabled;
    }
}
