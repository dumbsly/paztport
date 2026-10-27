// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.NonceCache;
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
 * session it opened, for the request filter to look up. There is one session per authenticated peer, the HTTP
 * stand-in for one session per connection, so a new handshake from a peer replaces its earlier session, and a
 * session id is honoured only for the peer it was opened with.
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

    /** A peer's current session; {@code verifier} is null when it is unsafe. */
    record Session(String sess, boolean attested, VerifierV3 verifier) {
    }

    private final SignedRoot ownRoot;
    private final KeyringFile ownKeyring;
    private final String ownPolicyKey;
    private final PublicKey ownPolicyPublic;
    private final PrivateKey ownPolicyPrivate;
    private final Set<String> pinnedClientKeys;
    private final Set<String> clientOrigins;
    private final List<String> unsafeDisabled;
    private final NonceCache nonces;
    private final LongSupplier clock;
    private final long callMaxAgeMs;
    private final long runMaxAgeMs;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    PartnerSessions(SignedRoot ownRoot, KeyringFile ownKeyring, String ownPolicyKey, PrivateKey ownPolicyPrivate,
            Set<String> pinnedClientKeys, Set<String> clientOrigins, List<String> unsafeDisabled, NonceCache nonces,
            LongSupplier clock, long callMaxAgeMs, long runMaxAgeMs) {
        this.ownRoot = ownRoot;
        this.ownKeyring = ownKeyring;
        this.ownPolicyKey = ownPolicyKey;
        this.ownPolicyPublic = Crypto.decodePublicKey(Base64Url.decode(ownPolicyKey));
        this.ownPolicyPrivate = ownPolicyPrivate;
        this.pinnedClientKeys = Set.copyOf(pinnedClientKeys);
        this.clientOrigins = Set.copyOf(clientOrigins);
        this.unsafeDisabled = List.copyOf(unsafeDisabled);
        this.nonces = nonces;
        this.clock = clock;
        this.callMaxAgeMs = callMaxAgeMs;
        this.runMaxAgeMs = runMaxAgeMs;
    }

    /**
     * Opens a session for {@code peerSvc}, replacing any it had, and returns the signed reply. The caller has
     * already checked {@link Sessions#opensSession}; a request that fails it throws
     * {@link IllegalArgumentException}, with the peer's current session left in place.
     */
    SessionReply open(SessionRequest req, String peerSvc) {
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
        sessions.put(peerSvc, new Session(sess, attested, verifier));
        TRACE.info("PAZTPORT_TRACE session peer={} status={}", LogSafe.of(peerSvc), attested ? "attested" : "unsafe");
        return Sessions.signReply(new SessionReply(ownRoot, ownPolicyKey, ownKeyring.services(), serverNonce, sess,
                attested ? "attested" : "unsafe", attested ? List.of() : unsafeDisabled, null), ownPolicyPrivate);
    }

    /** The peer's current session when its id is {@code sess}, else null: another peer's, a replaced or an unknown id. */
    Session find(String peerSvc, String sess) {
        Session current = peerSvc == null ? null : sessions.get(peerSvc);
        return current != null && current.sess().equals(sess) ? current : null;
    }

    /** The operations an unsafe session may not perform, as the reply lists them. */
    List<String> unsafeDisabled() {
        return unsafeDisabled;
    }
}
