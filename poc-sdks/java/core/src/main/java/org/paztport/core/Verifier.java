// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * The payment-side verifier. Runs a fixed sequence of checks and returns a
 * typed {@link VerifyResult}. Every branch fails closed: a parse error,
 * missing header, unknown key, or expired stamp is a rejection, never a pass.
 *
 * <p>The route is always rebuilt from the stamps' authenticated {@code svc}
 * fields, never from any claimed field, then checked for membership against the
 * pinned root. Step 8, checking the last stamp's {@code svc} against the
 * caller's mTLS identity, is not implemented.
 *
 * <p>A rejection names the last stamp's {@code svc}/{@code inst} as the suspect
 * only at {@link ReasonCode#PATH_NOT_ALLOWED} (and on success). By then the
 * signatures verified, the links hold, the chain is fresh, bound to this exact
 * request and unseen, so the last stamp's service really sent it. Only the
 * service is proven, by its key; the {@code inst} is whatever that service's
 * key holder signed, so the responder checks it against the container before
 * acting.
 * Earlier failures leave the suspect empty: the names are unsigned or
 * unverified (a forged chain could name anyone), or the genuine last stamp
 * belongs to someone else's request (a replayed or altered capture), and the
 * responder quarantines whoever is named.
 *
 * <p>One gap remains: a stamp does not bind which service it was meant for, so
 * a chain forwarded unchanged to another service whose method and path match
 * can still yield {@code PATH_NOT_ALLOWED} naming its innocent last signer.
 * Binding the receiver into the stamp, or mTLS caller identity (step 8), closes it.
 */
public final class Verifier {

    private final VerifierConfig cfg;

    public Verifier(VerifierConfig cfg) {
        this.cfg = cfg;
    }

    public VerifyResult verify(VerifyRequest req) {
        // 1. Chain header present and parseable, with at least one stamp.
        if (req.chainHeader() == null || req.chainHeader().isBlank()) {
            return VerifyResult.reject(ReasonCode.CHAIN_MISSING);
        }
        List<Stamp> stamps;
        try {
            stamps = PathChain.decode(req.chainHeader()).stamps();
        } catch (RuntimeException e) {
            return VerifyResult.reject(ReasonCode.CHAIN_MISSING);
        }
        if (stamps.isEmpty()) {
            return VerifyResult.reject(ReasonCode.CHAIN_MISSING);
        }

        Stamp last = stamps.get(stamps.size() - 1);

        // 2. First stamp's svc is an allowed origin.
        if (!cfg.allowedOrigins().contains(stamps.get(0).svc())) {
            return VerifyResult.reject(ReasonCode.BAD_ORIGIN);
        }

        // 3. Every signature verifies, and each prev links to the previous sig.
        for (int i = 0; i < stamps.size(); i++) {
            Stamp s = stamps.get(i);
            PublicKey key = cfg.keyring().keyFor(s.svc());
            if (key == null || !signatureValid(key, s)) {
                return VerifyResult.reject(ReasonCode.BAD_SIGNATURE);
            }
            String expectedPrev = i == 0 ? "" : stamps.get(i - 1).sig();
            if (!s.prev().equals(expectedPrev)) {
                return VerifyResult.reject(ReasonCode.BROKEN_LINK);
            }
        }

        // 4. All stamps share the origin's rid; the origin ts is within max age.
        String rid = stamps.get(0).rid();
        for (Stamp s : stamps) {
            if (!s.rid().equals(rid)) {
                return VerifyResult.reject(ReasonCode.RID_MISMATCH);
            }
        }
        long age = cfg.clock().getAsLong() - stamps.get(0).ts();
        if (age > cfg.maxAgeMs()) {
            return VerifyResult.reject(ReasonCode.EXPIRED);
        }

        // 5. Last stamp's bind matches the request actually received.
        String rebound = RequestBinding.compute(req.method(), req.path(), req.body());
        if (!rebound.equals(last.bind())) {
            return VerifyResult.reject(ReasonCode.BINDING_MISMATCH);
        }

        // 6. (rid, last svc) not seen before.
        if (cfg.nonceCache().seenBefore(rid, last.svc())) {
            return VerifyResult.reject(ReasonCode.REPLAY);
        }

        // 7. Route rebuilt from the stamps plus this service, proven against the root.
        List<String> hops = new ArrayList<>(stamps.stream().map(Stamp::svc).toList());
        hops.add(cfg.receivingService());
        String route = Routes.join(hops);
        if (!pathAllowed(req.proofHeader(), route)) {
            // Everything above held, so the last hop did sign this very request.
            return VerifyResult.reject(ReasonCode.PATH_NOT_ALLOWED, last.svc(), last.inst());
        }

        return VerifyResult.ok(last.svc(), last.inst());
    }

    private static boolean signatureValid(PublicKey key, Stamp s) {
        try {
            return Crypto.verify(key, s.signingBytes(), Base64Url.decode(s.sig()));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private boolean pathAllowed(String proofHeader, String route) {
        if (proofHeader == null || proofHeader.isBlank()) {
            return false;
        }
        MerkleProof proof;
        try {
            proof = MerkleProof.decode(proofHeader);
        } catch (RuntimeException e) {
            return false;
        }
        return proof.rootId().equals(cfg.rootId()) && proof.verify(route, cfg.root());
    }
}
