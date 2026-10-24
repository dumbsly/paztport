// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The payment-side verifier. Runs the fixed sequence of checks from the spec and
 * returns a typed {@link VerifyResult}. Every branch fails closed: a parse error,
 * missing header, unknown key, or expired stamp is a rejection, never a pass.
 *
 * <p>The route is always rebuilt from the stamps' authenticated {@code svc}
 * fields, never from any claimed field, then checked for membership against the
 * pinned root. Step 8 of the spec (mTLS caller identity) is deferred to phase 6.
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
        String suspectSvc = last.svc();
        String suspectInst = last.inst();

        // 2. First stamp's svc is an allowed origin.
        if (!cfg.allowedOrigins().contains(stamps.get(0).svc())) {
            return VerifyResult.reject(ReasonCode.BAD_ORIGIN, suspectSvc, suspectInst);
        }

        // 3. Every signature verifies, and each prev links to the previous sig.
        for (int i = 0; i < stamps.size(); i++) {
            Stamp s = stamps.get(i);
            PublicKey key = cfg.keyring().keyFor(s.svc());
            if (key == null || !signatureValid(key, s)) {
                return VerifyResult.reject(ReasonCode.BAD_SIGNATURE, suspectSvc, suspectInst);
            }
            String expectedPrev = i == 0 ? "" : stamps.get(i - 1).sig();
            if (!s.prev().equals(expectedPrev)) {
                return VerifyResult.reject(ReasonCode.BROKEN_LINK, suspectSvc, suspectInst);
            }
        }

        // 4. All stamps share the origin's rid; the origin ts is within max age.
        String rid = stamps.get(0).rid();
        for (Stamp s : stamps) {
            if (!s.rid().equals(rid)) {
                return VerifyResult.reject(ReasonCode.RID_MISMATCH, suspectSvc, suspectInst);
            }
        }
        long age = cfg.clock().getAsLong() - stamps.get(0).ts();
        if (age > cfg.maxAgeMs()) {
            return VerifyResult.reject(ReasonCode.EXPIRED, suspectSvc, suspectInst);
        }

        // 5. Last stamp's bind matches the request actually received.
        String rebound = RequestBinding.compute(req.method(), req.path(), req.body());
        if (!rebound.equals(last.bind())) {
            return VerifyResult.reject(ReasonCode.BINDING_MISMATCH, suspectSvc, suspectInst);
        }

        // 6. (rid, last svc) not seen before.
        if (cfg.nonceCache().seenBefore(rid, last.svc())) {
            return VerifyResult.reject(ReasonCode.REPLAY, suspectSvc, suspectInst);
        }

        // 7. Route rebuilt from the stamps plus this service, proven against the root.
        String route = stamps.stream().map(Stamp::svc).collect(Collectors.joining("/"))
                + "/" + cfg.receivingService();
        if (!pathAllowed(req.proofHeader(), route)) {
            return VerifyResult.reject(ReasonCode.PATH_NOT_ALLOWED, suspectSvc, suspectInst);
        }

        return VerifyResult.ok(suspectSvc, suspectInst);
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
