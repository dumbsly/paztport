// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.security.PrivateKey;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.paztport.core.MerkleProof;
import org.paztport.core.PathChain;
import org.paztport.core.ProofBundle;
import org.paztport.core.RequestBinding;
import org.paztport.core.Stamp;
import org.paztport.core.StampSigner;

/**
 * Builds the outbound {@code X-Path-Chain} and {@code X-Path-Proof} headers for
 * one hop. Framework-neutral: the Spring interceptor feeds it the request
 * details and the inbound chain, and sets whatever it returns.
 *
 * <p>An origin service mints a fresh {@code rid}/{@code ts} and an empty
 * {@code prev}. A non-origin service appends to the chain it received, carrying
 * the origin's {@code rid}/{@code ts} unchanged and linking {@code prev} to the
 * previous signature. A non-origin hop with no inbound chain fails closed:
 * only entry points start chains.
 */
public final class OutboundStamper {

    private final String svc;
    private final String inst;
    private final PrivateKey key;
    private final boolean origin;
    private final Supplier<String> ridSupplier;
    private final LongSupplier clock;

    public OutboundStamper(
            String svc, String inst, PrivateKey key, boolean origin,
            Supplier<String> ridSupplier, LongSupplier clock) {
        this.svc = svc;
        this.inst = inst;
        this.key = key;
        this.origin = origin;
        this.ridSupplier = ridSupplier;
        this.clock = clock;
    }

    /** The two header values for a hop; {@code proofHeader} is null when this hop holds no proof for the route. */
    public record StampedHeaders(String chainHeader, String proofHeader) {
    }

    public StampedHeaders stamp(
            PathChain inboundChain, String method, String path, byte[] body, String target, ProofBundle bundle) {
        String rid;
        long ts;
        String prev;
        PathChain base;
        if (origin) {
            rid = ridSupplier.get();
            ts = clock.getAsLong();
            prev = "";
            base = new PathChain(List.of());
        } else {
            if (inboundChain == null || inboundChain.stamps().isEmpty()) {
                throw new IllegalStateException("non-origin service " + svc + " has no inbound chain to append to");
            }
            Stamp first = inboundChain.stamps().get(0);
            rid = first.rid();
            ts = first.ts();
            prev = inboundChain.prevSig();
            base = inboundChain;
        }

        String bind = RequestBinding.compute(method, path, body);
        Stamp stamp = StampSigner.sign(svc, inst, rid, ts, bind, prev, key);
        PathChain outgoing = base.withAppended(stamp);

        String proofHeader = null;
        if (bundle != null) {
            String route = outgoing.stamps().stream().map(Stamp::svc).collect(Collectors.joining("/"))
                    + "/" + target;
            MerkleProof proof = bundle.proofFor(route);
            if (proof != null) {
                proofHeader = proof.encode();
            }
        }
        return new StampedHeaders(outgoing.encode(), proofHeader);
    }
}
