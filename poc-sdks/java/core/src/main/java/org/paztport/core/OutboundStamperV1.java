// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Builds the outbound {@code X-Path-Chain} and {@code X-Path-Proof} headers for
 * one hop. Framework-neutral: the Spring interceptor feeds it the binding of the
 * request it is sending and the inbound chain, and sets whatever it returns.
 *
 * <p>An origin service mints a fresh {@code rid}/{@code ts} and an empty
 * {@code prev}. A non-origin service appends to the chain it received, carrying
 * the origin's {@code rid}/{@code ts} unchanged and linking {@code prev} to the
 * previous signature. A non-origin hop with no inbound chain fails closed:
 * only entry points start chains.
 */
public final class OutboundStamperV1 {

    private final String svc;
    private final String inst;
    private final PrivateKey key;
    private final boolean origin;
    private final Supplier<String> ridSupplier;
    private final LongSupplier clock;

    public OutboundStamperV1(
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
            PathChainV1 inboundChain, String bind, String target, ProofBundle bundle) {
        String rid;
        long ts;
        String prev;
        PathChainV1 base;
        if (origin) {
            rid = ridSupplier.get();
            ts = clock.getAsLong();
            prev = "";
            base = new PathChainV1(List.of());
        } else {
            if (inboundChain == null || inboundChain.stamps().isEmpty()) {
                throw new IllegalStateException("non-origin service " + svc + " has no inbound chain to append to");
            }
            StampV1 first = inboundChain.stamps().get(0);
            rid = first.rid();
            ts = first.ts();
            prev = inboundChain.prevSig();
            base = inboundChain;
        }

        StampV1 stamp = StampSignerV1.sign(svc, inst, rid, ts, bind, prev, key);
        PathChainV1 outgoing = base.withAppended(stamp);

        String proofHeader = null;
        if (bundle != null) {
            List<String> hops = new ArrayList<>(outgoing.stamps().stream().map(StampV1::svc).toList());
            hops.add(target);
            String route = Routes.join(hops);
            MerkleProof proof = bundle.proofFor(route);
            if (proof != null) {
                proofHeader = proof.encode();
            }
        }
        return new StampedHeaders(outgoing.encode(), proofHeader);
    }
}
