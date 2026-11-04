// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;

/**
 * Stamps one hop's outbound call and its response. Framework-neutral: an HTTP layer hands it the inbound chain and
 * the binding, and sends whatever comes back.
 *
 * <p>An origin starts a chain; a non-origin appends to the one it received and fails closed without one, because
 * only entry points start chains. Every stamp carries its own time. A response is not a separate
 * structure: it is one more stamp on the request chain, naming the caller as receiver, so every live check applies
 * to it unchanged.
 */
public final class Stamper {

    private final String svc;
    private final String inst;
    private final PrivateKey key;
    private final boolean origin;
    private final Supplier<String> ridSupplier;
    private final LongSupplier clock;

    public Stamper(String svc, String inst, PrivateKey key, boolean origin, Supplier<String> ridSupplier,
            LongSupplier clock) {
        this.svc = svc;
        this.inst = inst;
        this.key = key;
        this.origin = origin;
        this.ridSupplier = ridSupplier;
        this.clock = clock;
    }

    /** The service this signs as: the {@code svc} of every stamp it makes. */
    public String svc() {
        return svc;
    }

    /** The chain to send, and the proof for its route; {@code proof} is null when the bundle holds none. */
    public record Stamped(List<Stamp> chain, MerkleProof proof) {
    }

    /**
     * Stamps an outbound call to {@code receiver}, committing the influence that shaped it.
     *
     * @throws IllegalArgumentException when this service's name or {@code receiver} is not a route node (see
     *     {@link Routes#requireValidNode}); nothing is signed
     */
    public Stamped next(List<Stamp> inbound, String receiver, String bind, List<InfluenceEntry> influence,
            ProofBundle bundle) {
        List<Stamp> chain = new ArrayList<>();
        String rid;
        String sess;
        String prev;
        if (origin) {
            rid = ridSupplier.get();
            sess = "";
            prev = "";
        } else {
            requireInbound(inbound);
            Stamp last = inbound.get(inbound.size() - 1);
            chain.addAll(inbound);
            rid = inbound.get(0).rid();
            sess = last.sess();
            prev = last.sig();
        }
        chain.add(sign(rid, sess, receiver, bind, Influence.commit(influence), prev));

        MerkleProof proof = null;
        if (bundle != null) {
            List<String> hops = new ArrayList<>(chain.stream().map(Stamp::svc).toList());
            hops.add(receiver);
            proof = bundle.proofFor(Routes.join(hops));
        }
        return new Stamped(List.copyOf(chain), proof);
    }

    /**
     * Stamps the call that leaves this organisation for {@code partnerEntry}, inside the session {@code sess}. The
     * stamp stands alone: {@code prev} is empty, because the partner holds only this service's keyring and the
     * internal chain's signers are not in it. It carries the internal chain's {@code rid} and the influence that
     * shaped the call, so the partner can check the same commitment as any receiver. Internal stamps stay with the
     * caller to keep as evidence; they are not sent. {@code sess} must be a real session id: an empty one would
     * make this a valid in-mesh origin stamp, so it is refused.
     *
     * <p>This checks nothing about {@code verifiedInternal}, only that it is there. The boundary stamp vouches for
     * the request that led to it, so on a chain nobody verified it signs for a request this service never
     * accepted. Pass only a chain that verified at this service.
     *
     * @throws IllegalArgumentException when {@code sess} is empty, or this service's name or {@code partnerEntry} is
     *     not a route node; nothing is signed
     */
    public Stamped boundary(List<Stamp> verifiedInternal, String sess, String partnerEntry, String bind,
            List<InfluenceEntry> influence, ProofBundle bundle) {
        requireInbound(verifiedInternal);
        if (sess == null || sess.isEmpty()) {
            throw new IllegalArgumentException("a boundary stamp needs a session id");
        }
        Stamp stamp = sign(verifiedInternal.get(0).rid(), sess, partnerEntry, bind, Influence.commit(influence), "");
        MerkleProof proof = bundle == null ? null : bundle.proofFor(Routes.join(List.of(svc, partnerEntry)));
        return new Stamped(List.of(stamp), proof);
    }

    /**
     * Stamps the response to the request whose chain is {@code inbound}: the receiver is the caller (the last
     * stamp's service), the {@code rid} and {@code sess} are the request's, and the influence is empty because a
     * response carries its labels in the binding instead. Over HTTP, callers pass the request's {@code rid} as
     * {@code callId}; it is taken as given. The caller appends this stamp to the chain it sent.
     *
     * <p>This checks nothing about {@code inbound}. A response stamp is shaped like a request stamp, so on a chain
     * nobody verified it can be a valid stamp the sender could never have made: on a forged one-stamp chain with
     * an empty {@code sig}, an origin's response is a genuine origin stamp. Pass only a chain that verified at this
     * service, and never respond from an origin.
     *
     * @throws IllegalArgumentException when this service's name, or the last stamp's {@code svc} that the response
     *     is for, is not a route node; nothing is signed
     */
    public Stamp respond(List<Stamp> inbound, String resultHash, String callId, List<ContentLabel> labels) {
        requireInbound(inbound);
        Stamp last = inbound.get(inbound.size() - 1);
        return sign(inbound.get(0).rid(), last.sess(), last.svc(), Bindings.response(resultHash, callId, labels),
                Influence.commit(List.of()), last.sig());
    }

    /**
     * The one place a stamp is signed. Both names must be route nodes, as a policy can hold nothing else: a stamp
     * over any other could never verify, so none is made. {@link Stamp} does not check this, because verifiers
     * rebuild signing bytes with it and must refuse such a stamp by their own checks, not by an exception.
     */
    private Stamp sign(String rid, String sess, String receiver, String bind, String infl, String prev) {
        requireNode(svc, "the signing service");
        requireNode(receiver, "the receiver");
        return Stamp.sign(svc, inst, rid, clock.getAsLong(), sess, receiver, bind, infl, prev, key);
    }

    /** Names the rule and the role, never the value: a name here may be a peer's, and may hold anything. */
    private static void requireNode(String name, String role) {
        try {
            Routes.requireValidNode(name);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(role
                    + " must be a route node: non-empty, not \".\" or \"..\", and none of '/', '\\', '|' or a lone"
                    + " surrogate; nothing is signed");
        }
    }

    private void requireInbound(List<Stamp> inbound) {
        if (inbound == null || inbound.isEmpty()) {
            throw new IllegalStateException("service " + svc + " has no inbound chain to stamp onto");
        }
    }
}
