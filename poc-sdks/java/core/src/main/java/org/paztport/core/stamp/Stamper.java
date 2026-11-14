// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;

/**
 * Stamps one hop's outbound call and its response. Framework-neutral: an HTTP layer hands it the inbound chain and
 * the binding, and sends whatever comes back.
 *
 * <p>An origin starts a chain; a non-origin appends to the one it received and fails closed without one, because
 * only entry points start chains. Every stamp carries its own time and commits to its signer's {@link Block}, the
 * claims this hop attaches; the stamper reads no extension. A response is not a separate structure: it is one more
 * stamp on the request chain, naming the caller as receiver, so every live check applies to it unchanged.
 *
 * <p>A stamp commits to its own block only. Sending the blocks received, then this hop's own, beside the chain is
 * the transport's (spec wire.md, Blocks, Forwarding), so {@link Stamped} carries the chain and the proof alone.
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
     * Stamps an outbound call to {@code receiver}, committing to {@code block}, this hop's own claims for the request
     * so far; {@link Block#EMPTY} for none.
     *
     * @throws NullPointerException when {@code block} is null; nothing is signed
     * @throws IllegalArgumentException when this service's name or {@code receiver} is not a route node (see
     *     {@link Routes#requireValidNode}), this service's name holds {@code #}, or a {@code receiver} holding
     *     {@code #} lacks a valid service part or a valid operation name (a route node holding no {@code #}); nothing
     *     is signed
     */
    public Stamped next(List<Stamp> inbound, String receiver, String bind, Block block, ProofBundle bundle) {
        Objects.requireNonNull(block, "block");
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
        chain.add(sign(rid, sess, receiver, bind, block.commit(), prev));

        MerkleProof proof = null;
        if (bundle != null) {
            proof = bundle.proofFor(Chains.route(chain, true));
        }
        return new Stamped(List.copyOf(chain), proof);
    }

    /**
     * Stamps the call that leaves this organisation for {@code partnerEntry}, inside the session {@code sess}. The
     * stamp stands alone: {@code prev} is empty, because the partner holds only this service's keyring and the
     * internal chain's signers are not in it. It carries the internal chain's {@code rid} and commits to
     * {@code block}, this service's claims, so the partner checks it as any receiver does. Internal stamps stay with
     * the caller to keep as evidence; they are not sent. {@code sess} must be a real session id: an empty one would
     * make this a valid in-mesh origin stamp, so it is refused.
     *
     * <p>This checks nothing about {@code verifiedInternal}, only that it is there. The boundary stamp vouches for
     * the request that led to it, so on a chain nobody verified it signs for a request this service never
     * accepted. Pass only a chain that verified at this service.
     *
     * @throws NullPointerException when {@code block} is null; nothing is signed
     * @throws IllegalArgumentException when {@code sess} is empty, or this service's name or {@code partnerEntry} is
     *     not a route node, this service's name holds {@code #}, or a {@code partnerEntry} holding {@code #} lacks a
     *     valid service part or a valid operation name (a route node holding no {@code #}); nothing is signed
     */
    public Stamped boundary(List<Stamp> verifiedInternal, String sess, String partnerEntry, String bind, Block block,
            ProofBundle bundle) {
        Objects.requireNonNull(block, "block");
        requireInbound(verifiedInternal);
        if (sess == null || sess.isEmpty()) {
            throw new IllegalArgumentException("a boundary stamp needs a session id");
        }
        Stamp stamp = sign(verifiedInternal.get(0).rid(), sess, partnerEntry, bind, block.commit(), "");
        MerkleProof proof = bundle == null ? null : bundle.proofFor(Routes.join(List.of(svc, partnerEntry)));
        return new Stamped(List.of(stamp), proof);
    }

    /**
     * Stamps the response to the request whose chain is {@code inbound}: the receiver is the caller (the last
     * stamp's service), the {@code rid} and {@code sess} are the request's, the binding is
     * {@link Bindings#response}, and the stamp commits to {@code block}, the responder's claims on the response. Over
     * HTTP, callers pass the request's {@code rid} as {@code callId}; it is taken as given. The caller appends this
     * stamp to the chain it sent.
     *
     * <p>This checks nothing about {@code inbound}. A response stamp is shaped like a request stamp, so on a chain
     * nobody verified it can be a valid stamp the sender could never have made: on a forged one-stamp chain with
     * an empty {@code sig}, an origin's response is a genuine origin stamp. Pass only a chain that verified at this
     * service, and never respond from an origin.
     *
     * @throws NullPointerException when {@code block} is null; nothing is signed
     * @throws IllegalArgumentException when this service's name, or the last stamp's {@code svc} that the response
     *     is for, is not a route node; nothing is signed
     */
    public Stamp respond(List<Stamp> inbound, String resultHash, String callId, Block block) {
        Objects.requireNonNull(block, "block");
        requireInbound(inbound);
        Stamp last = inbound.get(inbound.size() - 1);
        return sign(inbound.get(0).rid(), last.sess(), last.svc(), Bindings.response(resultHash, callId),
                block.commit(), last.sig());
    }

    /**
     * The one place a stamp is signed. Both names must be route nodes, as a policy can hold nothing else, and the
     * signing service's name must also hold no {@code #}. A receiver holding {@code #} needs a valid service part and
     * a valid operation name (a route node holding no {@code #}). A stamp over any other could never verify, so none
     * is made. {@link Stamp} does not check this, because verifiers rebuild signing bytes with it and must refuse
     * such a stamp by their own checks, not by an exception.
     */
    private Stamp sign(String rid, String sess, String receiver, String bind, String ext, String prev) {
        requireService(svc, "the signing service");
        requireNode(receiver, "the receiver");
        int hash = receiver.indexOf('#');
        if (hash >= 0) {
            requireService(Routes.service(receiver), "the receiver's service");
            requireOperation(receiver.substring(hash + 1), "the receiver's operation");
        }
        return Stamp.sign(svc, inst, rid, clock.getAsLong(), sess, receiver, bind, ext, prev, key);
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

    private static void requireService(String name, String role) {
        try {
            Routes.requireValidService(name);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(role + " must be a service name: a route node without '#'; nothing is"
                    + " signed");
        }
    }

    private static void requireOperation(String name, String role) {
        try {
            Routes.requireValidOperation(name);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(role + " must be an operation name: a route node without '#';"
                    + " nothing is signed");
        }
    }

    private void requireInbound(List<Stamp> inbound) {
        if (inbound == null || inbound.isEmpty()) {
            throw new IllegalStateException("service " + svc + " has no inbound chain to stamp onto");
        }
    }
}
