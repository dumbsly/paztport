// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.function.Consumer;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.NonceCacheUnavailableException;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.internal.VerifyInputs;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A service's receiver for v3 over HTTP, with no web framework and no request scope: given one request as it arrived
 * and the peer the transport authenticated, it decides whether the request is refused, what the handler starts from,
 * and whether the response may be attested, and says so in an {@link Accepted}. A framework's adapter reads the
 * request, calls {@link #accept}, then writes the refusal or runs the handler, and hands the complete response to
 * {@link Accepted#attest}. Where requests are verified ({@link Builder#verifyRequests}), the
 * {@link VerificationMode} the adapter passes applies, read once per request so that a switch cannot catch a request
 * half-way:
 *
 * <ul>
 *   <li>{@code OFF}: Paztport is off on this hop. Nothing is verified, not even to decide attestation, nothing is
 *       published, and the response is not attested. The chain and influence are still carried, so the handler's own
 *       calls are stamped as in any other mode, and unreadable influence is still refused 400.</li>
 *   <li>{@code AUDIT}: verify, publish an event on failure, and pass, unless the influence cannot be read: that is
 *       refused 400 in every mode, as below.</li>
 *   <li>{@code ENFORCE}: verify, publish an event and refuse {@code 403 {"reason":"<code>"}} on failure.</li>
 * </ul>
 *
 * A nonce cache that cannot answer gives no verdict, so there is no event and no reason code. Under {@code ENFORCE}
 * the request is refused 503 with an empty body ({@link HttpAnswer#unavailable}) and never reaches the handler; under
 * {@code AUDIT}, and on a receiver with no mode, it is served with its chain unverified and its answer unattested.
 * One warning names the cause's class and nothing else, and {@link Accepted#cacheFailure} carries the failure.
 *
 * The influence the handler starts from is the verified entries when the request verified, and otherwise the
 * entries as received. Influence that cannot be read is never dropped, because dropping it could hide private data
 * from the rule: in every mode, a non-origin service refuses it {@code 400 {"reason":"INFLUENCE_MISMATCH"}}.
 *
 * <p>A chain may name this service's operation ({@code rcv} {@code <service>#<operation>}). The adapter passes the
 * operation its framework will dispatch the request to ({@link InboundRequest#operation}), and the request is
 * verified as received by {@code <service>#<operation>}, so a chain naming another operation, or one when the
 * framework dispatches to none, is refused {@code BINDING_MISMATCH}. A chain that names no operation is verified
 * under the service alone, whatever is dispatched. The trace line names the receiver as it was verified.
 *
 * <p>An origin starts every request tree afresh: it ignores the inbound chain and influence, so its handler starts
 * from none, and it never attests.
 *
 * <p>A non-origin service holding a stamp key and a verifier attests what it answers: one stamp on the chain it
 * received, back to the caller, binding the status, the body and the labels the handler gave it, sent as
 * {@code X-Path-Response}. It attests only a chain that passed the full live order here (its own verifier, itself as
 * receiver, the request's proof and influence, the peer) whether or not it enforces, unless an operator has switched
 * its verification {@code OFF}. A response stamp is shaped like a request stamp, so attesting a chain nobody checked
 * would let whoever sent it mint stamps under this service's key: a one-stamp chain with an empty signature would come
 * back as a valid origin stamp from this service. Where the request was already verified under the mode, that result
 * decides; otherwise the chain is verified for attestation alone, once, and a failure only withholds the
 * attestation: the request is served, and nothing is published. A request it refused, or that failed in
 * {@code AUDIT}, gets no attestation either. A service without a verifier never attests.
 *
 * <p>{@code OFF} withholds attestation only on a service that verifies requests, because only there is it a choice:
 * the operator set that mode to take Paztport off the hop, and a hop that is off must not run Paztport's work at all,
 * or {@code OFF} would not be a baseline to measure against. A service that does not verify requests has no mode to
 * switch; it is not off, it only does not enforce, so its verifier still decides attestation as above. Switching a
 * hop off is fail-safe: its caller records an unattested response as {@code local-untrusted}, so it can only add
 * caution downstream, never vouch for anything.
 *
 * <p>With a peer, the request is verified against the sender the transport authenticated ({@link PeerCert}): the
 * chain's last signer must be the service its certificate names, and every result names that service at the address
 * it connected from. The event carries both; the trace line shows only the peer's service. A refusal names no one
 * ({@link HttpAnswer#refusal}).
 *
 * <p>A non-null {@link ReceivedRequestListener} is offered every request first, before any verification, so an
 * application can observe traffic without the SDK knowing why. Every verification, including one run only to decide
 * attestation, logs one {@code PAZTPORT_TRACE request} line. The chain header is read once per request, for the
 * chain the handler carries and the nonce key alike; the verifier reads it again for itself.
 *
 * <p>This is the function a framework adapts, in any binding: it touches no thread-local. Carrying its result for the
 * handler is the binding's work, as
 * {@link RequestContext#accept(HttpReceiver, InboundRequest, Peer, VerificationMode)} does for blocking Java.
 */
public final class HttpReceiver {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");
    static final Logger LOG = LoggerFactory.getLogger(HttpReceiver.class);

    private static final HttpAnswer UNREADABLE_INFLUENCE = HttpAnswer.refusal(400, ReasonCode.INFLUENCE_MISMATCH);

    private final Verifier verifier;
    private final boolean verifyRequests;
    private final boolean origin;
    private final String receiver;
    private final EventPublisher publisher;
    private final ReceivedRequestListener listener;
    private final Stamper stamper;

    private HttpReceiver(Builder b) {
        this.verifier = b.verifier;
        this.verifyRequests = b.verifyRequests;
        this.origin = b.origin;
        this.receiver = b.receiver;
        this.publisher = b.publisher;
        this.listener = b.listener;
        this.stamper = b.stamper;
    }

    /**
     * A receiver for the service {@code receiver}, which every request's last stamp must be addressed to. A service
     * left unnamed may still be built, as one that is never configured to verify anything; whatever it verifies is
     * then addressed to no one, and fails.
     */
    public static Builder builder(String receiver) {
        return new Builder(receiver);
    }

    /**
     * What a receiver is built with. Only the service's name is required; a receiver with nothing else neither
     * verifies nor attests, and carries what it is sent.
     */
    public static final class Builder {

        private final String receiver;
        private Verifier verifier;
        private boolean verifyRequests;
        private boolean origin;
        private EventPublisher publisher;
        private ReceivedRequestListener listener;
        private Stamper stamper;

        private Builder(String receiver) {
            this.receiver = receiver;
        }

        /**
         * This service's verifier, where it holds a keyring, a root and a pin; without one it neither verifies nor
         * attests.
         */
        public Builder verifier(Verifier verifier) {
            this.verifier = verifier;
            return this;
        }

        /**
         * Whether requests are verified under the mode {@link #accept} is given. It needs a verifier and a publisher.
         * Otherwise the verifier only decides attestation, and the receiver has no mode.
         */
        public Builder verifyRequests(boolean verifyRequests) {
            this.verifyRequests = verifyRequests;
            return this;
        }

        /** Whether this service is an entry point, which ignores the inbound chain and influence and never attests. */
        public Builder origin(boolean origin) {
            this.origin = origin;
            return this;
        }

        /** Where a verification that fails under the mode is published. */
        public Builder publisher(EventPublisher publisher) {
            this.publisher = publisher;
            return this;
        }

        /** Offered every request before any verification; optional. */
        public Builder listener(ReceivedRequestListener listener) {
            this.listener = listener;
            return this;
        }

        /** This service's stamper, where it has a stamp key; without one it cannot attest. */
        public Builder stamper(Stamper stamper) {
            this.stamper = stamper;
            return this;
        }

        /** @throws IllegalArgumentException when requests are verified with no verifier or no publisher */
        public HttpReceiver build() {
            if (verifyRequests && (verifier == null || publisher == null)) {
                throw new IllegalArgumentException("verifying requests needs a verifier and a publisher");
            }
            return new HttpReceiver(this);
        }
    }

    /**
     * Decides one request.
     *
     * @param request the request as it arrived
     * @param peer the sender the transport authenticated, or null without one (plain HTTP, or no client certificate)
     * @param mode the operator's mode for this request, read once; a receiver that does not verify requests has none
     *     and is given {@code OFF}
     * @throws IllegalArgumentException when a receiver that does not verify requests is given another mode
     */
    public Accepted accept(InboundRequest request, Peer peer, VerificationMode mode) {
        return accept(request, peer, mode, chain -> {
        });
    }

    /**
     * {@link #accept(InboundRequest, Peer, VerificationMode)}, telling {@code carried} the chain the request carries
     * as soon as it is read, before the listener is offered the request. A binding uses it to hold that chain for
     * everything the receiver calls out to, as it will for the handler; the receiver itself holds nothing.
     */
    Accepted accept(InboundRequest request, Peer peer, VerificationMode mode, Consumer<List<Stamp>> carried) {
        Objects.requireNonNull(mode, "mode");
        if (!verifyRequests && mode != VerificationMode.OFF) {
            throw new IllegalArgumentException("a receiver that does not verify requests has no mode but OFF");
        }
        String chainHeader = request.header(PaztportHeaders.CHAIN);
        String proofHeader = request.header(PaztportHeaders.PROOF);
        String influenceHeader = request.header(PaztportHeaders.INFLUENCE);

        // An origin starts a new request tree, so whatever chain came with the request is not carried.
        String chain = HttpWire.decodeChain(chainHeader);
        ParsedChain parsed = Chains.parse(chain);
        List<Stamp> received = stamps(parsed);
        List<Stamp> inbound = origin ? null : received;
        String named = receiverFor(receiver, received, request.operation());
        String rid = received != null ? received.get(0).rid() : "";
        carried.accept(inbound);
        if (listener != null) {
            listener.received(chainHeader, proofHeader, influenceHeader, request.method(), request.target(),
                    request.body());
        }
        // The operator took Paztport off this hop. A service that does not verify requests is OFF here too, but has
        // no mode to switch, so it still attests what verifies.
        boolean switchedOff = verifyRequests && mode == VerificationMode.OFF;
        List<InfluenceEntry> influence;
        // The live order's result on this request here, once it has run: it decides attestation.
        VerifyResult checked = null;
        boolean verified = false;
        NonceCacheUnavailableException cacheFailure = null;
        if (mode != VerificationMode.OFF) {
            VerifyInput input = VerifyInputs.request(chain, parsed, proofHeader, influenceHeader, request.method(),
                    request.target(), request.body(), named, peer);
            try {
                checked = verifier.verify(input);
            } catch (NonceCacheUnavailableException e) {
                // No verdict: nothing is verified or published, and only enforce refuses.
                cacheFailure = cacheUnavailable(e);
            }
            // On OK these are the entries the last stamp committed to; otherwise what was received.
            influence = parseInfluence(input.influence());
            if (cacheFailure != null) {
                if (mode == VerificationMode.ENFORCE) {
                    return Accepted.unavailable(cacheFailure);
                }
            } else {
                trace(traceLine(rid, checked, named, peer, influence));
                if (!checked.ok()) {
                    publisher.publish(new AttestationEvent(checked.reason().name(), checked.suspectSvc(),
                            checked.suspectInst(), rid, mode == VerificationMode.AUDIT));
                    if (mode == VerificationMode.ENFORCE) {
                        return Accepted.refused(HttpAnswer.refusal(403, checked.reason()), checked);
                    }
                } else if (!origin && inbound != null) {
                    verified = true;
                }
            }
        } else {
            influence = parseInfluence(HttpWire.decodeInfluence(influenceHeader));
        }
        // An origin starts the tree with no influence: what a client claims is not carried, so it cannot hide
        // anything by being unreadable either.
        if (!origin && influence == null) {
            return Accepted.refused(UNREADABLE_INFLUENCE, checked);
        }
        boolean attesting = !switchedOff && stamper != null && verifier != null && !origin && inbound != null;
        if (attesting && checked == null && cacheFailure == null) {
            // A hop that does not verify requests, so verified here for attestation alone: never refused, never
            // published. Run at most once per request, since the live order spends the request's nonce.
            try {
                checked = verifier.verify(VerifyInputs.request(chain, parsed, proofHeader, influenceHeader,
                        request.method(), request.target(), request.body(), named, peer));
                trace(traceLine(rid, checked, named, peer, influence));
                verified = checked.ok();
            } catch (NonceCacheUnavailableException e) {
                cacheFailure = cacheUnavailable(e);
            }
        }
        return Accepted.served(inbound, verified, origin ? List.of() : influence,
                attesting && checked != null && checked.ok() ? stamper : null, checked, cacheFailure);
    }

    /**
     * The name this request is verified under: {@code service#operation} when the chain's last stamp names an
     * operation and the framework dispatched to one, otherwise the bare service. Nothing here is trusted from the
     * claim; it only chooses which name the verifier confirms, so a request naming an operation the framework did not
     * dispatch to is refused, and a chain naming none is verified under the service alone.
     */
    static String receiverFor(String service, List<Stamp> received, String operation) {
        if (received != null && !received.isEmpty() && operation != null
                && received.get(received.size() - 1).rcv().indexOf('#') >= 0) {
            return service + "#" + operation;
        }
        return service;
    }

    /** Logs that the nonce cache could not answer: the cause's class only, never its message, a key or a stamp. */
    private static NonceCacheUnavailableException cacheUnavailable(NonceCacheUnavailableException e) {
        LOG.warn("nonce cache unavailable: {}", e.getCause().getClass().getName());
        return e;
    }

    private static void trace(String line) {
        if (TRACE.isInfoEnabled()) {
            TRACE.info(line);
        }
    }

    /** The received chain as stamps, or null when there is none or it does not parse. */
    static List<Stamp> stamps(ParsedChain parsed) {
        return parsed.ok() ? parsed.stamps() : null;
    }

    /** The entries, or null when the header could not be read as influence. */
    static List<InfluenceEntry> parseInfluence(String json) {
        try {
            return Influence.parse(json);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * {@code PAZTPORT_TRACE request rid=… reason=… receiver=… ✓|✗ peer=…|peer=none classes=…|classes=-}.
     * The rid and the classes come from the request, so every value goes through {@link LogSafe}.
     */
    static String traceLine(String rid, VerifyResult result, String receiver, Peer peer,
            List<InfluenceEntry> influence) {
        TreeSet<String> classes = new TreeSet<>();
        if (influence != null) {
            influence.forEach(e -> classes.add(e.cls().wire()));
        }
        return String.format("PAZTPORT_TRACE request rid=%s reason=%s receiver=%s %s %s classes=%s",
                rid.isEmpty() ? "-" : LogSafe.of(rid), result.reason(), LogSafe.of(receiver),
                result.ok() ? "✓" : "✗", peerField(peer),
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }

    /**
     * The same line from a partner, which verifies each request in the session the caller named: the line above
     * with {@code session=<status>} after it, so that the line itself is unchanged.
     */
    static String traceLine(String rid, VerifyResult result, String receiver, Peer peer,
            List<InfluenceEntry> influence, String session) {
        return traceLine(rid, result, receiver, peer, influence) + " session=" + session;
    }

    /** {@code peer=<svc> (mTLS)}, or {@code peer=none} without a client certificate. */
    static String peerField(Peer peer) {
        return peer == null ? "peer=none" : "peer=" + peerName(peer.svc()) + " (mTLS)";
    }

    /** A certificate that names no service is shown as {@code ""}, so the trace never reads {@code peer= (mTLS)}. */
    private static String peerName(String svc) {
        return svc.isEmpty() ? "\"\"" : LogSafe.of(svc);
    }
}
