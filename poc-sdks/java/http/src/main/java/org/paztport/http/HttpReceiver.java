// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import org.paztport.core.event.AttestationEvent;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.influence.RequestInfluence;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.RequestIntent;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.NonceCacheUnavailableException;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.ServedUnverified;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.internal.Extensions;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.internal.VerifyInputs;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A service's receiver for version 4 over HTTP, with no web framework and no request scope: given one request as it
 * arrived and the peer the transport authenticated, it decides whether the request is refused, what the handler starts
 * from, and whether the response may be attested, and says so in an {@link Accepted}. A framework's adapter reads the
 * request, calls {@link #accept}, then writes the refusal or runs the handler, and hands the complete response to
 * {@link Accepted#attest}. Where requests are verified ({@link Builder#verifyRequests}), the
 * {@link VerificationMode} the adapter passes applies, read once per request so that a switch cannot catch a request
 * half-way:
 *
 * <ul>
 *   <li>{@code OFF}: Paztport is off on this hop. Nothing is verified, not even to decide attestation, nothing is
 *       published, and the response is not attested. The chain and its blocks are still carried, so the handler's
 *       own calls are stamped as in any other mode, and blocks that cannot be carried are still refused 400.</li>
 *   <li>{@code AUDIT}: verify, publish an event on failure, and pass, unless the blocks cannot be carried: that is
 *       refused 400 in every mode, as below.</li>
 *   <li>{@code ENFORCE}: verify, publish an event and refuse {@code 403 {"reason":"<code>"}} on failure.</li>
 * </ul>
 *
 * <p>A nonce cache that cannot answer gives no verdict, so there is no event and no reason code. Under {@code ENFORCE}
 * the request is refused 503 with an empty body ({@link HttpAnswer#unavailable}) and never reaches the handler; under
 * {@code AUDIT}, and on a receiver with no mode, it is served with its chain unverified and its answer unattested.
 * One warning names the cause's class and nothing else, and {@link Accepted#cacheFailure} carries the failure.
 *
 * <p>The blocks ({@code X-Path-Extensions}) are carried with the chain, as received, for the handler's own calls to
 * forward before their own (spec wire.md, Blocks); none received is one empty block per stamp. Blocks are never
 * dropped or altered, because that would hide a claim from every later hop: in every mode, a non-origin service
 * refuses blocks it cannot carry, ones that do not read as one block per stamp of the chain it carries,
 * {@code 400 {"reason":"EXTENSION_MISMATCH"}} where verification has not refused them first. Where the chain passed
 * the live order here, the verifier's hand-over ({@link Accepted#handOver}) holds what the blocks hold for the names
 * the service acts on, read from its verifier ({@link Builder#extensions}); a request served without verifying is
 * handed its items as not verified, where its chain read and its blocks passed check 9a. A service that acts on
 * {@code influence} or {@code intent} refuses items under it that do not read, {@code 400} with the extension's
 * code, verified or not and in every mode, influence's first.
 *
 * <p>A chain may name this service's operation ({@code rcv} {@code <service>#<operation>}). The adapter passes the
 * operation its framework will dispatch the request to ({@link InboundRequest#operation}), and the request is
 * verified as received by {@code <service>#<operation>}, so a chain naming another operation, or one when the
 * framework dispatches to none, is refused {@code BINDING_MISMATCH}. A chain that names no operation is verified
 * under the service alone, whatever is dispatched. The trace line names the receiver as it was verified, and
 * {@link Accepted#operation} the operation, if any, for an adapter that checks it again as the handler runs.
 *
 * <p>Where the receiver holds its own table ({@link Builder#operations}) and the dispatched operation declares a key,
 * the receiver reads the key value from the request target, by the operation's template and never from anything else
 * the request says. A chain naming that operation is then verified with the key value in its nonce key,
 * {@code [rid, lastSvc, lastRcv, keyValue, "req"]}, so the operation is served once per request tree for each item,
 * and {@link Accepted#delivery} carries the value. A request with no key value (a percent-encoded, over-long or absent
 * value) is treated as dispatched to no operation, so a chain naming the operation is refused
 * {@code BINDING_MISMATCH} before any nonce key is spent. A chain that names no operation reads no key value, and is
 * verified with the bare key, {@code [rid, lastSvc, lastRcv, "req"]}, whatever is dispatched.
 *
 * <p>An origin starts every request tree afresh: it ignores the inbound chain and its blocks, so its handler starts
 * from none and is handed nothing, and it never attests.
 *
 * <p>A non-origin service holding a stamp key and a verifier attests what it answers: one stamp on the chain it
 * received, back to the caller, binding the status and the body the handler gave it, sent as {@code X-Path-Response}
 * with its own block. It attests only a chain that passed the full live order here (its own verifier, itself as
 * receiver, the request's proof and blocks, the peer) whether or not it enforces, unless an operator has switched
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

    /** The answer to blocks that fail check 9a at a request this service would serve without verifying. */
    private static final HttpAnswer BLOCKS_NOT_CARRIED = HttpAnswer.refusal(400, ReasonCode.EXTENSION_MISMATCH);

    private final Verifier verifier;
    private final boolean verifyRequests;
    private final boolean origin;
    private final String receiver;
    private final EventPublisher publisher;
    private final ReceivedRequestListener listener;
    private final Stamper stamper;
    private final OperationTable table;
    /** What this service acts on: a request served without verifying is handed its items under them. */
    private final ExtensionSettings extensions;

    private HttpReceiver(Builder b, ExtensionSettings extensions) {
        this.extensions = extensions;
        this.verifier = b.verifier;
        this.verifyRequests = b.verifyRequests;
        this.origin = b.origin;
        this.receiver = b.receiver;
        this.publisher = b.publisher;
        this.listener = b.listener;
        this.stamper = b.stamper;
        this.table = b.table;
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
        private OperationTable table;
        private ExtensionSettings extensions;

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

        /** Whether this service is an entry point, which ignores the inbound chain and its blocks and never attests. */
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

        /**
         * This service's own operation table, covered by the signed root, where it names its operations; null for
         * none. It is read only for the key value of the dispatched operation where that operation declares a key:
         * the operation itself is the adapter's to say ({@link InboundRequest#operation}). Without it no key value is
         * read, so a chain naming a keyed operation is verified with the operation's unkeyed nonce key, and the
         * delivery's key is null.
         */
        public Builder operations(OperationTable own) {
            this.table = own;
            return this;
        }

        /**
         * The extensions this service acts on and the names it carries, for a receiver with no verifier; one with a
         * verifier reads them from it ({@link Verifier#extensions}), and is refused others.
         * {@link ExtensionSettings#NONE} unless set.
         */
        public Builder extensions(ExtensionSettings extensions) {
            this.extensions = extensions;
            return this;
        }

        /**
         * @throws IllegalArgumentException when requests are verified with no verifier or no publisher, the
         *     operation table is another service's, or the extension settings differ from the verifier's
         */
        public HttpReceiver build() {
            if (verifyRequests && (verifier == null || publisher == null)) {
                throw new IllegalArgumentException("verifying requests needs a verifier and a publisher");
            }
            if (table != null && !table.service().equals(receiver)) {
                throw new IllegalArgumentException("the operation table is for the service " + table.service()
                        + ", not " + LogSafe.of(receiver));
            }
            return new HttpReceiver(this, Extensions.resolve(verifier, extensions));
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
        return accept(request, peer, mode, (chain, blocks) -> {
        });
    }

    /**
     * {@link #accept(InboundRequest, Peer, VerificationMode)}, telling {@code carried} the chain the request carries
     * and its blocks as soon as they are read, before the listener is offered the request. A binding uses it to hold
     * them for everything the receiver calls out to, as it will for the handler; the receiver itself holds nothing.
     */
    Accepted accept(InboundRequest request, Peer peer, VerificationMode mode,
            BiConsumer<List<Stamp>, List<Block>> carried) {
        Objects.requireNonNull(mode, "mode");
        if (!verifyRequests && mode != VerificationMode.OFF) {
            throw new IllegalArgumentException("a receiver that does not verify requests has no mode but OFF");
        }
        String chainHeader = request.header(PaztportHeaders.CHAIN);
        String proofHeader = request.header(PaztportHeaders.PROOF);
        String blocksHeader = request.header(PaztportHeaders.EXTENSIONS);

        // An origin starts a new request tree, so whatever chain came with the request is not carried.
        String chain = HttpWire.decodeChain(chainHeader);
        ParsedChain parsed = Chains.parse(chain);
        List<Stamp> received = stamps(parsed);
        List<Stamp> inbound = origin ? null : received;
        // Null beside a carried chain: blocks that cannot be carried. Where the request is served, check 9a refuses
        // them (ServedUnverified, below), and where it is verified, the verifier does.
        String blocksJson = HttpWire.decodeBlocks(blocksHeader);
        List<Block> blocks = carriedBlocks(inbound, blocksJson);
        String operation = request.operation();
        String keyValue = keyValue(operation, request.target());
        if (keyValue == null && keyed(operation)) {
            // A keyed operation with no key value is dispatched to as no operation, so a chain naming it fails
            // check 4 before any nonce key is spent.
            operation = null;
        }
        String named = receiverFor(receiver, received, operation);
        // Only a chain that names the operation carries its key value; one that names none keeps the bare key.
        String key = Objects.equals(named, receiver) ? null : keyValue;
        String rid = received != null ? received.get(0).rid() : "";
        carried.accept(inbound, blocks);
        if (listener != null) {
            listener.received(chainHeader, proofHeader, blocksHeader, request.method(), request.target(),
                    request.body());
        }
        // The operator took Paztport off this hop. A service that does not verify requests is OFF here too, but has
        // no mode to switch, so it still attests what verifies.
        boolean switchedOff = verifyRequests && mode == VerificationMode.OFF;
        // The live order's result on this request here, once it has run: it decides attestation.
        VerifyResult checked = null;
        boolean verified = false;
        NonceCacheUnavailableException cacheFailure = null;
        if (mode != VerificationMode.OFF) {
            VerifyInput input = VerifyInputs.request(chain, parsed, proofHeader, blocksHeader, request.method(),
                    request.target(), request.body(), named, key, peer);
            try {
                checked = verifier.verify(input);
            } catch (NonceCacheUnavailableException e) {
                // No verdict: nothing is verified or published, and only enforce refuses.
                cacheFailure = cacheUnavailable(e);
            }
            if (cacheFailure != null) {
                if (mode == VerificationMode.ENFORCE) {
                    return Accepted.unavailable(cacheFailure);
                }
            } else {
                trace(traceLine(rid, checked, named, peer, classes(checked)));
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
        }
        boolean attesting = !switchedOff && stamper != null && verifier != null && !origin && inbound != null;
        if (attesting && checked == null && cacheFailure == null) {
            // A hop that does not verify requests, so verified here for attestation alone: never refused, never
            // published. Run at most once per request, since the live order spends the request's nonce.
            try {
                checked = verifier.verify(VerifyInputs.request(chain, parsed, proofHeader, blocksHeader,
                        request.method(), request.target(), request.body(), named, key, peer));
                trace(traceLine(rid, checked, named, peer, classes(checked)));
                verified = checked.ok();
            } catch (NonceCacheUnavailableException e) {
                cacheFailure = cacheUnavailable(e);
            }
        }
        // The operation the request was verified with, where the chain named one and the live order ran, whether
        // or not it passed (it may have failed under audit or where it ran for attestation alone).
        String verifiedOperation = checked != null && !named.equals(receiver) ? operation : null;
        // A chain that passed the live order here is handed on as verified. Every other request this service is
        // about to serve is read by ServedUnverified (verification.md, "A service never serves a request whose
        // blocks fail check 9a"); an origin carries no chain and is not subject to it.
        HandOver handOver = null;
        if (verified) {
            handOver = checked.handOver();
        } else if (!origin) {
            ServedUnverified unverified = ServedUnverified.of(chain, blocksJson, extensions);
            if (!unverified.blocksMatch()) {
                return Accepted.refused(BLOCKS_NOT_CARRIED, checked);
            }
            handOver = unverified.handOver();
        }
        HttpAnswer unread = unreadInfluence(extensions, handOver, rid);
        if (unread == null) {
            unread = unreadIntent(extensions, handOver, rid);
        }
        if (unread != null) {
            return Accepted.refused(unread, checked);
        }
        return Accepted.served(inbound, blocks, verified, handOver,
                attesting && checked != null && checked.ok() ? stamper : null, checked, cacheFailure,
                verifiedOperation, key, extensions);
    }

    /**
     * The refusal of a service that acts on {@code influence} and is handed an item that does not read as an entry,
     * {@code 400} with the code {@link RequestInfluence#reason} gives, verified or not, in every mode (spec
     * influence.md, Entries); null otherwise. The one reading of a request's items at a receiver, so the one place
     * this answer is made; a service that does not act on influence reads nothing and refuses nothing for it. The log
     * names the signer of the first block holding such an item, never the item.
     *
     * @param handOver what the service is handed, or null for nothing
     */
    static HttpAnswer unreadInfluence(ExtensionSettings settings, HandOver handOver, String rid) {
        if (handOver == null || !settings.actsOn().contains(Influence.NAME)) {
            return null;
        }
        RequestInfluence read = Influence.readRequest(handOver.under(Influence.NAME));
        if (read.reads()) {
            return null;
        }
        LOG.warn("request refused, an influence item does not read: rid={} unreadSigner={}", LogSafe.of(rid),
                LogSafe.of(read.unreadSigner()));
        return HttpAnswer.refusal(400, read.reason());
    }

    /**
     * The refusal of a service that acts on {@code intent} and is handed items under it that do not read (spec
     * intent.md, The receiver's part, P1), {@code 400 INTENT_MISMATCH}, verified or not, in every mode; null
     * otherwise. It runs after {@link #unreadInfluence}, so a request whose items of both do not read is answered for
     * influence. A service that does not act on intent reads nothing and refuses nothing for it. The log names the
     * signer of the first block holding such items, never an item.
     *
     * @param handOver what the service is handed, or null for nothing
     */
    static HttpAnswer unreadIntent(ExtensionSettings settings, HandOver handOver, String rid) {
        if (handOver == null || !settings.actsOn().contains(Intent.NAME)) {
            return null;
        }
        RequestIntent read = Intent.readRequest(handOver.under(Intent.NAME));
        if (read.reads()) {
            return null;
        }
        LOG.warn("request refused, an intent item does not read: rid={} unreadSigner={}", LogSafe.of(rid),
                LogSafe.of(read.unreadSigner()));
        return HttpAnswer.refusal(400, read.reason());
    }

    /**
     * The blocks to carry with {@code inbound}: those received, read as one block per stamp, or one empty block per
     * stamp where none were received; null where no chain is carried, and null where the blocks received do not read
     * as one per stamp, so they cannot be forwarded unchanged.
     */
    static List<Block> carriedBlocks(List<Stamp> inbound, String blocks) {
        if (inbound == null) {
            return null;
        }
        if (blocks == null) {
            return Collections.nCopies(inbound.size(), Block.EMPTY);
        }
        try {
            List<Block> read = Block.parseAll(blocks);
            return read.size() == inbound.size() ? read : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The influence classes a trace line names: those of the entries handed on under influence where the live order
     * gave OK and the service acts on it, read by {@link Influence#readRequest}; none otherwise.
     */
    static List<InfluenceEntry> classes(VerifyResult result) {
        return result.ok() ? Influence.readRequest(result.handOver().under(Influence.NAME)).entries() : List.of();
    }

    /** Whether this receiver's own table has {@code operation}, and it declares a key. */
    private boolean keyed(String operation) {
        if (table == null || operation == null) {
            return false;
        }
        OperationTable.Operation op = table.operation(operation);
        return op != null && op.key() != null;
    }

    /**
     * The key value of a request to {@code operation} at {@code target}, the raw path plus {@code ?} and the raw query
     * as sent, read by this receiver's own table; null without a table or an operation, or where it gives none.
     */
    private String keyValue(String operation, String target) {
        if (table == null || operation == null) {
            return null;
        }
        int q = target.indexOf('?');
        return q < 0 ? table.keyValue(operation, target, null)
                : table.keyValue(operation, target.substring(0, q), target.substring(q + 1));
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
