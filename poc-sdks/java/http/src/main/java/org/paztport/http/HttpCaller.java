// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.http.internal.LogSafe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A service's caller for v3 over HTTP, with no web framework: it stamps each call this service makes, and checks
 * each response against the chain it sent. A framework's adapter hands it the call as it will go on the wire, sets
 * the headers {@link #stampFromContext} returns, sends it, reads the response whole, and hands that to
 * {@link #recordToContext} before the application sees it.
 *
 * <p>The stamp names the receiver by its policy name, which the spec requires and which is the deployment's to
 * configure, never the request's or the destination's to say. By default that name is the URI's host (Docker Compose
 * service names equal hostnames); {@link Builder#receivers} maps a host that is not the policy name to the one that
 * is. The binding covers the raw path and the raw query, exactly as they go on the wire, so the receiver can bind the
 * same bytes its container hands it without decoding anything.
 *
 * <p>What a response says becomes part of the request that made the call. A response whose attestation verifies, by
 * the live order on the chain that was sent (nonce key {@code <rid>|<target>|resp}), contributes its labels, each as
 * an entry with {@code src} {@code http:<target>} and {@code h} the result hash. Any other, unattested, failing, a
 * refusal, or one received where no verifier is configured, contributes exactly one {@code local-untrusted} entry
 * with the same {@code src} and {@code h}, so content nobody vouched for still counts against later calls; it is
 * never dropped. The target is the receiver's policy name, as stamped. Every response checked logs one
 * {@code PAZTPORT_TRACE response} line.
 *
 * <p>The functions are {@link #stamp(String, URI, byte[], List, List)}, given the inbound chain and the influence
 * so far, and {@link #check}, which answers what a response contributes; they touch no thread-local, so another
 * binding, or another language, mirrors them. {@link #stampFromContext} and {@link #recordToContext} are the blocking
 * Java binding of the same two, over {@link RequestContext}: inside a {@link RequestContext.Scope} the stamp commits
 * to the request's chain and influence, and what the response contributes is recorded there. Outside one (a
 * scheduled job, a startup runner, a control-plane handler) a call is still stamped, with no inbound chain and no
 * influence, and its response is still checked and traced, but nothing is recorded: there is no unit of work to
 * carry it, and a pooled thread would otherwise hand it to whatever ran next. The two layers do not mix: a call the
 * function stamped is checked by the function, whose caller carries what it answers.
 */
public final class HttpCaller {

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");

    private final String caller;
    private final StamperV3 stamper;
    private final ProofBundle bundle;
    private final VerifierV3 verifier;
    private final Map<String, String> receivers;

    private HttpCaller(Builder b) {
        this.caller = b.caller;
        this.stamper = b.stamper;
        this.bundle = b.bundle;
        this.verifier = b.verifier;
        this.receivers = b.receivers;
    }

    /**
     * A caller for the service {@code caller}, which stamps with {@code stamper}. The name is the one every response
     * stamp must be addressed to; a caller with nothing else names each receiver by its host, attaches no proof, and
     * checks no response.
     */
    public static Builder builder(String caller, StamperV3 stamper) {
        return new Builder(caller, stamper);
    }

    /** What a caller is built with. Only its name and its stamper are required. */
    public static final class Builder {

        private final String caller;
        private final StamperV3 stamper;
        private ProofBundle bundle;
        private VerifierV3 verifier;
        private Map<String, String> receivers = Map.of();

        private Builder(String caller, StamperV3 stamper) {
            this.caller = caller;
            this.stamper = Objects.requireNonNull(stamper, "stamper");
        }

        /** This service's route proofs, where it holds them; a call with no proof for its route is sent without. */
        public Builder bundle(ProofBundle bundle) {
            this.bundle = bundle;
            return this;
        }

        /**
         * This service's verifier, where it holds a keyring, a root and a pin; without one no response is checked, so
         * every response is one {@code local-untrusted} entry.
         */
        public Builder verifier(VerifierV3 verifier) {
            this.verifier = verifier;
            return this;
        }

        /**
         * The receivers' policy names, by the host a call is sent to, where that host is not the name: an address, a
         * load balancer's name, or a name inside another network. The host is matched ignoring case, as DNS does; a
         * host not listed is its own name. This replaces any mapping given before.
         *
         * <p>A table, not a function: the name is the deployment's configuration, which a table holds and shows, and
         * the same table is what the starter binds, and what another language's caller is given.
         *
         * @throws NullPointerException when {@code byHost} is null; an empty map is no mapping
         * @throws IllegalArgumentException when a host or a name is blank, or two hosts differ only in case
         */
        public Builder receivers(Map<String, String> byHost) {
            Objects.requireNonNull(byHost, "receivers");
            Map<String, String> names = new HashMap<>();
            byHost.forEach((host, name) -> {
                if (host == null || host.isBlank() || name == null || name.isBlank()) {
                    throw new IllegalArgumentException("a receiver's host and policy name must not be blank");
                }
                if (names.putIfAbsent(host.toLowerCase(Locale.ROOT), name) != null) {
                    throw new IllegalArgumentException("the receiver host " + LogSafe.of(host)
                            + " is listed twice, in different cases");
                }
            });
            this.receivers = Map.copyOf(names);
            return this;
        }

        public HttpCaller build() {
            return new HttpCaller(this);
        }
    }

    /**
     * The receiver's policy name for a call to {@code uri}: the name its host is mapped to, or the host itself. The
     * same name is the response's target.
     */
    public String receiver(URI uri) {
        String host = uri.getHost();
        return host == null ? null : receivers.getOrDefault(host.toLowerCase(Locale.ROOT), host);
    }

    /**
     * A call, stamped: the headers to set on it, in order, and what was stamped, which {@link #check} and
     * {@link #recordToContext} check its response against.
     */
    public static final class Outbound {

        private final Map<String, String> headers;
        private final StamperV3.Stamped sent;
        private final String receiver;
        private final boolean scoped;

        private Outbound(Map<String, String> headers, StamperV3.Stamped sent, String receiver, boolean scoped) {
            this.headers = headers;
            this.sent = sent;
            this.receiver = receiver;
            this.scoped = scoped;
        }

        /**
         * {@code X-Path-Chain}, then {@code X-Path-Proof} when there is a proof for the route, then
         * {@code X-Path-Influence} when there is influence; read-only.
         */
        public Map<String, String> headers() {
            return headers;
        }

        /** The chain sent, ending in this call's stamp, and the proof sent with it, if any. */
        public StamperV3.Stamped sent() {
            return sent;
        }

        /** The receiver's policy name, as stamped: the response's target. */
        public String receiver() {
            return receiver;
        }
    }

    /**
     * What a response contributes: the check of its attestation, null where this caller has no verifier and nothing
     * was checked, and the influence entries it adds, never empty.
     */
    public record Received(HttpV3.ResponseCheck check, List<InfluenceEntry> influence) {

        public Received {
            influence = List.copyOf(influence);
        }
    }

    /**
     * Stamps a call to {@code uri}, after {@code inbound} and committing to {@code influence}. This touches no
     * thread-local.
     *
     * @param method the request method, as sent
     * @param uri the request URI, as sent: its raw path and raw query are bound as they stand
     * @param body the request body, whole
     * @param inbound the chain this request received, or null where there is none (an origin, or no request)
     * @param influence what has shaped the call so far; empty for none
     */
    public Outbound stamp(String method, URI uri, byte[] body, List<StampV3> inbound,
            List<InfluenceEntry> influence) {
        return stamp(method, uri, body, inbound, influence, false);
    }

    /**
     * The blocking binding of {@link #stamp(String, URI, byte[], List, List)}: inside a scope, the call is stamped
     * after the request's inbound chain and commits to its influence so far; outside one, with neither, and its
     * response will not be recorded.
     */
    public Outbound stampFromContext(String method, URI uri, byte[] body) {
        // Outside a scope the context belongs to no unit of work, so it is neither read nor written.
        boolean scoped = RequestContext.isOpen();
        return stamp(method, uri, body, scoped ? RequestContext.inboundChain() : null,
                scoped ? RequestContext.influence() : List.of(), scoped);
    }

    private Outbound stamp(String method, URI uri, byte[] body, List<StampV3> inbound,
            List<InfluenceEntry> influence, boolean scoped) {
        String query = uri.getRawQuery();
        String target = query == null || query.isEmpty() ? uri.getRawPath() : uri.getRawPath() + "?" + query;
        String receiver = receiver(uri);
        StamperV3.Stamped stamped = stamper.next(inbound, receiver, RequestBinding.compute(method, target, body),
                influence, bundle);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(PaztportHeaders.CHAIN, HttpV3.encodeChain(stamped.chain()));
        if (stamped.proof() != null) {
            headers.put(PaztportHeaders.PROOF, HttpV3.encodeProof(stamped.proof()));
        }
        String influenceHeader = HttpV3.encodeInfluence(influence);
        if (influenceHeader != null) {
            headers.put(PaztportHeaders.INFLUENCE, influenceHeader);
        }
        return new Outbound(Collections.unmodifiableMap(headers), stamped, receiver, scoped);
    }

    /**
     * Checks a response to {@code sent} against the chain that was sent, logs the result, and answers what it
     * contributes. This touches no thread-local.
     *
     * @param sent the call, as either stamp stamped it
     * @param status the response status
     * @param xPathResponse the {@code X-Path-Response} header, or null when none came
     * @param body the response body, whole
     */
    public Received check(Outbound sent, int status, String xPathResponse, byte[] body) {
        String src = "http:" + sent.receiver;
        HttpV3.ResponseCheck check = null;
        String hash;
        if (verifier != null) {
            check = HttpV3.verifyResponse(verifier, sent.sent.chain(), sent.sent.proof(), xPathResponse, status,
                    body, caller);
            hash = check.resultHash();
        } else {
            hash = HttpV3.resultHash(status, body);
        }
        List<InfluenceEntry> influence;
        if (check != null && check.result().ok()) {
            influence = check.labels().stream().map(l -> l.toEntry(src, hash)).toList();
        } else {
            influence = List.of(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, src, hash, null, null));
        }
        if (TRACE.isInfoEnabled()) {
            TRACE.info(traceLine(sent.sent.chain().get(0).rid(), sent.receiver, check, caller));
        }
        return new Received(check, influence);
    }

    /**
     * The blocking binding of {@link #check}: checks the response and, when the call was stamped inside a scope,
     * adds what it contributes to the request's influence.
     *
     * <p>A call not stamped from the context, by the function or before the scope opened, is refused while a scope
     * is open, before it is checked, traced or recorded. The binding cannot tell whose work such a call was:
     * recording what its response adds might credit the wrong request, and dropping it, as an unscoped call's is,
     * would silently lose it, the {@code local-untrusted} entry an unchecked response must leave included. Refusing
     * before the check also leaves the response's nonce unspent, so {@link #check} can still take it. Outside a scope
     * there is no request to credit, so such a call is checked and traced, and nothing is recorded.
     *
     * @return the check of the response's attestation, or null where this caller has no verifier
     * @throws IllegalStateException when a scope is open and {@code sent} was not stamped from it
     */
    public HttpV3.ResponseCheck recordToContext(Outbound sent, int status, String xPathResponse, byte[] body) {
        if (!sent.scoped && RequestContext.isOpen()) {
            throw new IllegalStateException("this call was not stamped from the request's context, so its response"
                    + " cannot be recorded to it: stamp it with stampFromContext, or check its response with check"
                    + " and carry what that answers");
        }
        Received received = check(sent, status, xPathResponse, body);
        // Unscoped, there is nothing to carry it to: recording would leak it into whatever this thread runs next.
        if (sent.scoped) {
            RequestContext.addInfluence(received.influence().toArray(InfluenceEntry[]::new));
        }
        return received.check();
    }

    /**
     * {@code PAZTPORT_TRACE response rid=… from=… reason=… receiver=… ✓|✗ labels=…|labels=-}. With no verifier
     * nothing was checked, so the reason is {@code -}. The labels are the verified ones' classes; every value goes
     * through {@link LogSafe}, since the target and the labels come from outside.
     */
    static String traceLine(String rid, String from, HttpV3.ResponseCheck check, String receiver) {
        TreeSet<String> classes = new TreeSet<>();
        if (check != null) {
            check.labels().stream().map(ContentLabel::cls).forEach(c -> classes.add(c.wire()));
        }
        boolean ok = check != null && check.result().ok();
        return String.format("PAZTPORT_TRACE response rid=%s from=%s reason=%s receiver=%s %s labels=%s",
                LogSafe.of(rid), LogSafe.of(from), check == null ? "-" : check.result().reason(),
                LogSafe.of(receiver), ok ? "✓" : "✗",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }
}
