// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.Verifier;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
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
 * never dropped. The target is the receiver's service name, without any operation. Every response checked logs one
 * {@code PAZTPORT_TRACE response} line.
 *
 * <p>Where the caller holds a receiver's operation table ({@link Builder#operations}), the stamp names the operation
 * the call invokes, {@code <receiver>#<operation>}, found by matching the call's method and raw path (without its
 * query, and not percent-decoded) to the table; a call no operation matches is refused before anything is signed. The
 * route proof attached is then the one for the chain ending at that operation. Everything that names the receiver as
 * a service keeps the bare name: {@link Outbound#receiver}, the response's target and its {@code src}.
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
    private final Stamper stamper;
    private final ProofBundle bundle;
    private final Verifier verifier;
    private final Map<String, String> receivers;
    private final Map<String, OperationTable> tables;

    private HttpCaller(Builder b) {
        this.caller = b.caller;
        this.stamper = b.stamper;
        this.bundle = b.bundle;
        this.verifier = b.verifier;
        this.receivers = b.receivers;
        this.tables = b.tables;
    }

    /**
     * A caller for the service {@code caller}, which stamps with {@code stamper}. The name is the one every response
     * stamp must be addressed to; a caller with nothing else names each receiver by its host, attaches no proof, and
     * checks no response.
     */
    public static Builder builder(String caller, Stamper stamper) {
        return new Builder(caller, stamper);
    }

    /** What a caller is built with. Only its name and its stamper are required. */
    public static final class Builder {

        private final String caller;
        private final Stamper stamper;
        private ProofBundle bundle;
        private Verifier verifier;
        private Map<String, String> receivers = Map.of();
        private Map<String, OperationTable> tables = Map.of();

        private Builder(String caller, Stamper stamper) {
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
        public Builder verifier(Verifier verifier) {
            this.verifier = verifier;
            return this;
        }

        /**
         * The receivers' policy names, by the host a call is sent to, where that host is not the name: an address, a
         * load balancer's name, or a name inside another network. The host is matched as {@link URI#getHost} gives
         * it with its ASCII letters in lower case, as DNS does, and nothing else: an IPv6 host keeps its brackets,
         * and a trailing dot is kept, so {@code orders.} is not {@code orders}. A host not listed is its own name,
         * lower-cased the same way. A host is ASCII, so a key that is not is refused. This replaces any mapping
         * given before.
         *
         * <p>A table, not a function: the name is the deployment's configuration, which a table holds and shows, and
         * the same table is what the starter binds, and what another language's caller is given.
         *
         * @throws NullPointerException when {@code byHost} is null; an empty map is no mapping
         * @throws IllegalArgumentException when a host or a name is blank, a name is not a route node (see
         *     {@link org.paztport.core.policy.Routes#requireValidNode}: a call to it could never be stamped), a host
         *     is not ASCII, or two hosts differ only in the case of their ASCII letters
         */
        public Builder receivers(Map<String, String> byHost) {
            Objects.requireNonNull(byHost, "receivers");
            Map<String, String> names = new HashMap<>();
            byHost.forEach((host, name) -> {
                if (host == null || host.isBlank() || name == null || name.isBlank()) {
                    throw new IllegalArgumentException("a receiver's host and policy name must not be blank");
                }
                if (!isAscii(host)) {
                    throw new IllegalArgumentException("a receiver's host must be ASCII");
                }
                try {
                    Routes.requireValidNode(name);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("a receiver's policy name must be a route node: non-empty, not"
                            + " \".\" or \"..\", and none of '/', '\\', '|' or a lone surrogate");
                }
                if (names.putIfAbsent(asciiLower(host), name) != null) {
                    throw new IllegalArgumentException("the receiver host " + LogSafe.of(host)
                            + " is listed twice, in different cases");
                }
            });
            this.receivers = Map.copyOf(names);
            return this;
        }

        /**
         * The operation tables of the receivers this service calls, where it names the operation a call invokes: a
         * call to a receiver with a table is stamped {@code <receiver>#<operation>}, the operation the table matches
         * the call's method and path to. A receiver without a table is named by its service alone. This replaces any
         * tables given before.
         *
         * @throws NullPointerException when {@code tables} is null
         * @throws IllegalArgumentException when two tables are for one service
         */
        public Builder operations(Collection<OperationTable> tables) {
            Objects.requireNonNull(tables, "operations");
            Map<String, OperationTable> byService = new HashMap<>();
            for (OperationTable table : tables) {
                if (byService.putIfAbsent(table.service(), table) != null) {
                    throw new IllegalArgumentException("two operation tables are for the service " + table.service());
                }
            }
            this.tables = Map.copyOf(byService);
            return this;
        }

        public HttpCaller build() {
            return new HttpCaller(this);
        }
    }

    /**
     * The receiver's policy name for a call to {@code uri}: the name its host is mapped to, or the host with its
     * ASCII letters in lower case. The same name is the response's target. {@link URI}'s host grammar is ASCII, so
     * {@code getHost()} is null for any host that is not, and for a URI with no host: such a call gets no name
     * (null), and {@code stamp} refuses it.
     */
    public String receiver(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            return null;
        }
        String lower = asciiLower(host);
        return receivers.getOrDefault(lower, lower);
    }

    private static boolean isAscii(String s) {
        return s.chars().allMatch(c -> c <= 0x7F);
    }

    /** Folds only A-Z to a-z: a Unicode fold maps a non-ASCII character such as U+212A KELVIN SIGN onto a letter. */
    private static String asciiLower(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
        }
        return out.toString();
    }

    /**
     * A call, stamped: the headers to set on it, in order, and what was stamped, which {@link #check} and
     * {@link #recordToContext} check its response against.
     */
    public static final class Outbound {

        private final Map<String, String> headers;
        private final Stamper.Stamped sent;
        private final String receiver;
        /**
         * The scope {@link #stampFromContext} stamped this call in, or null where it was stamped outside one or by
         * the function: {@link #recordToContext} records its response only to that same scope, while it is open.
         */
        final RequestContext.Scope scope;

        private Outbound(Map<String, String> headers, Stamper.Stamped sent, String receiver,
                RequestContext.Scope scope) {
            this.headers = headers;
            this.sent = sent;
            this.receiver = receiver;
            this.scope = scope;
        }

        /**
         * {@code X-Path-Chain}, then {@code X-Path-Proof} when there is a proof for the route, then
         * {@code X-Path-Influence} when there is influence; read-only.
         */
        public Map<String, String> headers() {
            return headers;
        }

        /** The chain sent, ending in this call's stamp, and the proof sent with it, if any. */
        public Stamper.Stamped sent() {
            return sent;
        }

        /** The receiver's service name, without any operation: the response's target. */
        public String receiver() {
            return receiver;
        }
    }

    /**
     * What a response contributes: the check of its attestation, null where this caller has no verifier and nothing
     * was checked, and the influence entries it adds. A response that verifies adds one entry per label, so none
     * where it verified with no labels; any other adds exactly one {@code local-untrusted} entry.
     */
    public record Received(HttpWire.ResponseCheck check, List<InfluenceEntry> influence) {

        public Received {
            influence = List.copyOf(influence);
        }
    }

    /**
     * Stamps a call to {@code uri}, after {@code inbound} and committing to {@code influence}. This touches no
     * thread-local.
     *
     * @param method the request method, as sent; not null or empty
     * @param uri the request URI, as sent: its raw path and raw query are bound as they stand, except that an empty
     *     path is bound as {@code /}, which is what a client sends for it ({@code http://host?q=1} binds
     *     {@code /?q=1})
     * @param body the request body, whole
     * @param inbound the chain this request received, or null where there is none (an origin, or no request)
     * @param influence what has shaped the call so far; empty for none
     * @throws IllegalArgumentException when the method is null or empty, the URI's host has no receiver name (see
     *     {@link #receiver}), the receiver or this service is not a route node, or the receiver has an operation table
     *     and no operation of it matches the method and path; nothing is signed
     */
    public Outbound stamp(String method, URI uri, byte[] body, List<Stamp> inbound,
            List<InfluenceEntry> influence) {
        return stamp(method, uri, body, inbound, influence, null);
    }

    /**
     * The blocking binding of {@link #stamp(String, URI, byte[], List, List)}: inside a scope, the call is stamped
     * after the request's inbound chain and commits to its influence so far; outside one, with neither, and its
     * response will not be recorded.
     *
     * @throws IllegalArgumentException when the method is null or empty, the URI's host has no receiver name, the
     *     receiver or this service is not a route node, or no operation of the receiver's table matches; nothing is
     *     signed
     */
    public Outbound stampFromContext(String method, URI uri, byte[] body) {
        // Outside a scope the context belongs to no unit of work, so it is neither read nor written.
        RequestContext.Scope scope = RequestContext.current();
        return stamp(method, uri, body, scope != null ? RequestContext.inboundChain() : null,
                scope != null ? RequestContext.influence() : List.of(), scope);
    }

    private Outbound stamp(String method, URI uri, byte[] body, List<Stamp> inbound,
            List<InfluenceEntry> influence, RequestContext.Scope scope) {
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("the method of a call must not be empty");
        }
        String receiver = receiver(uri);
        if (receiver == null) {
            throw new IllegalArgumentException("the host of a call has no receiver name");
        }
        // An empty path is sent as "/" (RFC 9112 section 3.2.1), and the receiver binds what it was sent.
        String rawPath = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery();
        String target = query == null || query.isEmpty() ? rawPath : rawPath + "?" + query;
        // The operation is matched on the raw path alone, as sent: no query, and nothing percent-decoded.
        String named = receiver;
        OperationTable table = tables.get(receiver);
        if (table != null) {
            String operation = table.match(method, rawPath);
            if (operation == null) {
                throw new IllegalArgumentException("no operation of " + receiver + " matches a "
                        + LogSafe.of(method) + " call; nothing is sent");
            }
            named = receiver + "#" + operation;
        }
        Stamper.Stamped stamped = stamper.next(inbound, named, RequestBinding.compute(method, target, body),
                influence, bundle);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(stamped.chain()));
        if (stamped.proof() != null) {
            headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(stamped.proof()));
        }
        String influenceHeader = HttpWire.encodeInfluence(influence);
        if (influenceHeader != null) {
            headers.put(PaztportHeaders.INFLUENCE, influenceHeader);
        }
        return new Outbound(Collections.unmodifiableMap(headers), stamped, receiver, scope);
    }

    /**
     * Checks a response to {@code sent} against the chain that was sent and answers what it contributes. It logs
     * the response's {@code PAZTPORT_TRACE response} line, as every check does, whatever its caller does with the
     * answer; a binding of it, or a mirror in another language, logs the same line. This touches no thread-local.
     *
     * @param sent the call, as either stamp stamped it
     * @param status the response status
     * @param xPathResponse the {@code X-Path-Response} header, or null when none came
     * @param body the response body, whole
     */
    public Received check(Outbound sent, int status, String xPathResponse, byte[] body) {
        String src = "http:" + sent.receiver;
        HttpWire.ResponseCheck check = null;
        String hash;
        if (verifier != null) {
            check = HttpWire.verifyResponse(verifier, sent.sent.chain(), sent.sent.proof(), xPathResponse, status,
                    body, caller);
            hash = check.resultHash();
        } else {
            hash = HttpWire.resultHash(status, body);
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
     * The blocking binding of {@link #check}: checks the response and, when the call was stamped inside the scope
     * that is open now, adds what it contributes to the request's influence.
     *
     * <p>A call not stamped from the context, by the function or before the scope opened, is refused while a scope
     * is open, before it is checked, traced or recorded. The binding cannot tell whose work such a call was:
     * recording what its response adds might credit the wrong request, and dropping it, as an unscoped call's is,
     * would silently lose it, the {@code local-untrusted} entry an unchecked response must leave included. A call
     * stamped in a scope that has since closed is refused in the same way, inside a later scope or outside any: its
     * request is over, so what its response adds would be credited to another unit of work, or left on the thread
     * for the next. Refusing before the check also leaves the response's nonce unspent, so {@link #check} can still
     * take it. Outside a scope, a call stamped outside one has no request to credit, so it is checked and traced,
     * and nothing is recorded.
     *
     * @return the check of the response's attestation, or null where this caller has no verifier
     * @throws IllegalStateException when {@code sent} was not stamped in the scope open now, and either a scope is
     *     open or it was stamped in one
     */
    public HttpWire.ResponseCheck recordToContext(Outbound sent, int status, String xPathResponse, byte[] body) {
        RequestContext.Scope current = RequestContext.current();
        if (sent.scope == null && current != null) {
            throw new IllegalStateException("this call was not stamped from the request's context, so its response"
                    + " cannot be recorded to it: stamp it with stampFromContext, or check its response with check"
                    + " and carry what that answers");
        }
        if (sent.scope != current) {
            throw new IllegalStateException("this call was stamped in a scope that has ended, so its response cannot"
                    + " be recorded: record it before its scope closes, or check its response with check and carry"
                    + " what that answers");
        }
        Received received = check(sent, status, xPathResponse, body);
        // Unscoped, there is nothing to carry it to: recording would leak it into whatever this thread runs next.
        if (current != null) {
            RequestContext.addInfluence(received.influence().toArray(InfluenceEntry[]::new));
        }
        return received.check();
    }

    /**
     * {@code PAZTPORT_TRACE response rid=… from=… reason=… receiver=… ✓|✗ labels=…|labels=-}. With no
     * verifier nothing was checked, so the reason is {@code -}. The labels are the verified ones' classes; every
     * value goes through {@link LogSafe}, since the target and the labels come from outside.
     */
    static String traceLine(String rid, String from, HttpWire.ResponseCheck check, String receiver) {
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
