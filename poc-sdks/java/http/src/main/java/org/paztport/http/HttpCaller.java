// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.http.internal.Extensions;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A service's caller for version 4 over HTTP, with no web framework: it stamps each call this service makes, and checks
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
 * <p>A call carries its blocks ({@code X-Path-Extensions}) beside its chain, always (spec wire.md, Blocks): the blocks
 * the request received, unchanged, one empty block per stamp where it received none, then this service's own, which
 * its stamp commits to. A service that acts on influence names it in its own block with the entries it added for
 * this request itself, the responses to its own calls ({@link RequestContext#added}), {@code []} when it has added
 * none, and never the entries it was handed; one that does not signs the empty block. Either puts in the block's
 * {@code requires} what {@link Builder#requires} asks of the receiver. A call whose blocks would pass the wire limit,
 * 256 KiB, is refused before anything is signed: nothing is dropped to make room, and a deployment whose influence
 * grows that large raises its servers' header limit, which is reached long before.
 *
 * <p>What a response says becomes part of the request that made the call. Its attestation is checked by the live
 * order on the chain and the blocks that were sent, then the response stamp and its own block (nonce key
 * {@code [rid, lastRcv, "resp"]}, {@code lastRcv} the receiver the sent chain's last stamp names, with the operation
 * when it names one, or {@code [rid, lastRcv, keyValue, "resp"]} where that operation declares a key). A response
 * contributes the entries {@link Influence#responseEntries} gives, with {@code src} {@code http:<target>} and
 * {@code h} the result hash: one per label of a response that verified and names influence, otherwise exactly one
 * {@code local-untrusted} entry, so content still counts against later calls; it is never dropped. A response that
 * fails check 9c is also {@link Received#refused}. The target is the receiver's service name, without any
 * operation. Every response checked logs one {@code PAZTPORT_TRACE response} line.
 *
 * <p>Where the caller holds a receiver's operation table ({@link Builder#operations}), the stamp names the operation
 * the call invokes, {@code <receiver>#<operation>}, found by matching the call's method and raw path (without its
 * query, and not percent-decoded) to the table; a call no operation matches is refused before anything is signed. The
 * route proof attached is then the one for the chain ending at that operation. Everything that names the receiver as
 * a service keeps the bare name: {@link Outbound#receiver}, the response's target and its {@code src}. Where that
 * operation declares a key, the call's key value is read from its raw target as the match reads it
 * ({@link OperationTable#keyValue}) and kept as {@link Outbound#key}, for the response's nonce key: the call is made
 * once per request tree for each item. A call to a keyed operation that gives no key value (a percent-encoded,
 * over-long or absent value) is refused before anything is signed. A caller holding no table for the receiver names
 * it alone and reads no key value, so it calls the receiver once per request tree.
 *
 * <p>The functions are {@link #stamp(String, URI, byte[], List, List, List)}, given the inbound chain, its blocks and
 * the entries added so far, and {@link #check}, which answers what a response contributes; they touch no
 * thread-local, so another binding, or another language, mirrors them. {@link #stampFromContext} and
 * {@link #recordToContext} are the blocking Java binding of the same two, over {@link RequestContext}: inside a
 * {@link RequestContext.Scope} the stamp follows the request's chain, forwards its blocks and signs what it added,
 * and what the response contributes is recorded there. Outside one (a scheduled job, a startup runner, a
 * control-plane handler) a call is still stamped, with no inbound chain and nothing added, and its response is still
 * checked and traced, but nothing is recorded: there is no unit of work to
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
    private final ExtensionSettings extensions;
    private final Map<String, List<String>> requires;

    private HttpCaller(Builder b, ExtensionSettings extensions) {
        this.caller = b.caller;
        this.stamper = b.stamper;
        this.bundle = b.bundle;
        this.verifier = b.verifier;
        this.receivers = b.receivers;
        this.tables = b.tables;
        this.extensions = extensions;
        this.requires = Map.copyOf(b.requires);
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
        private ExtensionSettings extensions;
        private final Map<String, List<String>> requires = new HashMap<>();

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
         * lower-cased the same way. A host is ASCII, so a key that is not is refused. Each name is a service's,
         * never an operation's: the operation a call invokes is matched per call from the receiver's table
         * ({@link #operations}). This replaces any mapping given before.
         *
         * <p>A table, not a function: the name is the deployment's configuration, which a table holds and shows, and
         * the same table is what an adapter such as the Spring starter binds, and what another language's caller is
         * given.
         *
         * @throws NullPointerException when {@code byHost} is null; an empty map is no mapping
         * @throws IllegalArgumentException when a host or a name is blank, a name is not a service name (see
         *     {@link org.paztport.core.policy.Routes#requireValidService}: a route node holding no {@code #}), a
         *     host is not ASCII, or two hosts differ only in the case of their ASCII letters
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
                    Routes.requireValidService(name);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("a receiver's policy name must be a service name, a route"
                            + " node: non-empty, not \".\" or \"..\", and none of '/', '\\', '|', '#' or a lone"
                            + " surrogate");
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
         * the call's method and path to, and where that operation declares a key, the call's key value is read from
         * its target ({@link Outbound#key}). A receiver without a table is named by its service alone. This replaces
         * any tables given before.
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

        /**
         * The extensions this service acts on and the names it carries, for a caller with no verifier; one with a
         * verifier reads them from it ({@link Verifier#extensions}), and is refused others.
         * {@link ExtensionSettings#NONE} unless set.
         */
        public Builder extensions(ExtensionSettings extensions) {
            this.extensions = extensions;
            return this;
        }

        /**
         * The extensions this service requires of {@code receiver}, by its policy name, which every call to it puts in
         * the {@code requires} of its own block (spec wire.md, Blocks): the receiver refuses the call
         * ({@code EXTENSION_REQUIRED}) unless it acts on each. This replaces what was required of that receiver
         * before; an empty set requires nothing.
         *
         * @throws IllegalArgumentException when {@code receiver} is not a service name, or a name is not an extension
         *     name, as {@link Block#of} reads it
         */
        public Builder requires(String receiver, Set<String> extensions) {
            Objects.requireNonNull(extensions, "extensions");
            try {
                Routes.requireValidService(receiver);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("a required receiver must be a service name, a route node");
            }
            // The block's own reading of the names, so what is refused here is exactly what a call could not sign.
            requires.put(receiver, Block.of(Map.of(), extensions).requires());
            return this;
        }

        /** @throws IllegalArgumentException when the extension settings differ from the verifier's */
        public HttpCaller build() {
            return new HttpCaller(this, Extensions.resolve(verifier, extensions));
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
        private final List<Block> blocks;
        private final String receiver;
        private final String key;
        /**
         * The scope {@link #stampFromContext} stamped this call in, or null where it was stamped outside one or by
         * the function: {@link #recordToContext} records its response only to that same scope, while it is open.
         */
        final RequestContext.Scope scope;

        private Outbound(Map<String, String> headers, Stamper.Stamped sent, List<Block> blocks, String receiver,
                String key, RequestContext.Scope scope) {
            this.headers = headers;
            this.sent = sent;
            this.blocks = blocks;
            this.receiver = receiver;
            this.key = key;
            this.scope = scope;
        }

        /**
         * {@code X-Path-Chain}, then {@code X-Path-Proof} when there is a proof for the route, then
         * {@code X-Path-Extensions}; read-only.
         */
        public Map<String, String> headers() {
            return headers;
        }

        /** The chain sent, ending in this call's stamp, and the proof sent with it, if any. */
        public Stamper.Stamped sent() {
            return sent;
        }

        /** The blocks sent, one per stamp of the chain sent, this call's own last; read-only. */
        public List<Block> blocks() {
            return blocks;
        }

        /** The receiver's service name, without any operation: the response's target. */
        public String receiver() {
            return receiver;
        }

        /**
         * The call's key value, where the stamp names an operation that declares a key, read from the target sent;
         * otherwise null. The response's nonce key carries it.
         */
        public String key() {
            return key;
        }
    }

    /**
     * What a response contributes: the check of its attestation, null where this caller has no verifier and nothing
     * was checked, the influence entries it adds ({@link Influence#responseEntries}: one per label of a response that
     * verified and names influence, otherwise one {@code local-untrusted} entry), and whether the caller refuses it.
     *
     * @param refused whether the response failed check 9c ({@code EXTENSION_REQUIRED}), so the application must
     *     not use it, and, since the responder's handler has already run, must not retry the call on that ground
     */
    public record Received(HttpWire.ResponseCheck check, List<InfluenceEntry> influence, boolean refused) {

        /** Copies the entries. */
        public Received {
            influence = List.copyOf(influence);
        }
    }

    /**
     * Stamps a call to {@code uri}, after {@code inbound}, forwarding {@code inboundBlocks} and then this service's
     * own block, which holds {@code added} where it acts on influence. This touches no thread-local.
     *
     * @param method the request method, as sent; not null or empty
     * @param uri the request URI, as sent: its raw path and raw query are bound as they stand, except that an empty
     *     path is bound as {@code /}, which is what a client sends for it ({@code http://host?q=1} binds
     *     {@code /?q=1})
     * @param body the request body, whole
     * @param inbound the chain this request received, or null where there is none (an origin, or no request)
     * @param inboundBlocks the blocks it came with, one per stamp, or null for one empty block per stamp; null where
     *     there is no inbound chain
     * @param added the entries this service added for the request itself so far, never those it was handed; empty
     *     for none
     * @throws IllegalArgumentException when the method is null or empty, the URI's host has no receiver name (see
     *     {@link #receiver}), the receiver or this service is not a route node, or the receiver has an operation table
     *     and no operation of it matches the method and path, or the operation matched declares a key and the call
     *     gives no key value, or {@code inboundBlocks} are not one per stamp of {@code inbound} or are given with no
     *     inbound chain, or the blocks would pass the wire limit; nothing is signed
     */
    public Outbound stamp(String method, URI uri, byte[] body, List<Stamp> inbound, List<Block> inboundBlocks,
            List<InfluenceEntry> added) {
        return stamp(method, uri, body, inbound, inboundBlocks, added, null);
    }

    /**
     * The blocking binding of {@link #stamp(String, URI, byte[], List, List, List)}: inside a scope, the call is
     * stamped after the request's inbound chain, forwards its blocks and signs what the request added so far; outside
     * one, with none of them, and its response will not be recorded.
     *
     * @throws IllegalArgumentException when the method is null or empty, the URI's host has no receiver name, the
     *     receiver or this service is not a route node, or no operation of the receiver's table matches, or the
     *     keyed operation it matches has no key value in the call, or the blocks would pass the wire limit; nothing is
     *     signed
     */
    public Outbound stampFromContext(String method, URI uri, byte[] body) {
        // Outside a scope the context belongs to no unit of work, so it is neither read nor written.
        RequestContext.Scope scope = RequestContext.current();
        return scope == null ? stamp(method, uri, body, null, null, List.of(), null)
                : stamp(method, uri, body, RequestContext.inboundChain(), RequestContext.inboundBlocks(),
                        RequestContext.added(), scope);
    }

    private Outbound stamp(String method, URI uri, byte[] body, List<Stamp> inbound, List<Block> inboundBlocks,
            List<InfluenceEntry> added, RequestContext.Scope scope) {
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("the method of a call must not be empty");
        }
        // One block per inbound stamp (spec wire.md, Blocks): a list of another length, or one beside no chain, would
        // be signed into a call the next hop refuses at check 9a, so it is refused here, before anything is signed.
        if (inboundBlocks != null && (inbound == null || inboundBlocks.size() != inbound.size())) {
            throw new IllegalArgumentException(inbound == null ? "blocks given with no inbound chain; nothing is sent"
                    : "the inbound blocks are not one per inbound stamp; nothing is sent");
        }
        String receiver = receiver(uri);
        if (receiver == null) {
            throw new IllegalArgumentException("the host of a call has no receiver name");
        }
        // An empty path is sent as "/" (RFC 9112 section 3.2.1), and the receiver binds what it was sent.
        String rawPath = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery();
        String target = query == null || query.isEmpty() ? rawPath : rawPath + "?" + query;
        // The operation is matched on the raw path and raw query, as sent: nothing is percent-decoded.
        String named = receiver;
        String key = null;
        OperationTable table = tables.get(receiver);
        if (table != null) {
            String operation = table.match(method, rawPath, query);
            if (operation == null) {
                throw new IllegalArgumentException("no operation of " + receiver + " matches a "
                        + LogSafe.of(method) + " call; nothing is sent");
            }
            named = receiver + "#" + operation;
            if (table.operation(operation).key() != null) {
                key = table.keyValue(operation, rawPath, query);
                if (key == null) {
                    // Neither the target nor the value is named: they come from the call, which may carry data.
                    throw new IllegalArgumentException("the call to " + named + " has no key value; nothing is sent");
                }
            }
        }
        String bind = RequestBinding.compute(method, target, body);
        Block own = ownBlock(receiver, added);
        List<Block> blocks = new ArrayList<>();
        if (inbound != null) {
            blocks.addAll(inboundBlocks != null ? inboundBlocks : Collections.nCopies(inbound.size(), Block.EMPTY));
        }
        blocks.add(own);
        // Encoded before anything is signed: blocks past the wire limit are refused here, and nothing is dropped.
        String blocksHeader = HttpWire.encodeBlocks(blocks);
        Stamper.Stamped stamped = stamper.next(inbound, named, bind, own, bundle);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(stamped.chain()));
        if (stamped.proof() != null) {
            headers.put(PaztportHeaders.PROOF, HttpWire.encodeProof(stamped.proof()));
        }
        headers.put(PaztportHeaders.EXTENSIONS, blocksHeader);
        return new Outbound(Collections.unmodifiableMap(headers), stamped, List.copyOf(blocks), receiver, key, scope);
    }

    /**
     * This service's own block for a call to {@code receiver} (spec influence.md, The every-stamp rule): where it acts
     * on influence, influence named with {@code added}, {@code []} when it has added nothing; otherwise the empty
     * block, or one that names nothing and only requires, where something is required of the receiver.
     */
    private Block ownBlock(String receiver, List<InfluenceEntry> added) {
        List<String> required = requires.getOrDefault(receiver, List.of());
        if (extensions.actsOn().contains(Influence.NAME)) {
            return Influence.block(added, required);
        }
        return required.isEmpty() ? Block.EMPTY : Block.of(Map.of(), required);
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
            check = HttpWire.verifyResponse(verifier, sent.sent.chain(), sent.blocks, sent.sent.proof(),
                    xPathResponse, status, body, caller, sent.key);
            hash = check.resultHash();
        } else {
            hash = HttpWire.resultHash(status, body);
        }
        ReasonCode reason = check == null ? null : check.result().reason();
        List<InfluenceEntry> influence = Influence.responseEntries(reason,
                check == null ? null : check.response(Influence.NAME), src, hash);
        boolean refused = reason == ReasonCode.EXTENSION_REQUIRED;
        if (TRACE.isInfoEnabled()) {
            TRACE.info(traceLine(sent.sent.chain().get(0).rid(), sent.receiver, check, caller, influence));
        }
        return new Received(check, influence, refused);
    }

    /**
     * The blocking binding of {@link #check}: checks the response and, when the call was stamped inside the scope
     * that is open now, adds what it contributes to what the request added ({@link RequestContext#added}).
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
     * @return what {@link #check} answers, whose entries are those recorded; its {@code refused()} is for the caller
     *     to act on, since the response's handler has already run, and its check is null where this caller has no
     *     verifier
     * @throws IllegalStateException when {@code sent} was not stamped in the scope open now, and either a scope is
     *     open or it was stamped in one
     */
    public Received recordToContext(Outbound sent, int status, String xPathResponse, byte[] body) {
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
        return received;
    }

    /**
     * {@code PAZTPORT_TRACE response rid=… from=… reason=… receiver=… ✓|✗ labels=…|labels=-}. With no
     * verifier nothing was checked, so the reason is {@code -}. The labels are the classes of the entries the
     * response's own labels added, sorted, or {@code -}; every value goes through {@link LogSafe}, since the target
     * comes from outside.
     */
    static String traceLine(String rid, String from, HttpWire.ResponseCheck check, String receiver,
            List<InfluenceEntry> added) {
        boolean ok = check != null && check.result().ok();
        // Only a label has a content id; the local-untrusted entry of an answer that was not believed has none.
        TreeSet<String> classes = new TreeSet<>();
        added.stream().filter(e -> e.cid() != null).forEach(e -> classes.add(e.cls().wire()));
        return String.format("PAZTPORT_TRACE response rid=%s from=%s reason=%s receiver=%s %s labels=%s",
                LogSafe.of(rid), LogSafe.of(from), check == null ? "-" : check.result().reason(),
                LogSafe.of(receiver), ok ? "✓" : "✗",
                classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }
}
