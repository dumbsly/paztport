// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paztport.http.VectorsHttpRules.NOW;
import static org.paztport.http.VectorsHttpRules.OWNED;
import static org.paztport.http.VectorsHttpRules.RID;
import static org.paztport.http.VectorsHttpRules.STEERED;
import static org.paztport.http.VectorsHttpRules.arr;
import static org.paztport.http.VectorsHttpRules.entries;
import static org.paztport.http.VectorsHttpRules.hex;
import static org.paztport.http.VectorsHttpRules.obj;
import static org.paztport.http.VectorsHttpRules.textList;
import static org.paztport.http.VectorsHttpRules.textSet;
import static org.paztport.http.VectorsHttpRules.texts;
import static org.paztport.http.VectorsHttpRules.tree;
import static org.paztport.http.VectorsHttpRules.unhex;
import static org.paztport.http.VectorsHttpRules.utf8;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.VectorsHttpRules.Chains;
import org.paztport.http.VectorsHttpRules.Fixtures;
import org.paztport.http.VectorsHttpRules.Material;
import org.paztport.http.VectorsHttpRules.Service;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.boundary.BoundaryHooks;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;

/**
 * The partner's and the egress's kinds in the {@code rules} section of {@code http-v3.json}. A partner case is a
 * script run against one {@link PartnerSessions} and its {@link PartnerReceiver}, with the handshake served by
 * {@link HttpSessions#serve} and each call entered through {@link RequestContext#accept}; its clock is set to each
 * step's time. A partner chooses each session's id from a fresh nonce of its own, so a case names its sessions
 * ({@code as}) and a call's boundary stamp is signed when the step runs, in the session it names. An egress case
 * enters one request at the egress and posts through {@link BoundaryClient} to a scripted partner on a loopback
 * port, which records what it receives.
 */
final class VectorsHttpPartner {

    static final byte[] CHARGE = "{\"charge\":100}".getBytes(StandardCharsets.UTF_8);
    static final List<String> DISABLED = List.of("POST /refund", "GET /statements/{id}");
    /** The egress's boundary key, as {@code boundaryInfluence} derives it. */
    static final byte[] BOUNDARY_KEY =
            Crypto.sha256("paztport-http-v3-vector-boundary-key".getBytes(StandardCharsets.UTF_8));

    private VectorsHttpPartner() {
    }

    // --- Partner scripts ---

    private static ObjectNode partner(String material, int maxSessionsPerPeer, long sessionIdleMs) {
        ObjectNode p = obj();
        p.put("material", material);
        p.set("pinned", texts("shop-policy"));
        p.set("clientOrigins", texts("payment"));
        p.set("unsafeDisabled", texts(DISABLED.toArray(String[]::new)));
        p.put("maxSessionsPerPeer", maxSessionsPerPeer);
        p.put("sessionIdleMs", sessionIdleMs);
        p.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        // The partner's own default: its builder holds a run to the call window unless told otherwise.
        p.put("runMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        p.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        p.put("start", NOW);
        return p;
    }

    private static ObjectNode partner() {
        return partner("psp", PartnerSessions.DEFAULT_MAX_SESSIONS_PER_PEER, PartnerSessions.DEFAULT_SESSION_IDLE_MS);
    }

    static JsonNode of(String label) {
        return obj().put("of", label);
    }

    static JsonNode id(String literal) {
        return obj().put("id", literal);
    }

    /** One script, built step by step; each call stamped for the partner gets a rid of its own. */
    private static final class Script {

        final ObjectNode c = obj();
        final ArrayNode steps;
        final Material shop;
        private int rids;

        Script(String name, ObjectNode partner, Material shop) {
            c.put("name", name);
            c.set("partner", partner);
            this.steps = c.putArray("steps");
            this.shop = shop;
        }

        Script handshake(long at, String peer, String request, String as, ObjectNode expected) {
            return handshake(at, peer, request, null, as, expected);
        }

        Script handshakeBody(long at, String peer, byte[] body, ObjectNode expected) {
            return handshake(at, peer, null, body, null, expected);
        }

        private Script handshake(long at, String peer, String request, byte[] body, String as, ObjectNode expected) {
            ObjectNode s = steps.addObject();
            s.put("at", at);
            ObjectNode h = s.putObject("handshake");
            text(h, "peer", peer);
            text(h, "request", request);
            text(h, "body", body == null ? null : hex(body));
            text(s, "as", as);
            s.set("expected", expected);
            return this;
        }

        /** A boundary stamp from payment, in {@code sess}, over {@code body} and committing to {@code committed}. */
        ObjectNode stamp(long at, JsonNode sess, String key, byte[] body, List<InfluenceEntry> committed) {
            ObjectNode st = obj();
            st.put("svc", "payment");
            st.put("inst", "pay-1");
            st.put("rid", "rid-b-" + ++rids);
            st.put("ts", at - 100);
            st.set("sess", sess);
            st.put("rcv", "psp");
            st.put("key", key);
            st.put("body", hex(body));
            st.set("influence", entries(committed));
            return st;
        }

        /**
         * {@code POST /charge} naming {@code session}, carrying {@link VectorsHttpRules#OWNED} and a boundary stamp
         * from payment made in that session, or in {@code s1} when the call names none.
         */
        ObjectNode charge(long at, String peer, JsonNode session) {
            return call(peer, session, "POST", "/charge", "/charge", CHARGE,
                    stamp(at, session == null ? of("s1") : session, "payment", CHARGE, OWNED),
                    shop.proofHeader(VectorsHttpRules.BOUNDARY_ROUTE), HttpWire.encodeInfluence(OWNED));
        }

        ObjectNode call(String peer, JsonNode session, String method, String target, String routePattern,
                byte[] body, ObjectNode stamp, String proofHeader, String influenceHeader) {
            ObjectNode call = obj();
            text(call, "peer", peer);
            call.set("session", session == null ? NullNode.instance : session);
            call.put("method", method);
            call.put("target", target);
            call.put("routePattern", routePattern);
            call.put("body", hex(body));
            call.set("stamp", stamp == null ? NullNode.instance : stamp);
            text(call, "proofHeader", proofHeader);
            text(call, "influenceHeader", influenceHeader);
            return call;
        }

        Script call(long at, ObjectNode call, ObjectNode expected) {
            ObjectNode s = steps.addObject();
            s.put("at", at);
            s.set("call", call);
            s.set("expected", expected);
            return this;
        }

        Script charge(long at, String peer, JsonNode session, ObjectNode expected) {
            return call(at, charge(at, peer, session), expected);
        }
    }

    private static void text(ObjectNode o, String name, String value) {
        if (value == null) {
            o.putNull(name);
        } else {
            o.put(name, value);
        }
    }

    static ObjectNode opened(String status) {
        ObjectNode e = obj();
        e.put("status", 200);
        e.putNull("error");
        e.put("sessionStatus", status);
        e.set("disabled", status.equals("unsafe") ? texts(DISABLED.toArray(String[]::new)) : arr());
        return e;
    }

    static ObjectNode handshakeError(String code) {
        ObjectNode e = obj();
        e.put("status", 400);
        e.put("error", code);
        e.putNull("sessionStatus");
        e.putNull("disabled");
        return e;
    }

    static ObjectNode attested(List<InfluenceEntry> influence, boolean trusted) {
        ObjectNode e = obj();
        e.putNull("refusal");
        e.put("attested", true);
        e.set("influence", entries(influence));
        e.put("trustedRecord", trusted);
        return e;
    }

    static ObjectNode unsafe() {
        ObjectNode e = obj();
        e.putNull("refusal");
        e.put("attested", false);
        e.set("influence", arr());
        e.put("trustedRecord", false);
        return e;
    }

    static ObjectNode refused(ReasonCode reason) {
        ObjectNode e = obj();
        e.set("refusal", VectorsHttpRules.refusal(403, reason));
        e.put("attested", false);
        e.set("influence", arr());
        e.put("trustedRecord", false);
        return e;
    }

    /** sessions-and-influence.md, over HTTP: a call names its session, which must be one its own peer opened. */
    static ArrayNode sessionHeader(Fixtures fx) {
        Material shop = fx.material("shop");
        ArrayNode a = arr();
        Script none = new Script("no header is an unsafe session, and nothing it carries is believed", partner(),
                shop).handshake(NOW, "shop", "shop", "s1", opened("attested"));
        a.add(none.call(NOW + 1_000, none.charge(NOW + 1_000, "shop", null), unsafe()).c);
        a.add(new Script("the session this peer opened", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .charge(NOW + 1_000, "shop", of("s1"), attested(OWNED, true)).c);
        a.add(new Script("an id that names no session", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .charge(NOW + 1_000, "shop", id("bm8tc3VjaC1zZXNzaW9u"), refused(ReasonCode.SESSION_UNKNOWN)).c);
        a.add(new Script("another peer's session", partner(), shop)
                .handshake(NOW, "clinic", "shop", "c1", opened("attested"))
                .charge(NOW + 1_000, "shop", of("c1"), refused(ReasonCode.SESSION_UNKNOWN)).c);
        a.add(new Script("the same name under another issuer", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .charge(NOW + 1_000, "shop-other-ca", of("s1"), refused(ReasonCode.SESSION_UNKNOWN)).c);
        a.add(new Script("no client certificate", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .charge(NOW + 1_000, null, of("s1"), refused(ReasonCode.SESSION_UNKNOWN)).c);
        a.add(new Script("a certificate that names no single service", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .charge(NOW + 1_000, "unnamed", of("s1"), refused(ReasonCode.SESSION_UNKNOWN)).c);
        a.add(new Script("an unsafe session believes nothing the call carries", partner(), shop)
                .handshake(NOW, "shop", "no-root", "u1", opened("unsafe"))
                .charge(NOW + 1_000, "shop", of("u1"), unsafe()).c);
        Script other = new Script("a stamp made in another session", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(NOW, "shop", "shop", "s2", opened("attested"));
        ObjectNode call = other.charge(NOW + 1_000, "shop", of("s2"));
        ((ObjectNode) call.get("stamp")).set("sess", of("s1"));
        a.add(other.call(NOW + 1_000, call, refused(ReasonCode.SESSION_UNKNOWN)).c);
        return a;
    }

    /** sessions-and-influence.md, over HTTP: sessions by id, at most N per peer, the least recently used evicted. */
    static ArrayNode sessionRegistry(Fixtures fx) {
        Material shop = fx.material("shop");
        ArrayNode a = arr();
        a.add(new Script("a peer's least recently used session is evicted", partner("psp", 2, 900_000), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(NOW + 1_000, "shop", "shop", "s2", opened("attested"))
                .charge(NOW + 2_000, "shop", of("s1"), attested(OWNED, true))
                .handshake(NOW + 3_000, "shop", "shop", "s3", opened("attested"))
                .charge(NOW + 4_000, "shop", of("s2"), refused(ReasonCode.SESSION_UNKNOWN))
                .charge(NOW + 5_000, "shop", of("s1"), attested(OWNED, true))
                .charge(NOW + 6_000, "shop", of("s3"), attested(OWNED, true)).c);
        a.add(new Script("replicas that share a certificate are one peer", partner("psp", 2, 900_000), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(NOW + 1_000, "shop-replica", "shop", "s2", opened("attested"))
                .handshake(NOW + 2_000, "shop", "shop", "s3", opened("attested"))
                .charge(NOW + 3_000, "shop", of("s1"), refused(ReasonCode.SESSION_UNKNOWN))
                .charge(NOW + 4_000, "shop", of("s2"), attested(OWNED, true)).c);
        a.add(new Script("another peer's handshakes evict none of this peer's", partner("psp", 2, 900_000), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(NOW + 1_000, "clinic", "shop", "c1", opened("attested"))
                .handshake(NOW + 2_000, "clinic", "shop", "c2", opened("attested"))
                .handshake(NOW + 3_000, "clinic", "shop", "c3", opened("attested"))
                .charge(NOW + 4_000, "shop", of("s1"), attested(OWNED, true)).c);
        a.add(new Script("a handshake replaces no session", partner("psp", 2, 900_000), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(NOW + 1_000, "shop", "shop", "s2", opened("attested"))
                .charge(NOW + 2_000, "shop", of("s1"), attested(OWNED, true))
                .charge(NOW + 3_000, "shop", of("s2"), attested(OWNED, true)).c);
        a.add(new Script("an idle session expires, and a call starts its idle period again",
                partner("psp", 2, 60_000), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .charge(NOW + 30_000, "shop", of("s1"), attested(OWNED, true))
                .charge(NOW + 89_000, "shop", of("s1"), attested(OWNED, true))
                .charge(NOW + 150_000, "shop", of("s1"), refused(ReasonCode.SESSION_UNKNOWN)).c);
        a.add(new Script("a handshake that opens no session changes none", partner("psp", 1, 900_000), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(NOW + 1_000, "shop", "short-nonce", null, handshakeError(HttpSessions.NO_SESSION))
                .charge(NOW + 2_000, "shop", of("s1"), attested(OWNED, true)).c);
        return a;
    }

    /** sessions-and-influence.md, over HTTP: the handshake endpoint's errors, and the peer it needs. */
    static ArrayNode handshakeErrors(Fixtures fx) {
        Material shop = fx.material("shop");
        // Each body is the shop's request in JCS member order but for the one flaw its case names, so that flaw is what
        // the reader refuses.
        JsonValue.Obj request = (JsonValue.Obj) JsonReader.wire(fx.handshake("shop"));
        byte[] stringRoot = jcs(with(request, "clientRoot", new JsonValue.Str("root")));
        byte[] nullWindow = jcs(with(request, "clientKeyringNotAfter", new JsonValue.Null()));
        byte[] unsigned = jcs(without(request, "clientKeyringSig"));
        byte[] noRingWindow = jcs(without(request, "clientKeyringNotAfter"));
        byte[] noRootWindow = jcs(with(request, "clientRoot",
                without((JsonValue.Obj) request.get("clientRoot"), "notAfter")));
        byte[] notANode = jcs(with(with(request, "clientKeyring", badNameKeyring(shop)), "clientKeyringSig",
                new JsonValue.Str(badNameKeyringSig(fx, shop))));
        ArrayNode a = arr();
        a.add(new Script("a body that is not JSON", partner(), shop)
                .handshakeBody(NOW, "shop", utf8("this is not JSON"), handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a JSON array", partner(), shop)
                .handshakeBody(NOW, "shop", utf8("[]"), handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a client root that is a string", partner(), shop)
                .handshakeBody(NOW, "shop", stringRoot, handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a keyring window that is null", partner(), shop)
                .handshakeBody(NOW, "shop", nullWindow, handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a keyring signature that is missing", partner(), shop)
                .handshakeBody(NOW, "shop", unsigned, handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a keyring window that is missing", partner(), shop)
                .handshakeBody(NOW, "shop", noRingWindow, handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a client root window that is missing", partner(), shop)
                .handshakeBody(NOW, "shop", noRootWindow, handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a keyring name that is not a route node", partner(), shop)
                .handshakeBody(NOW, "shop", notANode, handshakeError(HttpSessions.INVALID_PARAMS)).c);
        a.add(new Script("a nonce of 15 bytes", partner(), shop)
                .handshake(NOW, "shop", "short-nonce", null, handshakeError(HttpSessions.NO_SESSION)).c);
        a.add(new Script("a client root signature of 63 bytes", partner(), shop)
                .handshake(NOW, "shop", "short-root-sig", null, handshakeError(HttpSessions.NO_SESSION)).c);
        a.add(new Script("no client certificate", partner(), shop)
                .handshake(NOW, null, "shop", null, handshakeError(HttpSessions.NO_SESSION)).c);
        a.add(new Script("a certificate that names no single service", partner(), shop)
                .handshake(NOW, "unnamed", "shop", null, handshakeError(HttpSessions.NO_SESSION)).c);
        a.add(new Script("a request that opens an attested session", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested")).c);
        a.add(new Script("a request with no client root opens an unsafe session", partner(), shop)
                .handshake(NOW, "shop", "no-root", "u1", opened("unsafe")).c);
        return a;
    }

    /** The shop's keyring with one more service, named {@code a/b}: a name that is not a route node. */
    private static Map<String, String> badNameServices(Material shop) {
        Map<String, String> services = new TreeMap<>(shop.keyring().services());
        services.put("a/b", services.values().iterator().next());
        return services;
    }

    private static JsonValue.Obj badNameKeyring(Material shop) {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        badNameServices(shop).forEach((name, key) -> members.put(name, new JsonValue.Str(key)));
        return new JsonValue.Obj(members);
    }

    /** The shop policy key's signature over that keyring: genuine, so only the name rule refuses the request. */
    private static String badNameKeyringSig(Fixtures fx, Material shop) {
        return Base64Url.encode(Crypto.sign(fx.privateKey("shop-policy"),
                KeyringFile.signingBytes(shop.policyKey(), badNameServices(shop), shop.keyring().notAfter())));
    }

    private static byte[] jcs(JsonValue.Obj o) {
        return JsonWriter.wire(o);
    }

    /** {@code o} with its member {@code name} set to {@code value}, added or replaced. */
    private static JsonValue.Obj with(JsonValue.Obj o, String name, JsonValue value) {
        Map<String, JsonValue> members = new LinkedHashMap<>(o.members());
        members.put(name, value);
        return new JsonValue.Obj(members);
    }

    /** {@code o} without its member {@code name}. */
    private static JsonValue.Obj without(JsonValue.Obj o, String name) {
        Map<String, JsonValue> members = new LinkedHashMap<>(o.members());
        members.remove(name);
        return new JsonValue.Obj(members);
    }

    /** verification.md, at a partner: a session's calls once its material expires, and the partner's own lapse. */
    static ArrayNode sessionExpiry(Fixtures fx) {
        Material shop = fx.material("shop");
        long expires = VectorsHttpRules.EXPIRES;
        ArrayNode a = arr();
        a.add(new Script("a session's calls once the client's material has expired", partner(), shop)
                .handshake(NOW, "shop", "shop-expiring", "s1", opened("attested"))
                .charge(NOW + 1_000, "shop", of("s1"), attested(OWNED, true))
                .charge(expires, "shop", of("s1"), attested(OWNED, true))
                .charge(expires + 1, "shop", of("s1"), refused(ReasonCode.POLICY_EXPIRED)).c);
        a.add(new Script("a handshake once the client's material has expired is unsafe", partner(), shop)
                .handshake(expires + 1, "shop", "shop-expiring", "u1", opened("unsafe")).c);
        a.add(new Script("the partner's own lapse makes new sessions unsafe, not earlier ones",
                partner("psp-expiring", PartnerSessions.DEFAULT_MAX_SESSIONS_PER_PEER,
                        PartnerSessions.DEFAULT_SESSION_IDLE_MS), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"))
                .handshake(expires + 1, "shop", "shop", "u1", opened("unsafe"))
                .charge(expires + 2, "shop", of("s1"), attested(OWNED, true))
                .charge(expires + 3, "shop", of("u1"), unsafe()).c);
        return a;
    }

    /** verification.md, what a refusal carries, at the boundary: the partner's refusals, the unsafe gate's included. */
    static ArrayNode boundaryRefusals(Fixtures fx) {
        Material shop = fx.material("shop");
        String proof = shop.proofHeader(VectorsHttpRules.BOUNDARY_ROUTE);
        ArrayNode a = arr();
        Script forged = new Script("a stamp signed with another key", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"));
        a.add(forged.call(NOW + 1_000, forged.call("shop", of("s1"), "POST", "/charge", "/charge", CHARGE,
                forged.stamp(NOW + 1_000, of("s1"), "gateway", CHARGE, OWNED), proof, HttpWire.encodeInfluence(OWNED)),
                refused(ReasonCode.BAD_SIGNATURE)).c);
        Script altered = new Script("a body altered in transit", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"));
        a.add(altered.call(NOW + 1_000, altered.call("shop", of("s1"), "POST", "/charge", "/charge",
                utf8("{\"charge\":999}"), altered.stamp(NOW + 1_000, of("s1"), "payment", CHARGE, OWNED), proof,
                HttpWire.encodeInfluence(OWNED)), refused(ReasonCode.BINDING_MISMATCH)).c);
        Script other = new Script("influence other than the stamp commits to", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"));
        a.add(other.call(NOW + 1_000, other.call("shop", of("s1"), "POST", "/charge", "/charge", CHARGE,
                other.stamp(NOW + 1_000, of("s1"), "payment", CHARGE, OWNED), proof, HttpWire.encodeInfluence(STEERED)),
                refused(ReasonCode.INFLUENCE_MISMATCH)).c);
        Script unreadable = new Script("influence that cannot be read: a partner has no audit mode", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"));
        a.add(unreadable.call(NOW + 1_000, unreadable.call("shop", of("s1"), "POST", "/charge", "/charge", CHARGE,
                unreadable.stamp(NOW + 1_000, of("s1"), "payment", CHARGE, OWNED), proof, "not*base64url"),
                refused(ReasonCode.INFLUENCE_MISMATCH)).c);
        Script twice = new Script("the same call twice", partner(), shop)
                .handshake(NOW, "shop", "shop", "s1", opened("attested"));
        ObjectNode call = twice.charge(NOW + 1_000, "shop", of("s1"));
        a.add(twice.call(NOW + 1_000, call, attested(OWNED, true))
                .call(NOW + 1_500, call, refused(ReasonCode.REPLAY)).c);
        Script gated = new Script("operations switched off for unsafe sessions", partner(), shop)
                .handshake(NOW, "shop", "no-root", "u1", opened("unsafe"))
                .handshake(NOW, "shop", "shop", "s1", opened("attested"));
        gated.call(NOW + 1_000, gated.call("shop", of("u1"), "POST", "/refund", "/refund", CHARGE, null, null, null),
                refused(ReasonCode.UNSAFE_SESSION));
        gated.call(NOW + 2_000, gated.call("shop", of("u1"), "HEAD", "/statements/7", "/statements/{id}", new byte[0],
                null, null, null), refused(ReasonCode.UNSAFE_SESSION));
        gated.call(NOW + 3_000, gated.call("shop", null, "POST", "/refund", "/refund", CHARGE, null, null, null),
                refused(ReasonCode.UNSAFE_SESSION));
        gated.call(NOW + 4_000, gated.call("shop", of("u1"), "POST", "/charge", "/charge", CHARGE, null, null, null),
                unsafe());
        gated.call(NOW + 5_000, gated.call("shop", of("s1"), "POST", "/refund", "/refund", CHARGE,
                gated.stamp(NOW + 5_000, of("s1"), "payment", CHARGE, OWNED), proof, HttpWire.encodeInfluence(OWNED)),
                attested(OWNED, true));
        a.add(gated.c);
        return a;
    }

    // --- Running a partner script ---

    static ArrayNode runScript(JsonNode c, Fixtures fx) {
        JsonNode p = c.get("partner");
        AtomicLong clock = new AtomicLong(p.get("start").asLong());
        Material m = fx.material(p.get("material").asText());
        Set<String> pinned = new LinkedHashSet<>();
        p.get("pinned").forEach(k -> pinned.add(fx.publicKey(k.asText())));
        PartnerSessions sessions = PartnerSessions.builder()
                .ownRoot(m.root()).ownKeyring(m.keyring()).ownPolicyKey(m.policyKey())
                .ownService(m.entry()).ownServiceKey(fx.privateKey(m.entry())).ownReplyCert(m.replyCert())
                .pinnedClientKeys(pinned).clientOrigins(textSet(p.get("clientOrigins")))
                .unsafeDisabled(textList(p.get("unsafeDisabled")))
                .nonces(new InMemoryNonceCache(p.get("nonceTtlMs").asLong())).clock(clock::get)
                .callMaxAgeMs(p.get("callMaxAgeMs").asLong()).runMaxAgeMs(p.get("runMaxAgeMs").asLong())
                .maxSessionsPerPeer(p.get("maxSessionsPerPeer").asInt()).sessionIdleMs(p.get("sessionIdleMs").asLong())
                .build();
        PartnerReceiver receiver = new PartnerReceiver(sessions, m.entry());
        Map<String, String> opened = new HashMap<>();
        ArrayNode out = arr();
        for (JsonNode step : c.get("steps")) {
            clock.set(step.get("at").asLong());
            out.add(step.has("handshake") ? handshake(step, fx, sessions, opened)
                    : call(step.get("call"), fx, sessions, receiver, m.entry(), opened));
        }
        return out;
    }

    private static ObjectNode handshake(JsonNode step, Fixtures fx, PartnerSessions sessions,
            Map<String, String> opened) {
        JsonNode h = step.get("handshake");
        byte[] body = h.get("request").isNull() ? unhex(h.get("body")) : fx.handshake(h.get("request").asText());
        HttpAnswer answer;
        try {
            answer = HttpSessions.serve(new ByteArrayInputStream(body), fx.peer(h.get("peer")), sessions);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        JsonNode json = tree(new String(answer.json(), StandardCharsets.UTF_8));
        ObjectNode e = obj();
        e.put("status", answer.status());
        if (answer.status() == 200) {
            if (!step.get("as").isNull()) {
                opened.put(step.get("as").asText(), json.get("sess").asText());
            }
            e.putNull("error");
            e.set("sessionStatus", json.get("status"));
            e.set("disabled", json.get("disabled"));
        } else {
            e.set("error", json.get("error"));
            e.putNull("sessionStatus");
            e.putNull("disabled");
        }
        return e;
    }

    /** The session id a reference names: one a handshake opened, a literal id, or none. */
    private static String sessionId(JsonNode ref, Map<String, String> opened) {
        if (ref.isNull()) {
            return null;
        }
        if (ref.has("id")) {
            return ref.get("id").asText();
        }
        String sess = opened.get(ref.get("of").asText());
        if (sess == null) {
            throw new IllegalStateException("no session was opened as " + ref.get("of").asText());
        }
        return sess;
    }

    private static ObjectNode call(JsonNode call, Fixtures fx, PartnerSessions sessions, PartnerReceiver receiver,
            String entry, Map<String, String> opened) {
        String method = call.get("method").asText();
        String target = call.get("target").asText();
        Map<String, String> headers = new TreeMap<>();
        String sess = sessionId(call.get("session"), opened);
        if (sess != null) {
            headers.put(PaztportHeaders.SESSION, sess);
        }
        JsonNode st = call.get("stamp");
        if (!st.isNull()) {
            Stamp stamp = Stamp.sign(st.get("svc").asText(), st.get("inst").asText(), st.get("rid").asText(),
                    st.get("ts").asLong(), sessionId(st.get("sess"), opened), st.get("rcv").asText(),
                    RequestBinding.compute(method, target, unhex(st.get("body"))),
                    Influence.commit(entries(st.get("influence"))), "", fx.privateKey(st.get("key").asText()));
            headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(List.of(stamp)));
        }
        if (!call.get("proofHeader").isNull()) {
            headers.put(PaztportHeaders.PROOF, call.get("proofHeader").asText());
        }
        if (!call.get("influenceHeader").isNull()) {
            headers.put(PaztportHeaders.INFLUENCE, call.get("influenceHeader").asText());
        }
        InboundRequest request = new InboundRequest(method, target, headers, unhex(call.get("body")));
        ObjectNode e = obj();
        try (RequestContext.Entered<PartnerAccepted> entered = RequestContext.accept(receiver, request,
                fx.peer(call.get("peer")))) {
            PartnerAccepted a = entered.result();
            HttpAnswer refusal = a.refusal();
            // As an adapter does: an unsafe session's switched-off operations are refused before the handler runs.
            if (refusal == null && !a.attested()
                    && sessions.unsafeOperations().refuses(method, call.get("routePattern").asText())) {
                refusal = UnsafeOperations.refusal();
            }
            if (refusal == null) {
                e.putNull("refusal");
            } else {
                ObjectNode r = e.putObject("refusal");
                r.put("status", refusal.status());
                r.put("body", hex(refusal.json()));
            }
            e.put("attested", refusal == null && a.attested());
            e.set("influence", entries(refusal == null ? a.influence() : List.of()));
            e.put("trustedRecord", refusal == null && new PublicWrites(entry).shapedOnlyByTrusted());
        }
        return e;
    }

    // --- The egress ---

    /** The egress, payment, which calls the partner's entry psp; its boundary key is {@link #BOUNDARY_KEY}. */
    private static ObjectNode egressConfig() {
        ObjectNode e = obj();
        e.put("svc", "payment");
        e.put("inst", "pay-1");
        e.put("material", "shop");
        e.put("partner", "psp");
        e.put("partnerPolicyKey", "psp-policy");
        e.put("boundaryKey", Base64Url.encode(BOUNDARY_KEY));
        e.put("sessionIdleMs", 600_000);
        return e;
    }

    /** The request the egress was handed, entered at payment as a receiver case enters it; null for none. */
    private static ObjectNode inbound(Service service, String mode, List<Stamp> chain, List<InfluenceEntry> sent,
            Chains ch) {
        ObjectNode c = VectorsHttpRules.receiverCase("inbound", service, mode, ch.request(chain, sent));
        c.remove("name");
        c.remove("uses");
        c.remove("read");
        return c;
    }

    private static ObjectNode egressCase(String name, JsonNode inbound, List<String> handshakes, String replacement,
            List<ObjectNode> answers, int posts) {
        ObjectNode c = obj();
        c.put("name", name);
        c.set("egress", egressConfig());
        c.set("inbound", inbound == null ? NullNode.instance : inbound);
        ObjectNode script = c.putObject("partnerScript");
        script.set("handshakes", texts(handshakes.toArray(String[]::new)));
        script.put("replacement", replacement);
        ArrayNode calls = script.putArray("calls");
        answers.forEach(calls::add);
        ArrayNode p = c.putArray("posts");
        for (int i = 0; i < posts; i++) {
            ObjectNode post = p.addObject();
            post.put("path", "/charge");
            post.put("body", hex(CHARGE));
        }
        return c;
    }

    private static ObjectNode answer(int status, byte[] body) {
        ObjectNode a = obj();
        a.put("status", status);
        a.put("body", hex(body));
        return a;
    }

    private static ObjectNode posted(String outcome, Integer status, Boolean attested) {
        ObjectNode p = obj();
        p.put("outcome", outcome);
        if (status == null) {
            p.putNull("status");
            p.putNull("attested");
        } else {
            p.put("status", status);
            p.put("attested", attested);
        }
        return p;
    }

    private static ObjectNode handshakeReceived(boolean clientRoot) {
        ObjectNode r = obj();
        r.putObject("handshake").put("clientRoot", clientRoot);
        return r;
    }

    /** A call received in the session the {@code session}-th thing received opened, stamped or not. */
    private static ObjectNode callReceived(int session, List<InfluenceEntry> held, Material shop) {
        ObjectNode r = obj();
        ObjectNode call = r.putObject("call");
        call.put("method", "POST");
        call.put("path", "/charge");
        call.put("body", hex(CHARGE));
        call.put("session", session);
        if (held == null) {
            call.putNull("stamps");
            call.putNull("stampSession");
            call.putNull("proof");
            call.putNull("influence");
            return r;
        }
        List<InfluenceEntry> sent = BoundaryInfluence.reduce(held, BOUNDARY_KEY, RID, "psp", "payment");
        ObjectNode stamp = call.putArray("stamps").addObject();
        stamp.put("v", 3);
        stamp.put("svc", "payment");
        stamp.put("inst", "pay-1");
        stamp.put("rid", RID);
        stamp.put("ts", NOW);
        stamp.put("rcv", "psp");
        stamp.put("bind", RequestBinding.compute("POST", "/charge", CHARGE));
        stamp.put("infl", Influence.commit(sent));
        stamp.put("prev", "");
        call.put("stampSession", session);
        call.set("proof", tree(shop.proofs().get(VectorsHttpRules.BOUNDARY_ROUTE).toJson()));
        call.set("influence", entries(sent));
        return r;
    }

    private static InfluenceEntry fromPartner(int status, byte[] body) {
        return new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:psp", HttpWire.resultHash(status, body), null,
                null);
    }

    private static ObjectNode egressExpected(List<ObjectNode> posts, List<ObjectNode> received,
            List<InfluenceEntry> influence) {
        ObjectNode e = obj();
        ArrayNode p = e.putArray("posts");
        posts.forEach(p::add);
        ArrayNode r = e.putArray("received");
        received.forEach(r::add);
        e.set("influence", entries(Influence.normalise(influence)));
        return e;
    }

    /** sessions-and-influence.md, between organisations: what the egress signs and sends, and when it sends nothing. */
    static ArrayNode egress(Fixtures fx, Chains ch) {
        Material shop = fx.material("shop");
        byte[] ok = utf8("{\"ok\":true}");
        ObjectNode verified = inbound(Service.PAYMENT, "enforce", ch.owned, OWNED, ch);
        List<InfluenceEntry> afterOk = new ArrayList<>(OWNED);
        afterOk.add(fromPartner(200, ok));
        ArrayNode a = arr();
        a.add(egressCase("attested: one boundary stamp, and the influence blinded", verified, List.of("attested"),
                "unsafe", List.of(answer(200, ok)), 1).set("expected", egressExpected(
                        List.of(posted("answered", 200, true)),
                        List.of(handshakeReceived(true), callReceived(0, OWNED, shop)), afterOk)));
        a.add(egressCase("unsafe: the session id and nothing else", verified, List.of("unsafe"), "unsafe",
                List.of(answer(200, ok)), 1).set("expected", egressExpected(List.of(posted("answered", 200, false)),
                        List.of(handshakeReceived(true), callReceived(0, null, shop)), afterOk)));
        a.add(egressCase("a handshake answered 404 is followed by the replacement", verified, List.of("notFound"),
                "unsafe", List.of(answer(200, ok)), 1).set("expected", egressExpected(
                        List.of(posted("answered", 200, false)),
                        List.of(handshakeReceived(true), handshakeReceived(false), callReceived(1, null, shop)),
                        afterOk)));
        a.add(egressCase("a reply under a key other than the pinned one is followed by the replacement", verified,
                List.of("wrongKey"), "unsafe", List.of(answer(200, ok)), 1).set("expected", egressExpected(
                        List.of(posted("answered", 200, false)),
                        List.of(handshakeReceived(true), handshakeReceived(false), callReceived(1, null, shop)),
                        afterOk)));
        a.add(egressCase("the replacement's session is unsafe whatever its reply says", verified,
                List.of("notFound"), "attested", List.of(answer(200, ok)), 1).set("expected", egressExpected(
                        List.of(posted("answered", 200, false)),
                        List.of(handshakeReceived(true), handshakeReceived(false), callReceived(1, null, shop)),
                        afterOk)));
        byte[] unknown = utf8("{\"reason\":\"SESSION_UNKNOWN\"}");
        List<InfluenceEntry> afterUnknown = new ArrayList<>(OWNED);
        afterUnknown.add(fromPartner(403, unknown));
        List<InfluenceEntry> afterBoth = new ArrayList<>(afterUnknown);
        afterBoth.add(fromPartner(200, ok));
        a.add(egressCase("SESSION_UNKNOWN drops the session, and the next call opens another", verified,
                List.of("attested", "attested"), "unsafe", List.of(answer(403, unknown), answer(200, ok)), 2)
                .set("expected", egressExpected(
                        List.of(posted("answered", 403, true), posted("answered", 200, true)),
                        List.of(handshakeReceived(true), callReceived(0, OWNED, shop), handshakeReceived(true),
                                callReceived(2, afterUnknown, shop)), afterBoth)));
        a.add(egressCase("a replacement answered 404 too: the call fails, and nothing of it is sent", verified,
                List.of("notFound"), "notFound", List.of(), 1).set("expected", egressExpected(
                        List.of(posted("failed", null, null)),
                        List.of(handshakeReceived(true), handshakeReceived(false)), OWNED)));
        // The partner is scripted to answer nothing, so any handshake or call from these fails the replay.
        List<ObjectNode> nothing = List.of(posted("refused", null, null));
        a.add(egressCase("a chain that failed in audit mode: nothing is sent", inbound(Service.PAYMENT, "audit",
                ch.forged, List.of(), ch), List.of(), "unsafe", List.of(), 1)
                .set("expected", egressExpected(nothing, List.of(), List.of())));
        a.add(egressCase("a hop that is off: nothing is sent", inbound(Service.PAYMENT, "off", ch.clean, List.of(),
                ch), List.of(), "unsafe", List.of(), 1).set("expected", egressExpected(nothing, List.of(),
                        List.of())));
        a.add(egressCase("a service with no verifier: nothing is sent", inbound(Service.NO_VERIFIER, null, ch.owned,
                OWNED, ch), List.of(), "unsafe", List.of(), 1).set("expected", egressExpected(nothing, List.of(),
                        OWNED)));
        a.add(egressCase("an origin: nothing is sent", inbound(new Service("payment", "pay-1", true, true), null,
                ch.owned, OWNED, ch), List.of(), "unsafe", List.of(), 1)
                .set("expected", egressExpected(nothing, List.of(), List.of())));
        a.add(egressCase("outside any request: nothing is sent", null, List.of(), "unsafe", List.of(), 1)
                .set("expected", egressExpected(nothing, List.of(), List.of())));
        return a;
    }

    /** Runs one egress case against a scripted partner, and answers in the shape of its {@code expected}. */
    static ObjectNode runEgress(JsonNode c, Fixtures fx) {
        JsonNode cfg = c.get("egress");
        JsonNode inbound = c.get("inbound");
        long now = inbound.isNull() ? NOW : inbound.get("now").asLong();
        Material shop = fx.material(cfg.get("material").asText());
        String svc = cfg.get("svc").asText();
        ArrayNode posts = arr();
        ObjectNode e = obj();
        try (ScriptedPartner partner = ScriptedPartner.start(fx, c.get("partnerScript"), shop.keyring());
                BoundaryClient egress = BoundaryHooks.millis(BoundaryHooks.nanos(BoundaryClient.builder()
                        .stamper(new Stamper(svc, cfg.get("inst").asText(), fx.privateKey(svc), false,
                                () -> "unused", () -> now))
                        .bundle(shop.bundle(svc)).ownRoot(shop.root()).ownKeyring(shop.keyring())
                        .ownPolicyKey(shop.policyKey()).partner(cfg.get("partner").asText()).partnerUrl(partner.url())
                        .pinnedPartnerKey(fx.publicKey(cfg.get("partnerPolicyKey").asText()))
                        .blindingKey(Base64Url.decode(cfg.get("boundaryKey").asText()))
                        .http(HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                                .connectTimeout(Duration.ofSeconds(5))
                                .sslContext(StubPartner.fixtureContext("payment")).build())
                        .sessionIdleMs(cfg.get("sessionIdleMs").asLong()), () -> 0L), () -> now)
                        .build()) {
            List<InfluenceEntry> influence = List.of();
            if (inbound.isNull()) {
                post(egress, c.get("posts"), posts);
            } else {
                try (RequestContext.Entered<Accepted> entered = RequestContext.accept(
                        VectorsHttpRules.receiver(inbound, fx), VectorsHttpRules.inbound(inbound.get("request")),
                        VectorsHttpRules.peer(inbound.get("peer")), VectorsHttpRules.mode(inbound.get("mode")))) {
                    if (entered.result().refusal() != null) {
                        throw new IllegalStateException(c.get("name").asText() + ": the egress refused the request");
                    }
                    post(egress, c.get("posts"), posts);
                    influence = RequestContext.influence();
                }
            }
            e.set("posts", posts);
            e.set("received", partner.received(c.get("name").asText()));
            e.set("influence", entries(Influence.normalise(influence)));
        }
        return e;
    }

    private static void post(BoundaryClient egress, JsonNode posts, ArrayNode out) {
        for (JsonNode p : posts) {
            try {
                BoundaryClient.Response r = egress.post(p.get("path").asText(), unhex(p.get("body")));
                out.add(posted("answered", r.status(), r.attested()));
            } catch (IllegalStateException e) {
                out.add(posted(BoundaryHooks.NO_VERIFIED_CHAIN.equals(e.getMessage()) ? "refused" : "failed", null,
                        null));
            }
        }
    }

    /**
     * A partner reduced to a script, on a loopback port over HTTPS with the fixture certificate: each handshake with a
     * client root takes the next answer from {@code handshakes} ({@code attested} or {@code unsafe}, a genuine reply
     * in the entry-key form from the {@code psp} material; {@code notFound}, a 404; {@code wrongKey}, a reply in the
     * policy-key form signed by and naming {@code stranger-policy}); one with none is answered as
     * {@code replacement} says, signed genuinely; each call takes the next of {@code calls}. It records everything it
     * receives, and the session id each reply issued. A handshake or call the script has no answer for is answered
     * 500 and fails the replay, as does a boundary stamp whose signature does not verify under the egress's keyring
     * key for its {@code svc}, over the {@code sess} it carries.
     */
    static final class ScriptedPartner implements AutoCloseable {

        private record Received(String method, String path, Map<String, String> headers, byte[] body,
                Boolean clientRoot, String issued) {
        }

        private final Fixtures fx;
        private final Material psp;
        private final KeyringFile egressKeyring;
        private final List<String> beyondScript = new ArrayList<>();
        private final Deque<String> handshakes = new ArrayDeque<>();
        private final String replacement;
        private final Deque<JsonNode> calls = new ArrayDeque<>();
        private final List<Received> received = new ArrayList<>();
        private final HttpsServer server;
        private final ExecutorService executor = Executors.newSingleThreadExecutor();

        static ScriptedPartner start(Fixtures fx, JsonNode script, KeyringFile egressKeyring) {
            try {
                return new ScriptedPartner(fx, script, egressKeyring);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        private ScriptedPartner(Fixtures fx, JsonNode script, KeyringFile egressKeyring) throws IOException {
            this.fx = fx;
            this.psp = fx.material("psp");
            this.egressKeyring = egressKeyring;
            script.get("handshakes").forEach(h -> handshakes.add(h.asText()));
            this.replacement = script.get("replacement").asText();
            script.get("calls").forEach(calls::add);
            server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(StubPartner.fixtureContext("payment")));
            server.setExecutor(executor);
            server.createContext("/", this::handle);
            server.start();
        }

        URI url() {
            return URI.create("https://127.0.0.1:" + server.getAddress().getPort());
        }

        private synchronized void handle(HttpExchange exchange) throws IOException {
            try (exchange) {
                byte[] body = exchange.getRequestBody().readAllBytes();
                Map<String, String> headers = new HashMap<>();
                exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), v.get(0)));
                String path = exchange.getRequestURI().getRawPath();
                if (!path.equals(HttpSessions.PATH)) {
                    received.add(new Received(exchange.getRequestMethod(), path, headers, body, null, null));
                    JsonNode a = calls.poll();
                    if (a == null) {
                        beyondScript.add("a call to " + path);
                        send(exchange, 500, new byte[0]);
                        return;
                    }
                    send(exchange, a.get("status").asInt(), unhex(a.get("body")));
                    return;
                }
                SessionRequest req = SessionRequest.parse(body);
                boolean root = req.clientRoot() != null;
                String answer = root ? handshakes.poll() : replacement;
                if (answer == null) {
                    received.add(new Received("POST", path, headers, body, root, null));
                    beyondScript.add("a handshake");
                    send(exchange, 500, new byte[0]);
                    return;
                }
                if ("notFound".equals(answer)) {
                    received.add(new Received("POST", path, headers, body, root, null));
                    send(exchange, 404, new byte[0]);
                    return;
                }
                String nonce = Sessions.newNonce();
                String sess = Sessions.deriveSessionId(root ? req.clientRoot().sig() : null, psp.root().sig(),
                        req.nonce(), nonce, req.clientPolicyKey(), req.clientKeyring());
                SessionReply reply;
                if ("wrongKey".equals(answer)) {
                    reply = Sessions.signReply(new SessionReply(psp.root(), fx.publicKey("stranger-policy"),
                            psp.keyring().services(), null, null, null, nonce, sess, "attested", List.of(), null),
                            fx.privateKey("stranger-policy"));
                } else {
                    reply = Sessions.signReply(new SessionReply(psp.root(), psp.policyKey(), psp.keyring().services(),
                            psp.keyring().sig(), psp.keyring().notAfter(), psp.replyCert(), nonce, sess, answer,
                            answer.equals("unsafe") ? DISABLED : List.of(), null), fx.privateKey(psp.entry()));
                }
                received.add(new Received("POST", path, headers, body, root, sess));
                send(exchange, 200, utf8(reply.toJson()));
            }
        }

        private static void send(HttpExchange exchange, int status, byte[] body) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }

        /**
         * What it received, each call's session named by the position of the handshake whose reply issued it; fails
         * the case {@code name} when something came that the script had no answer for, or a boundary stamp's
         * signature does not verify.
         */
        synchronized ArrayNode received(String name) {
            assertEquals(List.of(), beyondScript, name + ": received beyond the partner's script");
            ArrayNode out = arr();
            for (Received r : received) {
                if (r.clientRoot() != null) {
                    out.add(handshakeReceived(r.clientRoot()));
                    continue;
                }
                ObjectNode call = obj();
                call.put("method", r.method());
                call.put("path", r.path());
                call.put("body", hex(r.body()));
                index(call, "session", r.headers().get(PaztportHeaders.SESSION.toLowerCase()));
                String chain = r.headers().get(PaztportHeaders.CHAIN.toLowerCase());
                if (chain == null) {
                    call.putNull("stamps");
                    call.putNull("stampSession");
                } else {
                    ArrayNode stamps = (ArrayNode) tree(HttpWire.decodeChain(chain));
                    VectorsHttpRules.stamps(stamps).forEach(s -> assertTrue(signedBySvc(s),
                            name + ": a boundary stamp's signature does not verify under " + s.svc() + "'s key"));
                    String made = stamps.get(0).get("sess").asText();
                    stamps.forEach(s -> ((ObjectNode) s).remove(List.of("sess", "sig")));
                    call.set("stamps", stamps);
                    index(call, "stampSession", made);
                }
                String proof = r.headers().get(PaztportHeaders.PROOF.toLowerCase());
                call.set("proof", proof == null ? NullNode.instance : tree(HttpWire.decodeProof(proof)));
                String influence = r.headers().get(PaztportHeaders.INFLUENCE.toLowerCase());
                call.set("influence", influence == null ? NullNode.instance : tree(HttpWire.decodeInfluence(influence)));
                ObjectNode o = obj();
                o.set("call", call);
                out.add(o);
            }
            return out;
        }

        /** Whether {@code stamp}'s signature, over its own fields, verifies under its signer's key in the keyring. */
        private boolean signedBySvc(Stamp stamp) {
            String key = egressKeyring.services().get(stamp.svc());
            try {
                return key != null && Crypto.verify(Crypto.decodePublicKey(Base64Url.decode(key)),
                        stamp.signingBytes(), Base64Url.decode(stamp.sig()));
            } catch (IllegalArgumentException e) {
                return false;
            }
        }

        /** The position of the handshake whose reply issued {@code sess}, or null when none did. */
        private void index(ObjectNode o, String name, String sess) {
            for (int i = 0; i < received.size(); i++) {
                if (sess != null && sess.equals(received.get(i).issued())) {
                    o.put(name, i);
                    return;
                }
            }
            o.putNull(name);
        }

        @Override
        public void close() {
            server.stop(0);
            executor.shutdownNow();
        }
    }

    // --- Building and replaying ---

    static void assertAll(JsonNode rules, Fixtures fx) {
        for (String kind : List.of("sessionHeader", "sessionRegistry", "handshakeErrors", "sessionExpiry",
                "boundaryRefusals")) {
            for (JsonNode c : rules.get(kind)) {
                ArrayNode actual = runScript(c, fx);
                JsonNode steps = c.get("steps");
                assertEquals(steps.size(), actual.size(), kind + ": " + c.get("name").asText());
                for (int i = 0; i < steps.size(); i++) {
                    assertEquals(steps.get(i).get("expected"), actual.get(i),
                            kind + ": " + c.get("name").asText() + ", step " + i);
                }
            }
        }
        for (JsonNode c : rules.get("egress")) {
            assertEquals(c.get("expected"), runEgress(c, fx), "egress: " + c.get("name").asText());
        }
    }
}
