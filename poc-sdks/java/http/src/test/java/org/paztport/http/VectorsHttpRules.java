// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.paztport.core.Vectors;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleLeaf;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.MerkleTree;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;

/**
 * Builds and replays the {@code rules} section of {@code spec/vectors/http-v3.json}: the HTTP rules the spec requires
 * of a receiver, a caller, a partner and an egress, each case an input and the answer the spec gives for it. A case
 * is replayed through the framework-neutral functions a binding adapts ({@link HttpReceiver} and
 * {@link PartnerReceiver} entered through {@link RequestContext#accept}, {@link HttpCaller#stamp} and
 * {@link HttpCaller#check}, {@link HttpSessions#serve}, {@link PeerCert#of}, {@link UnsafeEndpoints} and
 * {@link BoundaryClient}), so the file holds nothing a framework decides. The partner and egress kinds are
 * {@link VectorsHttpPartner}'s.
 *
 * <p>Every expected answer here is written by hand from the spec, not taken from a run: {@link #assertAll} replays
 * each case and compares, so an export fails rather than record what the code happens to do. The one exception is
 * what an egress sends, whose blinded entries and stamp commitment are computed with {@code BoundaryInfluence.reduce}
 * and {@code Influence.commit}: those primitives are pinned on their own, by {@code boundaryInfluence} here and by
 * {@code influence} in {@code v3.json}.
 */
final class VectorsHttpRules {

    static final long NOW = 1_767_225_600_000L;
    /** The fixture material's window: 2100-01-01. */
    static final long NOT_AFTER = 4_102_444_800_000L;
    /** The window of the material that expires during a case: a minute after {@link #NOW}. */
    static final long EXPIRES = NOW + 60_000;
    static final long GATEWAY_TS = NOW - 1_500;
    static final long ORDERS_TS = NOW - 500;
    static final long RESPONSE_TS = NOW - 200;
    static final String RID = "rid-rules-1";
    static final String MESH_ROUTE = "gateway/orders/payment";
    static final String BOUNDARY_ROUTE = "payment/psp";
    static final byte[] PAY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    static final byte[] PAID = "{\"paid\":true}".getBytes(StandardCharsets.UTF_8);

    /** Private data of alice's and a public page: shaped only by trusted content. */
    static final List<InfluenceEntry> OWNED = Influence.normalise(List.of(
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-1", "cid-order-1", "alice"),
            new InfluenceEntry(InfluenceClass.PUBLIC, "http:catalogue", "h-catalogue-1", null, null)));
    /** A third-party ticket beside alice's order: steered by untrusted content. */
    static final List<InfluenceEntry> STEERED = Influence.normalise(List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "h-ticket-1", "cid-ticket-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-1", "cid-order-1", "alice")));

    private static final String ABOUT = "The HTTP rules the spec requires of a receiver, a caller, a partner and an"
            + " egress, each case an input and the answer the spec gives. A key is looked up by name here, then in"
            + " this file's top-level `keys`, then in v3.json; each new one is derived by v3.json's rule. A `material`"
            + " is one organisation's policy key (by name), its signed root and signed keyring, each with its"
            + " notAfter, the"
            + " proofs of its routes and, for a partner, its entry service and reply certificate. Each root's tree has"
            + " depth 1, its two routes filling both leaves with salts by v3.json's rule, so it has no padding; its"
            + " rootId is \"v\" and the first 12 hex digits of SHA-256(utf8(\"paztport-http-v3-vector-root:\" + tree)),"
            + " for the vectors only. A handshake request's nonce is the first 16 bytes (15 for `short-nonce`) of"
            + " SHA-256(utf8(\"paztport-http-v3-vector-nonce:\" + name)), base64url, and `handshakeBodies` holds each"
            + " request's JCS bytes, the body a step posts. Bodies and certificates are hex, and headers are their"
            + " values as sent. A receiver case enters `request` at `service` `uses` times"
            + " against one nonce cache that already holds `spent`, the handler then reads `read`, and `expected` is"
            + " the last entry's answer. A partner case runs `steps` in order against one partner whose clock reads"
            + " each step's `at`; a handshake's `as` names the session it opens, since the partner picks the id, and a"
            + " call's boundary stamp is signed as the step runs, in the session it names; a call may carry `read`,"
            + " what the handler reads once it is accepted. The spec's README says what each kind covers.";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private VectorsHttpRules() {
    }

    // --- JSON ---

    static ObjectNode obj() {
        return JsonNodeFactory.instance.objectNode();
    }

    static ArrayNode arr() {
        return JsonNodeFactory.instance.arrayNode();
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    static byte[] unhex(JsonNode n) {
        return HexFormat.of().parseHex(n.asText());
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * A value the SDK wrote as JSON text, as a tree to place in a vector, each object's members in the order the
     * vectors list them.
     */
    static JsonNode tree(String json) {
        try {
            return layout(MAPPER.readTree(json));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A kind of object, told by the members it always has, and the order a vector lists its members in. */
    private record Layout(Set<String> marker, List<String> order) {
    }

    private static final List<Layout> LAYOUTS = List.of(
            new Layout(Set.of("v", "svc", "rcv"),
                    List.of("v", "svc", "inst", "rid", "ts", "sess", "rcv", "bind", "infl", "prev", "sig")),
            new Layout(Set.of("leafSalt"), List.of("leafSalt", "siblings", "dirs", "rootId")),
            new Layout(Set.of("root", "rootId"), List.of("rootId", "root", "sig", "notAfter")),
            new Layout(Set.of("services", "policy"), List.of("services", "policy", "sig", "notAfter")),
            new Layout(Set.of("policy", "svc", "key"), List.of("policy", "svc", "key", "notAfter", "sig")),
            new Layout(Set.of("cls", "src", "h"), List.of("cls", "src", "h", "cid", "owner")),
            new Layout(Set.of("cls", "cid"), List.of("cls", "cid", "owner")),
            new Layout(Set.of("cls", "salt", "originals"), List.of("cls", "owner", "salt", "originals")),
            new Layout(Set.of("clientPolicyKey"), List.of("clientRoot", "clientPolicyKey", "clientKeyring",
                    "clientKeyringSig", "clientKeyringNotAfter", "nonce")));

    /** {@code n} with the members of every object in the order its kind's layout gives; other objects keep theirs. */
    private static JsonNode layout(JsonNode n) {
        if (n.isArray()) {
            ArrayNode a = arr();
            n.forEach(item -> a.add(layout(item)));
            return a;
        } else if (!n.isObject()) {
            return n;
        }
        List<String> names = new ArrayList<>();
        n.fieldNames().forEachRemaining(names::add);
        List<String> order = LAYOUTS.stream()
                .filter(l -> names.containsAll(l.marker()) && l.order().containsAll(names))
                .map(Layout::order).findFirst().orElse(names);
        ObjectNode o = obj();
        for (String name : order) {
            if (n.has(name)) {
                o.set(name, layout(n.get(name)));
            }
        }
        return o;
    }

    static JsonNode entries(List<InfluenceEntry> entries) {
        return tree(Influence.toJson(entries));
    }

    static List<InfluenceEntry> entries(JsonNode n) {
        return Influence.parse(Vectors.text(n));
    }

    static ArrayNode texts(String... values) {
        ArrayNode a = arr();
        for (String v : values) {
            a.add(v);
        }
        return a;
    }

    static Set<String> textSet(JsonNode n) {
        Set<String> out = new LinkedHashSet<>();
        n.forEach(v -> out.add(v.asText()));
        return out;
    }

    static List<String> textList(JsonNode n) {
        List<String> out = new ArrayList<>();
        n.forEach(v -> out.add(v.asText()));
        return out;
    }

    static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    // --- Fixtures ---

    /** An organisation's signed material, read back from the file. */
    record Material(String policyKey, SignedRoot root, KeyringFile keyring,
            Map<String, MerkleProof> proofs, String entry, ReplyCert replyCert) {

        ProofBundle bundle(String service) {
            return new ProofBundle(service, root.rootId(), proofs);
        }

        String proofHeader(String route) {
            return HttpWire.encodeProof(proofs.get(route));
        }
    }

    /** The keys and material a case names, found in {@code rules}, then {@code http}, then {@code core}. */
    static final class Fixtures {

        final JsonNode rules;
        final JsonNode http;
        final JsonNode core;

        Fixtures(JsonNode rules, JsonNode http, JsonNode core) {
            this.rules = rules;
            this.http = http;
            this.core = core;
        }

        private JsonNode key(String name) {
            for (JsonNode keys : List.of(rules.get("keys"), http.get("keys"), core.get("keys"))) {
                if (keys.has(name)) {
                    return keys.get(name);
                }
            }
            throw new IllegalArgumentException("no key " + name);
        }

        PrivateKey privateKey(String name) {
            return Crypto.decodePrivateKey(Base64Url.decode(key(name).get("priv").asText()));
        }

        String publicKey(String name) {
            return key(name).get("pub").asText();
        }

        Material material(String name) {
            JsonNode m = rules.get("material").get(name);
            Map<String, MerkleProof> proofs = new LinkedHashMap<>();
            m.get("proofs").properties()
                    .forEach(e -> proofs.put(e.getKey(), MerkleProof.parse(Vectors.text(e.getValue()))));
            return new Material(publicKey(m.get("policyKey").asText()), SignedRoot.parse(Vectors.text(m.get("root"))),
                    KeyringFile.parse(Vectors.text(m.get("keyring"))), proofs,
                    m.has("entry") ? m.get("entry").asText() : null,
                    m.has("replyCert") ? ReplyCert.parse(Vectors.text(m.get("replyCert"))) : null);
        }

        /** A named handshake request's body: its JCS bytes. */
        byte[] handshake(String name) {
            return unhex(rules.get("handshakeBodies").get(name));
        }

        /** The peer a named client certificate gives, connected from its address; null names no certificate. */
        PeerCert peer(JsonNode name) {
            if (name.isNull()) {
                return null;
            }
            JsonNode p = rules.get("peers").get(name.asText());
            return PeerCert.of(x509(unhex(p.get("certificate")), name.asText()), p.get("remoteAddr").asText());
        }
    }

    /**
     * {@code o} with its member {@code field}, an object of names, in name order: core holds such a map unordered,
     * and the signatures over it are over JCS, so the file can list it in an order of its own that every run keeps.
     */
    private static JsonNode sorted(JsonNode o, String field) {
        Map<String, JsonNode> byName = new TreeMap<>();
        o.get(field).properties().forEach(e -> byName.put(e.getKey(), e.getValue()));
        ObjectNode sorted = obj();
        byName.forEach(sorted::set);
        ((ObjectNode) o).set(field, sorted);
        return o;
    }

    /** A handshake request as the SDK writes it, its keyring in name order. */
    private static JsonNode request(SessionRequest req) {
        return sorted(tree(req.toJson()), "clientKeyring");
    }

    /** {@code section} read back from its own text, as a replay reads it, so core reads each value as written. */
    private static JsonNode reread(JsonNode section) {
        try {
            return Vectors.read(section.toString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** {@code "v"} and 12 hex digits, derived from the material's name for the vectors only. */
    private static String rootId(String name) {
        return "v" + hex(Crypto.sha256(utf8("paztport-http-v3-vector-root:" + name))).substring(0, 12);
    }

    /** Two routes at depth 1 fill both leaves, so the tree needs no random padding. */
    private static MerkleTree tree(String name, List<String> routes) {
        List<MerkleLeaf> leaves = routes.stream()
                .map(r -> new MerkleLeaf(Arrays.copyOf(Crypto.sha256(utf8("paztport-v3-vector-salt:" + r)),
                        MerkleProof.SALT_BYTES), r))
                .toList();
        return MerkleTree.build(leaves, 1, rootId(name));
    }

    private static ObjectNode material(String treeName, List<String> routes, String policyName, KeyPair policy,
            Map<String, String> services, long notAfter) {
        MerkleTree t = tree(treeName, routes);
        ObjectNode m = obj();
        m.put("policyKey", policyName);
        m.set("root", tree(SignedRoot.sign(t.root(), t.rootId(), notAfter, policy.getPrivate()).toJson()));
        m.set("keyring", sorted(tree(KeyringFile.sign(services, pub(policy), notAfter, policy.getPrivate()).toJson()),
                "services"));
        ObjectNode proofs = m.putObject("proofs");
        routes.forEach(r -> proofs.set(r, tree(t.proofFor(r).toJson())));
        return m;
    }

    private static ObjectNode partnerMaterial(KeyPair policy, KeyPair entry, long notAfter) {
        Map<String, String> services = new TreeMap<>(Map.of("psp", pub(entry)));
        ObjectNode m = material("psp", List.of("psp/ledger", "psp/refunds"), "psp-policy", policy, services, notAfter);
        m.put("entry", "psp");
        m.set("replyCert", tree(ReplyCert.issue(pub(policy), "psp", pub(entry), NOT_AFTER, policy.getPrivate())
                .toJson()));
        return m;
    }

    /** The first {@code bytes} bytes of a hash of {@code name}, base64url: a handshake nonce kept from run to run. */
    static String nonce(String name, int bytes) {
        return Base64Url.encode(Arrays.copyOf(Crypto.sha256(utf8("paztport-http-v3-vector-nonce:" + name)), bytes));
    }

    /** Builds the section; {@code http} supplies the top-level keys, {@code core} the rest. */
    static ObjectNode build(JsonNode http, JsonNode core) {
        ObjectNode rules = obj();
        rules.put("about", ABOUT);
        ObjectNode keys = rules.putObject("keys");
        Map<String, KeyPair> made = new LinkedHashMap<>();
        for (String name : List.of("shop-policy", "psp-policy", "psp", "stranger-policy", "shop-ca")) {
            KeyPair k = VectorsHttpV3Export.derive(name);
            made.put(name, k);
            ObjectNode o = keys.putObject(name);
            o.put("pub", pub(k));
            o.put("priv", Base64Url.encode(Crypto.encodePrivateKey(k.getPrivate())));
        }
        Fixtures base = new Fixtures(rules, http, core);
        Map<String, String> shopServices = new TreeMap<>();
        for (String svc : List.of("gateway", "orders", "payment")) {
            shopServices.put(svc, base.publicKey(svc));
        }
        ObjectNode material = rules.putObject("material");
        List<String> shopRoutes = List.of(MESH_ROUTE, BOUNDARY_ROUTE);
        material.set("shop", material("shop", shopRoutes, "shop-policy", made.get("shop-policy"), shopServices,
                NOT_AFTER));
        material.set("shop-expiring", material("shop", shopRoutes, "shop-policy", made.get("shop-policy"),
                shopServices, EXPIRES));
        material.set("psp", partnerMaterial(made.get("psp-policy"), made.get("psp"), NOT_AFTER));
        material.set("psp-expiring", partnerMaterial(made.get("psp-policy"), made.get("psp"), EXPIRES));
        rules.set("handshakes", handshakes(new Fixtures(reread(rules), http, core)));
        rules.set("handshakeBodies", handshakeBodies(rules.get("handshakes")));
        rules.set("peers", peers(made.get("shop-ca")));
        // The cases are built from the fixtures as the file holds them, as a replay reads them.
        Fixtures fx = new Fixtures(reread(rules), http, core);

        Chains chains = new Chains(fx);
        rules.set("requests", requests(chains));
        rules.set("unreadableInfluence", unreadableInfluence(chains));
        rules.set("attestation", attestation(chains));
        rules.set("peerCertificates", peerCertificates(made.get("shop-ca")));
        rules.set("sessionHeader", VectorsHttpPartner.sessionHeader(fx));
        rules.set("sessionRegistry", VectorsHttpPartner.sessionRegistry(fx));
        rules.set("unsafeEndpoints", unsafeEndpoints());
        rules.set("handshakeErrors", VectorsHttpPartner.handshakeErrors(fx));
        rules.set("egress", VectorsHttpPartner.egress(fx, chains));
        rules.set("callerInfluence", callerInfluence(chains));
        rules.set("sessionExpiry", VectorsHttpPartner.sessionExpiry(fx));
        rules.set("refusals", refusals(chains));
        rules.set("boundaryRefusals", VectorsHttpPartner.boundaryRefusals(fx));
        rules.set("trustedRecord", trustedRecord(chains));
        rules.set("partnerTrustedRecord", VectorsHttpPartner.partnerTrustedRecord(fx));
        return rules;
    }

    private static ObjectNode handshakes(Fixtures fx) {
        Material shop = fx.material("shop");
        Material expiring = fx.material("shop-expiring");
        ObjectNode h = obj();
        h.set("shop", request(SessionRequest.of(shop.root(), shop.policyKey(), shop.keyring(), nonce("shop", 16))));
        h.set("shop-expiring", request(SessionRequest.of(expiring.root(), expiring.policyKey(), expiring.keyring(),
                nonce("shop-expiring", 16))));
        h.set("no-root", request(SessionRequest.of(null, shop.policyKey(), shop.keyring(), nonce("no-root", 16))));
        h.set("short-nonce", request(SessionRequest.of(shop.root(), shop.policyKey(), shop.keyring(),
                nonce("short-nonce", 15))));
        SignedRoot r = shop.root();
        String shortSig = Base64Url.encode(Arrays.copyOf(Base64Url.decode(r.sig()), 63));
        h.set("short-root-sig", request(SessionRequest.of(new SignedRoot(r.rootId(), r.root(), shortSig, r.notAfter()),
                shop.policyKey(), shop.keyring(), nonce("short-root-sig", 16))));
        return h;
    }

    /** Each handshake request's body: the hex of its JCS bytes. */
    private static ObjectNode handshakeBodies(JsonNode handshakes) {
        ObjectNode bodies = obj();
        handshakes.properties().forEach(e -> bodies.put(e.getKey(), hex(utf8(Vectors.text(e.getValue())))));
        return bodies;
    }

    // --- Chains a receiver is sent ---

    /** The request chains the receiver cases send to {@code payment}, stamped once with fixed clocks. */
    static final class Chains {

        final Fixtures fx;
        final Material shop;
        final List<Stamp> toOrders;
        /** gateway, orders, payment, committing to no influence. */
        final List<Stamp> clean;
        /** The same, committing to {@link #OWNED}. */
        final List<Stamp> owned;
        /** The same, committing to {@link #STEERED}. */
        final List<Stamp> steered;
        /** orders' stamp signed with the gateway's key. */
        final List<Stamp> forged;
        /** One origin stamp from the gateway straight to payment, a route the policy does not hold. */
        final List<Stamp> direct;
        /** orders' stamp signed with the gateway's key, committing to {@link #STEERED}. */
        final List<Stamp> forgedSteered;
        /** One gateway stamp to payment with an empty signature. */
        final List<Stamp> unsigned;

        Chains(Fixtures fx) {
            this.fx = fx;
            this.shop = fx.material("shop");
            Stamper gateway = new Stamper("gateway", "gw-1", fx.privateKey("gateway"), true, () -> RID,
                    () -> GATEWAY_TS);
            this.toOrders = gateway.next(List.of(), "orders", "bind-gateway-to-orders", List.of(), null).chain();
            Stamper orders = new Stamper("orders", "ord-1", fx.privateKey("orders"), false, () -> RID,
                    () -> ORDERS_TS);
            String bind = RequestBinding.compute("POST", "/pay", PAY);
            this.clean = orders.next(toOrders, "payment", bind, List.of(), null).chain();
            this.owned = orders.next(toOrders, "payment", bind, OWNED, null).chain();
            this.steered = orders.next(toOrders, "payment", bind, STEERED, null).chain();
            this.forged = new Stamper("orders", "ord-1", fx.privateKey("gateway"), false, () -> RID,
                    () -> ORDERS_TS).next(toOrders, "payment", bind, List.of(), null).chain();
            this.forgedSteered = new Stamper("orders", "ord-1", fx.privateKey("gateway"), false, () -> RID,
                    () -> ORDERS_TS).next(toOrders, "payment", bind, STEERED, null).chain();
            this.direct = new Stamper("gateway", "gw-1", fx.privateKey("gateway"), true, () -> RID,
                    () -> ORDERS_TS).next(List.of(), "payment", bind, List.of(), null).chain();
            this.unsigned = List.of(new Stamp("gateway", "gw-1", RID, ORDERS_TS, "", "payment", bind, "", "", ""));
        }

        /** {@code POST /pay} with the chain, the mesh route's proof and the influence it commits to, when any. */
        ObjectNode request(List<Stamp> chain, List<InfluenceEntry> influence) {
            ObjectNode headers = obj();
            headers.put(PaztportHeaders.CHAIN, HttpWire.encodeChain(chain));
            headers.put(PaztportHeaders.PROOF, shop.proofHeader(MESH_ROUTE));
            String influenceHeader = HttpWire.encodeInfluence(influence);
            if (influenceHeader != null) {
                headers.put(PaztportHeaders.INFLUENCE, influenceHeader);
            }
            return request(headers, PAY);
        }

        static ObjectNode request(ObjectNode headers, byte[] body) {
            ObjectNode r = obj();
            r.put("method", "POST");
            r.put("target", "/pay");
            r.set("headers", headers);
            r.put("body", hex(body));
            return r;
        }
    }

    // --- Receiver cases ---

    /**
     * What the service receiving a case is. Every one holds its stamp key, and verifies requests exactly when the
     * case gives it a mode.
     */
    record Service(String svc, String inst, boolean origin, boolean verifier) {

        static final Service PAYMENT = new Service("payment", "pay-1", false, true);
        static final Service NO_VERIFIER = new Service("payment", "pay-1", false, false);
        static final Service ORIGIN = new Service("gateway", "gw-1", true, true);

        ObjectNode json() {
            ObjectNode s = obj();
            s.put("svc", svc);
            s.put("inst", inst);
            s.put("origin", origin);
            s.put("verifier", verifier);
            return s;
        }
    }

    /** A receiver case's inputs, with the mesh defaults: no peer, no spent keys, one use and nothing read. */
    static ObjectNode receiverCase(String name, Service service, String mode, JsonNode request) {
        ObjectNode c = obj();
        c.put("name", name);
        c.put("material", "shop");
        c.set("service", service.json());
        c.set("allowedOrigins", texts("gateway"));
        if (mode == null) {
            c.putNull("mode");
        } else {
            c.put("mode", mode);
        }
        c.set("request", request);
        c.putNull("peer");
        c.put("now", NOW);
        c.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfig.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        c.set("spent", arr());
        c.put("uses", 1);
        c.set("read", arr());
        return c;
    }

    static ObjectNode served(boolean verified, List<InfluenceEntry> influence, boolean attests, boolean trusted) {
        ObjectNode e = obj();
        e.putNull("refusal");
        e.put("verified", verified);
        e.set("influence", entries(influence));
        e.put("attests", attests);
        e.put("trustedRecord", trusted);
        return e;
    }

    /** A refusal: the status and exactly {@code {"reason":"<code>"}}, with no whitespace and no other member. */
    static ObjectNode refusal(int status, ReasonCode reason) {
        ObjectNode r = obj();
        r.put("status", status);
        r.put("body", hex(utf8("{\"reason\":\"" + reason.name() + "\"}")));
        return r;
    }

    static ObjectNode refused(int status, ReasonCode reason) {
        ObjectNode e = obj();
        e.set("refusal", refusal(status, reason));
        e.put("verified", false);
        e.set("influence", arr());
        e.put("attests", false);
        e.put("trustedRecord", false);
        return e;
    }

    private static ObjectNode expect(ObjectNode c, ObjectNode expected) {
        c.set("expected", expected);
        return c;
    }

    private static ObjectNode headers(String chain, String proof, String influence) {
        ObjectNode h = obj();
        if (chain != null) {
            h.put(PaztportHeaders.CHAIN, chain);
        }
        if (proof != null) {
            h.put(PaztportHeaders.PROOF, proof);
        }
        if (influence != null) {
            h.put(PaztportHeaders.INFLUENCE, influence);
        }
        return h;
    }

    private static String b64(String text) {
        return Base64Url.encode(utf8(text));
    }

    /** verification.md, a request at the receiver: the nonce key and how each unreadable header is read. */
    private static ArrayNode requests(Chains ch) {
        String chain = HttpWire.encodeChain(ch.clean);
        String proof = ch.shop.proofHeader(MESH_ROUTE);
        ArrayNode a = arr();
        a.add(expect(receiverCase("verified", Service.PAYMENT, "enforce", ch.request(ch.clean, List.of())),
                served(true, List.of(), true, true)));
        a.add(expect(receiverCase("verified, with the influence the stamp commits to", Service.PAYMENT, "enforce",
                ch.request(ch.owned, OWNED)), served(true, OWNED, true, true)));
        ObjectNode twice = receiverCase("the same request twice", Service.PAYMENT, "enforce",
                ch.request(ch.clean, List.of()));
        twice.put("uses", 2);
        a.add(expect(twice, refused(403, ReasonCode.REPLAY)));
        ObjectNode spent = receiverCase("its nonce key <rid>|<last svc>|<last rcv>|req already spent",
                Service.PAYMENT, "enforce", ch.request(ch.clean, List.of()));
        spent.set("spent", texts(RID + "|orders|payment|req"));
        a.add(expect(spent, refused(403, ReasonCode.REPLAY)));
        ObjectNode others = receiverCase("other directions', hops' and operations' keys are not its own",
                Service.PAYMENT, "enforce", ch.request(ch.clean, List.of()));
        others.set("spent", texts(RID + "|orders|resp", RID + "|payment|req", RID + "|gateway|req", RID + "|orders",
                RID + "|orders|local", RID + "|orders|payment#pay|req", RID + "|orders|req"));
        a.add(expect(others, served(true, List.of(), true, true)));
        a.add(expect(receiverCase("no chain header", Service.PAYMENT, "enforce",
                Chains.request(headers(null, proof, null), PAY)), refused(403, ReasonCode.CHAIN_MISSING)));
        a.add(expect(receiverCase("a chain header that is not base64url", Service.PAYMENT, "enforce",
                Chains.request(headers("not*base64url", proof, null), PAY)), refused(403, ReasonCode.CHAIN_MISSING)));
        a.add(expect(receiverCase("a chain header that is not JSON", Service.PAYMENT, "enforce",
                Chains.request(headers(b64("not json"), proof, null), PAY)), refused(403, ReasonCode.CHAIN_MISSING)));
        a.add(expect(receiverCase("no proof header", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, null, null), PAY)), refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        a.add(expect(receiverCase("a proof header that is not base64url is no proof", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, "not*base64url", null), PAY)),
                refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        a.add(expect(receiverCase("a proof header that is not JSON is no proof", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, b64("{"), null), PAY)), refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        a.add(expect(receiverCase("an influence header that is not base64url", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, proof, "not*base64url"), PAY)),
                refused(403, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("no influence header where the stamp commits to some", Service.PAYMENT,
                "enforce", Chains.request(headers(HttpWire.encodeChain(ch.owned), proof, null), PAY)),
                refused(403, ReasonCode.INFLUENCE_MISMATCH)));
        return a;
    }

    /** verification.md: unreadable influence is never dropped, so it is answered 400 wherever nothing refused first. */
    private static ArrayNode unreadableInfluence(Chains ch) {
        String chain = HttpWire.encodeChain(ch.clean);
        String forged = HttpWire.encodeChain(ch.forged);
        String proof = ch.shop.proofHeader(MESH_ROUTE);
        String garbled = "not*base64url";
        ArrayNode a = arr();
        a.add(expect(receiverCase("enforce: check 9 refuses it", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, proof, garbled), PAY)), refused(403, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("enforce: an earlier check refuses first", Service.PAYMENT, "enforce",
                Chains.request(headers(forged, proof, garbled), PAY)), refused(403, ReasonCode.BAD_SIGNATURE)));
        a.add(expect(receiverCase("audit, on a chain that verifies otherwise", Service.PAYMENT, "audit",
                Chains.request(headers(chain, proof, garbled), PAY)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("audit, on a chain that fails", Service.PAYMENT, "audit",
                Chains.request(headers(forged, proof, garbled), PAY)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("audit: a JSON object, not a list", Service.PAYMENT, "audit",
                Chains.request(headers(chain, proof, b64("{\"cls\":\"private\",\"src\":\"s\",\"h\":\"h\"}")), PAY)),
                refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("audit: an entry with an empty owner", Service.PAYMENT, "audit",
                Chains.request(headers(chain, proof, b64("[{\"cls\":\"private\",\"src\":\"s\",\"h\":\"h\","
                        + "\"owner\":\"\"}]")), PAY)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("a service that verifies only to attest", Service.PAYMENT, null,
                Chains.request(headers(chain, proof, garbled), PAY)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("a service with no verifier", Service.NO_VERIFIER, null,
                Chains.request(headers(chain, proof, garbled), PAY)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("an origin carries none, so has none to drop", Service.ORIGIN, null,
                Chains.request(headers(chain, proof, garbled), PAY)), served(false, List.of(), false, false)));
        return a;
    }

    /** verification.md, who attests: only a chain that passed the live order at this service. */
    private static ArrayNode attestation(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("enforce, verified", Service.PAYMENT, "enforce", ch.request(ch.owned, OWNED)),
                served(true, OWNED, true, true)));
        a.add(expect(receiverCase("enforce, refused", Service.PAYMENT, "enforce", ch.request(ch.forged, List.of())),
                refused(403, ReasonCode.BAD_SIGNATURE)));
        a.add(expect(receiverCase("audit, verified", Service.PAYMENT, "audit", ch.request(ch.owned, OWNED)),
                served(true, OWNED, true, true)));
        a.add(expect(receiverCase("audit, failed: served with what came, unattested", Service.PAYMENT, "audit",
                ch.request(ch.forgedSteered, STEERED)), served(false, STEERED, false, false)));
        a.add(expect(receiverCase("no mode, verified for attestation alone", Service.PAYMENT, null,
                ch.request(ch.owned, OWNED)), served(true, OWNED, true, true)));
        a.add(expect(receiverCase("no mode, a forged chain: served, unattested", Service.PAYMENT, null,
                ch.request(ch.forged, List.of())), served(false, List.of(), false, false)));
        a.add(expect(receiverCase("no mode, a one-stamp chain with an empty signature", Service.PAYMENT, null,
                ch.request(ch.unsigned, List.of())), served(false, List.of(), false, false)));
        a.add(expect(receiverCase("no verifier: nothing to verify with, so never attests", Service.NO_VERIFIER, null,
                ch.request(ch.owned, OWNED)), served(false, OWNED, false, false)));
        a.add(expect(receiverCase("off: verifies and attests nothing", Service.PAYMENT, "off",
                ch.request(ch.clean, List.of())), served(false, List.of(), false, false)));
        a.add(expect(receiverCase("an origin never attests", Service.ORIGIN, null, ch.request(ch.owned, OWNED)),
                served(false, List.of(), false, false)));
        return a;
    }

    /** verification.md, what a refusal carries: the code, and no attribution even where the result names one. */
    private static ArrayNode refusals(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("a route not allowed names its last signer, but not to the caller",
                Service.PAYMENT, "enforce", Chains.request(headers(HttpWire.encodeChain(ch.direct), null, null), PAY)),
                refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        ObjectNode peer = receiverCase("a peer that is not the last signer is named, but not to the caller",
                Service.PAYMENT, "enforce", ch.request(ch.clean, List.of()));
        ObjectNode p = peer.putObject("peer");
        p.put("svc", "gateway");
        p.put("inst", "10.1.0.9");
        a.add(expect(peer, refused(403, ReasonCode.PEER_MISMATCH)));
        ObjectNode late = receiverCase("an expired chain", Service.PAYMENT, "enforce",
                ch.request(ch.clean, List.of()));
        late.put("now", NOW + 10_000);
        a.add(expect(late, refused(403, ReasonCode.EXPIRED)));
        ObjectNode altered = Chains.request(headers(HttpWire.encodeChain(ch.clean), ch.shop.proofHeader(MESH_ROUTE),
                null), utf8("{\"amount\":999}"));
        a.add(expect(receiverCase("a body altered in transit", Service.PAYMENT, "enforce", altered),
                refused(403, ReasonCode.BINDING_MISMATCH)));
        a.add(expect(receiverCase("unreadable influence in audit mode", Service.PAYMENT, "audit",
                Chains.request(headers(HttpWire.encodeChain(ch.clean), ch.shop.proofHeader(MESH_ROUTE),
                        "not*base64url"), PAY)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        return a;
    }

    /** sessions-and-influence.md, trusted records: a verified chain, and no untrusted content in what it holds. */
    private static ArrayNode trustedRecord(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("verified, no influence", Service.PAYMENT, "enforce",
                ch.request(ch.clean, List.of())), served(true, List.of(), true, true)));
        a.add(expect(receiverCase("verified, private and public with owners", Service.PAYMENT, "enforce",
                ch.request(ch.owned, OWNED)), served(true, OWNED, true, true)));
        a.add(expect(receiverCase("verified, third-party content", Service.PAYMENT, "enforce",
                ch.request(ch.steered, STEERED)), served(true, STEERED, true, false)));
        List<InfluenceEntry> untrusted = List.of(
                new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:search", "h-search-1", null, null));
        ObjectNode readUntrusted = receiverCase("verified, then a local-untrusted read", Service.PAYMENT,
                "enforce", ch.request(ch.owned, OWNED));
        readUntrusted.set("read", entries(untrusted));
        a.add(expect(readUntrusted, served(true, OWNED, true, false)));
        List<InfluenceEntry> card = List.of(
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:cards", "h-card-1", null, "bob"));
        ObjectNode readPrivate = receiverCase("verified, then a private read of someone else's", Service.PAYMENT,
                "enforce", ch.request(ch.owned, OWNED));
        readPrivate.set("read", entries(card));
        a.add(expect(readPrivate, served(true, OWNED, true, true)));
        a.add(expect(receiverCase("a chain that failed in audit mode", Service.PAYMENT, "audit",
                ch.request(ch.forged, List.of())), served(false, List.of(), false, false)));
        a.add(expect(receiverCase("refused", Service.PAYMENT, "enforce", ch.request(ch.forged, List.of())),
                refused(403, ReasonCode.BAD_SIGNATURE)));
        a.add(expect(receiverCase("a hop that is off", Service.PAYMENT, "off", ch.request(ch.clean, List.of())),
                served(false, List.of(), false, false)));
        a.add(expect(receiverCase("a service with no verifier", Service.NO_VERIFIER, null,
                ch.request(ch.clean, List.of())), served(false, List.of(), false, false)));
        a.add(expect(receiverCase("an origin", Service.ORIGIN, null, ch.request(ch.clean, List.of())),
                served(false, List.of(), false, false)));
        ObjectNode outside = receiverCase("work outside any request", Service.PAYMENT, "enforce", null);
        outside.putNull("request");
        a.add(expect(outside, served(false, List.of(), false, false)));
        return a;
    }

    /** Runs one receiver case and answers in the shape of its {@code expected}. */
    static ObjectNode runReceiver(JsonNode c, Fixtures fx) {
        HttpReceiver receiver = receiver(c, fx);
        String svc = c.get("service").get("svc").asText();
        JsonNode request = c.get("request");
        if (request.isNull()) {
            return answer(null, false, new PublicWrites(svc).shapedOnlyByTrusted());
        }
        Accepted last = null;
        boolean trusted = false;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            try (RequestContext.Entered<Accepted> entered = RequestContext.accept(receiver, inbound(request),
                    peer(c.get("peer")), mode(c.get("mode")))) {
                last = entered.result();
                if (last.refusal() == null) {
                    RequestContext.addInfluence(entries(c.get("read")).toArray(InfluenceEntry[]::new));
                }
                trusted = new PublicWrites(svc).shapedOnlyByTrusted();
            }
        }
        return answer(last, last.attests(), trusted);
    }

    private static ObjectNode answer(Accepted a, boolean attests, boolean trusted) {
        ObjectNode e = obj();
        if (a == null || a.refusal() == null) {
            e.putNull("refusal");
        } else {
            ObjectNode r = e.putObject("refusal");
            r.put("status", a.refusal().status());
            r.put("body", hex(a.refusal().json()));
        }
        e.put("verified", a != null && a.verifiedChain() != null);
        e.set("influence", entries(a == null ? List.of() : a.influence()));
        e.put("attests", attests);
        e.put("trustedRecord", trusted);
        return e;
    }

    /** The receiver a case names, its verifier pinned to the case's material over a cache holding {@code spent}. */
    static HttpReceiver receiver(JsonNode c, Fixtures fx) {
        JsonNode s = c.get("service");
        String svc = s.get("svc").asText();
        boolean origin = s.get("origin").asBoolean();
        long now = c.get("now").asLong();
        HttpReceiver.Builder b = HttpReceiver.builder(svc).origin(origin)
                .verifyRequests(!c.get("mode").isNull()).publisher(event -> { });
        if (s.get("verifier").asBoolean()) {
            Material m = fx.material(c.get("material").asText());
            InMemoryNonceCache nonces = new InMemoryNonceCache(c.get("nonceTtlMs").asLong());
            c.get("spent").forEach(k -> nonces.seenBefore(k.asText(), now));
            b.verifier(new Verifier(VerifierConfig.pinned(List.of(m.keyring()), List.of(m.root()), m.policyKey(),
                    now, textSet(c.get("allowedOrigins")), "", nonces, () -> now, c.get("callMaxAgeMs").asLong(),
                    c.get("runMaxAgeMs").asLong())));
        }
        return b.stamper(new Stamper(svc, s.get("inst").asText(), fx.privateKey(svc), origin, () -> "unused",
                () -> now)).build();
    }

    static InboundRequest inbound(JsonNode r) {
        Map<String, String> headers = new LinkedHashMap<>();
        r.get("headers").properties().forEach(e -> headers.put(e.getKey(), e.getValue().asText()));
        return new InboundRequest(r.get("method").asText(), r.get("target").asText(), headers, unhex(r.get("body")));
    }

    static Peer peer(JsonNode p) {
        return p.isNull() ? null : new Peer(p.get("svc").asText(), p.get("inst").asText());
    }

    /**
     * The case's {@code mode}: {@code enforce} or {@code audit}; {@code off}, a hop its deployment has switched off,
     * which verifies requests under no mode at all; or null, a service that does not verify requests. The receiver
     * is given both of the last two as {@code OFF}, the one value its API has for them.
     */
    static VerificationMode mode(JsonNode m) {
        return m.isNull() ? VerificationMode.OFF : VerificationMode.valueOf(m.asText().toUpperCase());
    }

    // --- The peer from a certificate ---

    private static final byte[] CN = {0x55, 0x04, 0x03};
    private static final byte[] O = {0x55, 0x04, 0x0A};
    private static final byte[] ED25519 = tlv(0x30, tlv(0x06, new byte[] {0x2B, 0x65, 0x70}));

    /** One DER element, its length in the shortest form. */
    private static byte[] tlv(int tag, byte[]... parts) {
        ByteArrayOutputStream contents = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            contents.writeBytes(p);
        }
        int n = contents.size();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (n < 0x80) {
            out.write(n);
        } else if (n < 0x100) {
            out.write(0x81);
            out.write(n);
        } else {
            out.write(0x82);
            out.write(n >> 8);
            out.write(n & 0xFF);
        }
        out.writeBytes(contents.toByteArray());
        return out.toByteArray();
    }

    private static byte[] attribute(byte[] type, int valueTag, byte[] value) {
        return tlv(0x30, tlv(0x06, type), tlv(valueTag, value));
    }

    private static byte[] rdn(byte[]... attributes) {
        return tlv(0x31, attributes);
    }

    private static byte[] name(byte[]... rdns) {
        return tlv(0x30, rdns);
    }

    /** {@code element}, whose length fits in one octet, with that length written in the long form instead. */
    private static byte[] longForm(byte[] element) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(element[0]);
        out.write(0x81);
        out.write(element.length - 2);
        out.write(element, 2, element.length - 2);
        return out.toByteArray();
    }

    /** {@code O=<organisation>} then {@code CN=<common name>}, which RFC 2253 writes the other way round. */
    private static byte[] organisation(String organisation, String commonName) {
        return name(rdn(attribute(O, 0x0C, utf8(organisation))), rdn(attribute(CN, 0x0C, utf8(commonName))));
    }

    private static byte[] certificate(KeyPair ca, boolean version, byte[] subject) {
        return certificate(ca, organisation("shop", "shop CA"), version, subject);
    }

    /**
     * A certificate from {@code issuer} for {@code subject}, both encoded exactly as given, signed with {@code ca}'s
     * Ed25519 key so that it is the same bytes on every run. No receiver rule checks the signature: the TLS layer has.
     */
    private static byte[] certificate(KeyPair ca, byte[] issuer, boolean version, byte[] subject) {
        byte[] validity = tlv(0x30, tlv(0x17, utf8("260101000000Z")), tlv(0x17, utf8("360101000000Z")));
        byte[] tbs = tlv(0x30, version ? tlv(0xA0, tlv(0x02, new byte[] {2})) : new byte[0],
                tlv(0x02, new byte[] {1}), ED25519, issuer, validity, subject, Crypto.encodePublicKey(ca.getPublic()));
        byte[] sig = Crypto.sign(ca.getPrivate(), tbs);
        byte[] bits = new byte[sig.length + 1];
        System.arraycopy(sig, 0, bits, 1, sig.length);
        return tlv(0x30, tbs, ED25519, tlv(0x03, bits));
    }

    private static ObjectNode certCase(String name, byte[] certificate, String remote, String svc) {
        ObjectNode c = obj();
        c.put("name", name);
        c.put("certificate", hex(certificate));
        c.put("remoteAddr", remote);
        ObjectNode e = c.putObject("expected");
        e.put("svc", svc);
        e.put("inst", remote);
        return c;
    }

    /** verification.md, the peer under mTLS: the subject's one common name, read from the signed bytes. */
    private static ArrayNode peerCertificates(KeyPair ca) {
        byte[] shop = rdn(attribute(O, 0x0C, utf8("shop")));
        byte[] orders = rdn(attribute(CN, 0x0C, utf8("orders")));
        ArrayNode a = arr();
        a.add(certCase("one common name, a UTF8String", certificate(ca, true, name(shop, orders)), "10.1.0.5",
                "orders"));
        a.add(certCase("one common name, a PrintableString", certificate(ca, true,
                name(rdn(attribute(CN, 0x13, utf8("orders"))))), "10.1.0.5", "orders"));
        a.add(certCase("read as it is, with no case folding", certificate(ca, true,
                name(rdn(attribute(CN, 0x0C, utf8("Orders"))))), "10.1.0.5", "Orders"));
        a.add(certCase("UTF-8 past ASCII", certificate(ca, true,
                name(rdn(attribute(CN, 0x0C, utf8("zahlung-ü"))))), "10.1.0.5", "zahlung-ü"));
        a.add(certCase("a certificate with no version field", certificate(ca, false, name(shop, orders)),
                "10.1.0.6", "orders"));
        a.add(certCase("no common name", certificate(ca, true, name(shop)), "10.1.0.7", ""));
        a.add(certCase("two equal common names in two RDNs", certificate(ca, true, name(orders, orders)),
                "10.1.0.7", ""));
        a.add(certCase("two equal common names in one RDN", certificate(ca, true,
                name(rdn(attribute(CN, 0x0C, utf8("orders")), attribute(CN, 0x0C, utf8("orders"))))), "10.1.0.7",
                ""));
        a.add(certCase("a second common name of another type still counts", certificate(ca, true,
                name(orders, rdn(attribute(CN, 0x16, utf8("orders"))))), "10.1.0.7", ""));
        a.add(certCase("a BMPString", certificate(ca, true, name(rdn(attribute(CN, 0x1E,
                "orders".getBytes(StandardCharsets.UTF_16BE))))), "10.1.0.7", ""));
        a.add(certCase("an IA5String", certificate(ca, true, name(rdn(attribute(CN, 0x16, utf8("orders"))))),
                "10.1.0.7", ""));
        a.add(certCase("a TeletexString", certificate(ca, true, name(rdn(attribute(CN, 0x14, utf8("orders"))))),
                "10.1.0.7", ""));
        a.add(certCase("a PrintableString holding a character it may not", certificate(ca, true,
                name(rdn(attribute(CN, 0x13, utf8("orders@shop"))))), "10.1.0.7", ""));
        a.add(certCase("a subject whose length is not in its shortest form", certificate(ca, true,
                longForm(name(orders))), "10.1.0.7", ""));
        a.add(certCase("an attribute's length not in its shortest form", certificate(ca, true,
                name(rdn(longForm(attribute(CN, 0x0C, utf8("orders")))))), "10.1.0.7", ""));
        return a;
    }

    /**
     * The client certificates the partner cases name. Replicas share one certificate; the others differ in the CA's
     * name or the service they name, or name none. None has an empty issuer: the JDK refuses to read such a
     * certificate, so a TLS layer built on it never hands one over.
     */
    private static ObjectNode peers(KeyPair ca) {
        byte[] payment = organisation("shop", "payment");
        ObjectNode p = obj();
        peer(p, "shop", certificate(ca, true, payment), "10.1.0.5");
        peer(p, "shop-replica", certificate(ca, true, payment), "10.1.0.6");
        peer(p, "shop-other-ca", certificate(ca, organisation("elsewhere", "other CA"), true, payment), "10.1.0.7");
        peer(p, "clinic", certificate(ca, organisation("clinic", "clinic CA"), true,
                organisation("clinic", "intake")), "10.2.0.5");
        peer(p, "unnamed", certificate(ca, true, name(rdn(attribute(O, 0x0C, utf8("shop"))))), "10.1.0.8");
        return p;
    }

    private static void peer(ObjectNode peers, String name, byte[] certificate, String remoteAddr) {
        ObjectNode o = peers.putObject(name);
        o.put("certificate", hex(certificate));
        o.put("remoteAddr", remoteAddr);
    }

    /** {@code der} as the JDK reads a certificate, which is how a TLS layer hands one over. */
    static X509Certificate x509(byte[] der, String name) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(name + ": the JDK does not read the certificate", e);
        }
    }

    static ObjectNode runCertificate(JsonNode c) {
        PeerCert peer = PeerCert.of(x509(unhex(c.get("certificate")), c.get("name").asText()),
                c.get("remoteAddr").asText());
        ObjectNode e = obj();
        e.put("svc", peer.peer().svc());
        e.put("inst", peer.peer().inst());
        return e;
    }

    // --- Unsafe endpoints ---

    private static ObjectNode endpointCase(List<String> disabled, String method, String pattern, boolean refused) {
        ObjectNode c = obj();
        c.put("name", method + " " + pattern);
        c.set("disabled", texts(disabled.toArray(String[]::new)));
        c.put("method", method);
        c.put("routePattern", pattern);
        c.put("refused", refused);
        return c;
    }

    /** sessions-and-influence.md, over HTTP: an endpoint is the method and the dispatched handler's pattern. */
    private static ArrayNode unsafeEndpoints() {
        List<String> disabled = List.of("POST /refund", "GET /statements/{id}");
        ArrayNode a = arr();
        a.add(endpointCase(disabled, "POST", "/refund", true));
        a.add(endpointCase(disabled, "GET", "/refund", false));
        a.add(endpointCase(disabled, "HEAD", "/refund", false));
        a.add(endpointCase(disabled, "POST", "/refund/{id}", false));
        a.add(endpointCase(disabled, "GET", "/statements/{id}", true));
        a.add(endpointCase(disabled, "HEAD", "/statements/{id}", true));
        a.add(endpointCase(disabled, "POST", "/statements/{id}", false));
        a.add(endpointCase(disabled, "GET", "/statements", false));
        return a;
    }

    // --- The caller's influence ---

    /** A caller case's inputs: orders calls payment after the gateway's stamp, with what it has read so far. */
    private static ObjectNode callerCase(String name, boolean verifier, Map<String, String> receivers, String uri,
            int status, String header, byte[] body, Chains ch) {
        ObjectNode c = obj();
        c.put("name", name);
        c.put("material", "shop");
        ObjectNode caller = c.putObject("caller");
        caller.put("svc", "orders");
        caller.put("inst", "ord-1");
        caller.put("verifier", verifier);
        ObjectNode map = caller.putObject("receivers");
        receivers.forEach(map::put);
        c.set("allowedOrigins", texts("gateway"));
        c.put("ts", ORDERS_TS);
        c.set("inbound", stamps(ch.toOrders));
        c.set("influence", entries(OWNED));
        ObjectNode call = c.putObject("call");
        call.put("method", "POST");
        call.put("uri", uri);
        call.put("body", hex(PAY));
        ObjectNode response = c.putObject("response");
        response.put("status", status);
        if (header == null) {
            response.putNull("header");
        } else {
            response.put("header", header);
        }
        response.put("body", hex(body));
        c.put("now", NOW);
        c.put("callMaxAgeMs", VerifierConfig.CALL_MAX_AGE_MS);
        c.put("runMaxAgeMs", VerifierConfig.RUN_MAX_AGE_MS);
        c.put("nonceTtlMs", VerifierConfig.NONCE_TTL_MS);
        return c;
    }

    static ArrayNode stamps(List<Stamp> chain) {
        ArrayNode a = arr();
        chain.forEach(s -> a.add(tree(s.toJson())));
        return a;
    }

    static List<Stamp> stamps(JsonNode a) {
        List<Stamp> out = new ArrayList<>();
        a.forEach(s -> out.add(new Stamp(s.get("svc").asText(), s.get("inst").asText(), s.get("rid").asText(),
                s.get("ts").asLong(), s.get("sess").asText(), s.get("rcv").asText(), s.get("bind").asText(),
                s.get("infl").asText(), s.get("prev").asText(), s.get("sig").asText())));
        return out;
    }

    private static ObjectNode callerExpected(String reason, List<InfluenceEntry> influence) {
        ObjectNode e = obj();
        e.put("rcv", "payment");
        if (reason == null) {
            e.putNull("reason");
        } else {
            e.put("reason", reason);
        }
        e.set("influence", entries(influence));
        return e;
    }

    /** payment's attestation of {@code status} and {@code body} with {@code labels}, over what orders sent. */
    private static String attestation(Chains ch, int status, byte[] body, List<ContentLabel> labels) {
        List<Stamp> sent = new Stamper("orders", "ord-1", ch.fx.privateKey("orders"), false, () -> RID,
                () -> ORDERS_TS).next(ch.toOrders, "payment", RequestBinding.compute("POST", "/pay", PAY), OWNED,
                null).chain();
        Stamp stamp = new Stamper("payment", "pay-1", ch.fx.privateKey("payment"), false, () -> RID,
                () -> RESPONSE_TS).respond(sent, HttpWire.resultHash(status, body), RID, labels);
        return HttpWire.encodeResponse(stamp, labels);
    }

    /** verification.md, a response at the caller: what a response adds to the request's influence. */
    private static ArrayNode callerInfluence(Chains ch) {
        List<ContentLabel> labels = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-receipt-1", "alice"),
                new ContentLabel(InfluenceClass.PUBLIC, "cid-terms-1", null));
        String ok = attestation(ch, 200, PAID, labels);
        String okHash = HttpWire.resultHash(200, PAID);
        String uri = "https://payment/pay";
        List<InfluenceEntry> labelled = List.of(
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:payment", okHash, "cid-receipt-1", "alice"),
                new InfluenceEntry(InfluenceClass.PUBLIC, "http:payment", okHash, "cid-terms-1", null));
        ArrayNode a = arr();
        a.add(callerCase("each label becomes an entry", true, Map.of(), uri, 200, ok, PAID, ch)
                .set("expected", callerExpected("OK", labelled)));
        a.add(callerCase("the receiver's policy name, by configuration", true, Map.of("pay.internal", "payment"),
                "https://pay.internal:8443/pay", 200, ok, PAID, ch).set("expected", callerExpected("OK", labelled)));
        a.add(callerCase("verified with no labels adds nothing", true, Map.of(), uri, 200,
                attestation(ch, 200, PAID, List.of()), PAID, ch).set("expected", callerExpected("OK", List.of())));
        a.add(callerCase("unattested", true, Map.of(), uri, 200, null, PAID, ch).set("expected",
                callerExpected("CHAIN_MISSING", List.of(untrusted(okHash)))));
        String hash500 = HttpWire.resultHash(500, PAID);
        a.add(callerCase("failing: the attestation is for another status", true, Map.of(), uri, 500, ok, PAID, ch)
                .set("expected", callerExpected("BINDING_MISMATCH", List.of(untrusted(hash500)))));
        byte[] refusalBody = utf8("{\"reason\":\"BAD_SIGNATURE\"}");
        a.add(callerCase("a refusal", true, Map.of(), uri, 403, null, refusalBody, ch).set("expected",
                callerExpected("CHAIN_MISSING", List.of(untrusted(HttpWire.resultHash(403, refusalBody))))));
        a.add(callerCase("a caller with no verifier checks nothing", false, Map.of(), uri, 200, ok, PAID, ch)
                .set("expected", callerExpected(null, List.of(untrusted(okHash)))));
        return a;
    }

    private static InfluenceEntry untrusted(String hash) {
        return new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:payment", hash, null, null);
    }

    static ObjectNode runCaller(JsonNode c, Fixtures fx) {
        JsonNode s = c.get("caller");
        String svc = s.get("svc").asText();
        long now = c.get("now").asLong();
        long ts = c.get("ts").asLong();
        Material m = fx.material(c.get("material").asText());
        Stamper stamper = new Stamper(svc, s.get("inst").asText(), fx.privateKey(svc), false, () -> "unused",
                () -> ts);
        Map<String, String> receivers = new LinkedHashMap<>();
        s.get("receivers").properties().forEach(e -> receivers.put(e.getKey(), e.getValue().asText()));
        HttpCaller.Builder b = HttpCaller.builder(svc, stamper).bundle(m.bundle(svc)).receivers(receivers);
        if (s.get("verifier").asBoolean()) {
            b.verifier(new Verifier(VerifierConfig.pinned(List.of(m.keyring()), List.of(m.root()), m.policyKey(),
                    now, textSet(c.get("allowedOrigins")), "", new InMemoryNonceCache(c.get("nonceTtlMs").asLong()),
                    () -> now, c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong())));
        }
        HttpCaller caller = b.build();
        JsonNode call = c.get("call");
        HttpCaller.Outbound sent = caller.stamp(call.get("method").asText(), URI.create(call.get("uri").asText()),
                unhex(call.get("body")), stamps(c.get("inbound")), entries(c.get("influence")));
        JsonNode r = c.get("response");
        HttpCaller.Received received = caller.check(sent, r.get("status").asInt(),
                r.get("header").isNull() ? null : r.get("header").asText(), unhex(r.get("body")));
        ObjectNode e = obj();
        List<Stamp> chain = sent.sent().chain();
        e.put("rcv", chain.get(chain.size() - 1).rcv());
        if (received.check() == null) {
            e.putNull("reason");
        } else {
            e.put("reason", received.check().result().reason().name());
        }
        e.set("influence", entries(received.influence()));
        return e;
    }

    // --- Replay ---

    /** Replays every kind in {@code rules}. */
    static void assertAll(JsonNode rules, JsonNode http, JsonNode core) {
        Fixtures fx = new Fixtures(rules, http, core);
        for (String kind : List.of("requests", "unreadableInfluence", "attestation", "refusals", "trustedRecord")) {
            for (JsonNode c : rules.get(kind)) {
                assertEquals(c.get("expected"), runReceiver(c, fx), kind + ": " + c.get("name").asText());
            }
        }
        for (JsonNode c : rules.get("peerCertificates")) {
            assertEquals(c.get("expected"), runCertificate(c), "peerCertificates: " + c.get("name").asText());
        }
        assertTrue(rules.get("unsafeEndpoints") != null && !rules.get("unsafeEndpoints").isEmpty(),
                "the rules have an unsafeEndpoints section");
        for (JsonNode c : rules.get("unsafeEndpoints")) {
            assertEquals(c.get("refused").asBoolean(), new UnsafeEndpoints(textList(c.get("disabled")))
                    .refuses(c.get("method").asText(), c.get("routePattern").asText()),
                    "unsafeEndpoints: " + c.get("name").asText());
        }
        for (JsonNode c : rules.get("callerInfluence")) {
            assertEquals(c.get("expected"), runCaller(c, fx), "callerInfluence: " + c.get("name").asText());
        }
        VectorsHttpPartner.assertAll(rules, fx);
    }
}
