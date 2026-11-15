// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paztport.http.VectorsHttpV4Export.entries;
import static org.paztport.http.VectorsHttpV4Export.entriesJson;
import static org.paztport.http.VectorsHttpV4Export.hex;
import static org.paztport.http.VectorsHttpV4Export.nonceKey;
import static org.paztport.http.VectorsHttpV4Export.putSettings;
import static org.paztport.http.VectorsHttpV4Export.settings;
import static org.paztport.http.VectorsHttpV4Export.tree;
import static org.paztport.http.VectorsHttpV4Export.unhex;

import com.fasterxml.jackson.databind.JsonNode;
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
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;

/**
 * Builds and replays the {@code rules} section of {@code spec/vectors/http-v4.json}: the HTTP rules the spec requires
 * of a receiver, a caller, a partner and an egress, each case an input and the answer the spec gives for it. A case
 * is replayed through the framework-neutral functions a binding adapts ({@link HttpReceiver} and
 * {@link PartnerReceiver} entered through {@link RequestContext#accept}, with {@link PublicWrites} asked as a handler
 * asks it, {@link HttpCaller#stamp} and {@link HttpCaller#check}, {@link HttpSessions#serve}, {@link PeerCert#of},
 * {@link UnsafeEndpoints} and {@link org.paztport.http.boundary.BoundaryClient}), so the file holds nothing a
 * framework decides. The partner and egress kinds are {@link VectorsHttpPartner}'s. The section's fixtures also hold
 * a partner's material, handshake requests and client certificates.
 *
 * <p>Every expected answer here is written by hand from the spec, not taken from a run: {@link #assertAll} replays
 * each case and compares, so an export fails rather than record what the code happens to do. The exceptions are
 * primitives pinned on their own: what an egress sends holds blinded entries and a block commitment computed with
 * {@code BoundaryInfluence.reduce} and {@code Block.commit}, pinned by {@code boundaryInfluence} here and by
 * {@code blocks} and {@code influence} in {@code v4.json}, and the result hashes and request bindings it records are
 * computed as {@code resultHash} and {@code requestBinding} pin them.
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
    /** The mesh route with the operation orders names at payment, as a caller holding payment's table stamps it. */
    static final String OPERATION_ROUTE = "gateway/orders/payment#pay";
    static final String BOUNDARY_ROUTE = "payment/psp";
    static final byte[] PAY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    static final byte[] PAID = "{\"paid\":true}".getBytes(StandardCharsets.UTF_8);
    /** The owner of the destination every handler asks about a guarded public write to, from its own records. */
    static final String DESTINATION_OWNER = "bob";
    /** An extension no service here acts on, the name wire.md's own example uses. */
    static final String EXAMPLE = "example";

    /** Private data of alice's and a public page: shaped only by trusted content. */
    static final List<InfluenceEntry> OWNED = Influence.normalise(List.of(
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-1", "cid-order-1", "alice"),
            new InfluenceEntry(InfluenceClass.PUBLIC, "http:catalogue", "h-catalogue-1", null, null)));
    /** A third-party ticket beside alice's order: steered by untrusted content. */
    static final List<InfluenceEntry> STEERED = Influence.normalise(List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "h-ticket-1", "cid-ticket-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-1", "cid-order-1", "alice")));

    /** The block of a hop that acts on influence and has added nothing: it names influence with {@code []}. */
    static final Block NAMED = Influence.block(List.of(), List.of());
    /** A pass-along block: it requires influence of the next hop but does not name it (influence.md). */
    static final Block PASS_ALONG = Block.of(Map.of(), List.of(Influence.NAME));

    private static final String ABOUT = "The HTTP rules the spec requires of a receiver, a caller, a partner and an"
            + " egress, each case an input and the answer the spec gives. A key is looked up by name here, then in"
            + " this file's top-level `keys`, then in v4.json; each new one is derived by v4.json's rule. A `material`"
            + " is one organisation's policy key (by name), its signed root and signed keyring, each with its"
            + " notAfter, the proofs of its routes and, for a partner, its entry service and reply certificate. Each"
            + " root's tree has depth 1, its two routes filling both leaves with salts by v4.json's rule, so it has no"
            + " padding; its rootId is \"v\" and the first 12 hex digits of"
            + " SHA-256(utf8(\"paztport-http-v3-vector-root:\" + tree)), for the vectors only. `handshakes` holds"
            + " handshake requests on the shop's material, each nonce the first 16 bytes (15 for `short-nonce`) of"
            + " SHA-256(utf8(\"paztport-http-v3-vector-nonce:\" + name)), base64url, and `handshakeBodies` each"
            + " request's JCS bytes; `peers` holds client certificates, each with the address it connects from. Bodies"
            + " and certificates are hex, and headers are their values as sent. A receiver case enters `request` at"
            + " `service` `uses` times against one nonce cache that already holds `spent`, each key the JCS text of"
            + " its array of strings, the service's verifier, when it has one, pinned to `material`, and `expected` is"
            + " the last entry's answer. The service acts on the extensions in `actsOn` and carries the names in"
            + " `allowedExtensions` (null for unset, which carries any name), with a verifier or without one. Its"
            + " `mode` is `enforce` or `audit`; `off`, a hop that verifies requests but whose deployment has switched"
            + " it off; or null, a service that verifies no requests under a mode. Unless its name says otherwise, a"
            + " case's chain is gateway's stamp to orders, then orders' to payment, and each hop's block names"
            + " `influence`, with `[]` when the hop added nothing. The answer is the `refusal` (null when the request"
            + " is served); `verified`, whether the request is served as having passed the live order at this service"
            + " (false for every refusal); `handedOn`, what the service is handed, null for nothing, else one member"
            + " per name in `actsOn` ({} where `actsOn` is empty), each an array of {svc, items}, one per stamp, items"
            + " null where the stamp's block does not name the extension; and `attests`. Then the handler, having"
            + " read the entries in `read`, asks two questions, at a service that acts on `influence`, as every"
            + " receiver here does unless its `actsOn` says otherwise: `publicWrite`, the reason a guarded public"
            + " write to a destination whose owner is `destinationOwner` gets; and `trustedRecord`, whether a trusted"
            + " record may be written. A refused request runs no handler, and a service that does not act on"
            + " `influence` asks neither question, so both are null then; work outside any request (a null `request`)"
            + " asks only for the trusted record. A caller case is `caller` calling payment after `inbound`, the"
            + " gateway's stamp, which came with the blocks `inboundBlocks`, its own block holding the entries in"
            + " `added`, on `material`, holding the tables of the top-level `operations` that `caller.operations`"
            + " names, as a caller that acts on `actsOn` and carries `allowedExtensions`, with a verifier exactly when"
            + " `caller.verifier` is true; payment answers with `response`, and `expected` is the `rcv` of the stamp"
            + " the caller signed, the check's `reason` (null where the caller has no verifier), whether the caller"
            + " `refused` the response, and the `influence` entries the response adds. A partner case runs `steps` in"
            + " order against one partner on `material`, which pins the policy keys `pinned`, takes the egress"
            + " services `clientOrigins` as allowed origins, switches off `unsafeDisabled` for unsafe sessions, keeps"
            + " at most `maxSessionsPerPeer` sessions per peer, each until no call has used it for `sessionIdleMs`,"
            + " and acts on `actsOn` and carries `allowedExtensions` as a receiver does; its clock reads each step's"
            + " `at`. A handshake step posts, from the client certificate `peer`, the `handshakeBodies` entry its"
            + " `request` names, or `body` where `request` is null, and `as` names the session it opens, since the"
            + " partner picks the id; it expects the HTTP `status`, the `error`, and for a session opened its"
            + " `sessionStatus`, its `disabled` endpoints and the `extensions` the reply lists. A call step sends"
            + " `method` `target` with `body` from the client certificate `peer`, naming its `session` by a"
            + " handshake's `as` (`of`), as a literal (`id`), or not at all (null), with `proofHeader` and"
            + " `extensionsHeader` as given; its `stamp`, when there is one, is a boundary stamp with the fields"
            + " given, signed as the step runs with the key `key`, in the session its `sess` names, over the binding"
            + " of the call's method and target with the stamp's own `body`, and committing to `block`. A call may"
            + " carry `read`, what the handler reads once it is accepted. It expects the `refusal` (an unsafe"
            + " session's switched-off endpoint, by `routePattern`, included), whether it is served `attested`,"
            + " `handedOn` as a receiver case records it, and `trustedRecord`, null for a refusal. An egress case"
            + " enters `inbound`, a receiver case's inputs (null for work outside any request), at the egress"
            + " `egress`, which acts on `actsOn` and carries `allowedExtensions` as a receiver does, requires"
            + " `requires` of the partner and goes on without them when `continueWithout` is true, and posts each of"
            + " `posts` to `partnerScript`: a partner that answers each full handshake with the next of `handshakes`"
            + " (`attested` or `unsafe`, a genuine reply on the `psp` material; `notFound`, a 404; `wrongKey`, a reply"
            + " signed by and naming `stranger-policy`), the replacement as `replacement` says, every reply listing"
            + " `extensions`, and each call with the next of `calls`. It expects each post's `outcome` (`answered`,"
            + " with the `status` and whether the session was `attested`; `refused` by the egress's guard, nothing"
            + " sent; `withheld`, no call made in a session that does not meet the requirement; `failed`, no session),"
            + " all the partner `received` in order (a handshake, whether it had a client root; a call, its session"
            + " and the session its stamp was made in, each the position of the handshake whose reply issued it, its"
            + " stamps without `sess` and `sig`, its proof and its `blocks`), and the entries the request `added` at"
            + " the egress. A boundary block's entries are blinded under the boundary key as `boundaryInfluence` pins"
            + " it. Against http-v3.json's rules: stamps are version 4 and blocks travel in `X-Path-Extensions`; nonce"
            + " keys are JCS text. A receiver case gains the inputs `actsOn`, `allowedExtensions` and"
            + " `destinationOwner`; its answer holds `handedOn` in place of `influence` (null where v3 recorded `[]`"
            + " for nothing), and gains `publicWrite`; a refusal's `trustedRecord` is null, not false."
            + " `unreadableInfluence` is `influenceItems`, an item on a request's block that does not read as an"
            + " entry; `servedUnverified` is new, check 9a at a service about to serve a request it did not verify."
            + " `callerInfluence` follows the HTTP rule for what a response adds: its response header is {block,"
            + " stamp}, the caller's input `influence` is `added`, the entries its own block holds, it gains the"
            + " inputs `actsOn`, `allowedExtensions` and `inboundBlocks`, and its answer gains `refused`. Six cases of"
            + " http-v3.json are dropped, each for repeating another case's input and answer, and found under the case"
            + " that stays: requests' \"verified, with the influence the stamp commits to\" and attestation's"
            + " \"enforce, verified\" under trustedRecord's \"verified, private and public with owners\";"
            + " trustedRecord's \"verified, no influence\" under requests' \"verified\"; trustedRecord's \"refused\""
            + " under attestation's \"enforce, refused\"; attestation's \"off: verifies and attests nothing\" under"
            + " trustedRecord's \"a hop that is off\"; and refusals' \"unreadable influence in audit mode\" under"
            + " influenceItems' \"audit, on a chain that verifies otherwise\". A partner gains `actsOn` and"
            + " `allowedExtensions`, a session it opens `extensions`; a call's stamp commits to a `block` in place of"
            + " `influence` and the call carries `extensionsHeader` in place of `influenceHeader`; its answer holds"
            + " `handedOn` in place of `influence`, and a refused call's `trustedRecord` is null, not false."
            + " boundaryRefusals' \"influence other than the stamp commits to\" is \"a block other than the stamp"
            + " commits to\" and its \"influence that cannot be read\" is \"blocks that cannot be read\", both"
            + " EXTENSION_MISMATCH, and \"an item that is not an entry\" is new; sessionHeader gains an unsafe call"
            + " whose blocks differ from what its stamp commits to, and handshakeErrors a partner that acts on no"
            + " extension; partnerTrustedRecord gains a stamp whose block names influence with nothing and one whose"
            + " block does not name it. An egress gains `actsOn`, `allowedExtensions`, `requires` and"
            + " `continueWithout`, its partner script `extensions`, a post the outcome `withheld`; a call received"
            + " holds `blocks` in place of `influence`, and the answer `added`, what the egress added, in place of"
            + " `influence`; the cases on the requirement and on what the boundary block names are new. No partner or"
            + " egress case of http-v3.json is dropped: none repeats another's input.";

    private VectorsHttpRules() {
    }

    // --- JSON ---

    static ObjectNode obj() {
        return JsonNodeFactory.instance.objectNode();
    }

    static ArrayNode arr() {
        return JsonNodeFactory.instance.arrayNode();
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
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
    private static MerkleTree merkleTree(String name, List<String> routes) {
        List<MerkleLeaf> leaves = routes.stream()
                .map(r -> new MerkleLeaf(Arrays.copyOf(Crypto.sha256(utf8("paztport-v3-vector-salt:" + r)),
                        MerkleProof.SALT_BYTES), r))
                .toList();
        return MerkleTree.build(leaves, 1, rootId(name));
    }

    private static ObjectNode material(String treeName, List<String> routes, String policyName, KeyPair policy,
            Map<String, String> services, long notAfter) {
        MerkleTree t = merkleTree(treeName, routes);
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
            KeyPair k = VectorsHttpV4Export.derive(name);
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
        material.set("shop-operations", material("shop-operations", List.of(OPERATION_ROUTE,
                String.join("/", VectorsHttpV4Export.paymentTable().route())), "shop-policy",
                made.get("shop-policy"), shopServices, NOT_AFTER));
        material.set("shop-keys", material("shop-keys", List.of(VectorsHttpV4Export.KEYED_ROUTE,
                String.join("/", VectorsHttpV4Export.keyedTable().route())), "shop-policy",
                made.get("shop-policy"), shopServices, NOT_AFTER));
        material.set("psp", partnerMaterial(made.get("psp-policy"), made.get("psp"), NOT_AFTER));
        material.set("psp-expiring", partnerMaterial(made.get("psp-policy"), made.get("psp"), EXPIRES));
        rules.set("handshakes", handshakes(new Fixtures(reread(rules), http, core)));
        rules.set("handshakeBodies", handshakeBodies(rules.get("handshakes")));
        rules.set("peers", peers(made.get("shop-ca")));
        // The cases are built from the fixtures as the file holds them, as a replay reads them.
        Fixtures fx = new Fixtures(reread(rules), http, core);

        Chains chains = new Chains(fx);
        rules.set("requests", requests(chains));
        rules.set("influenceItems", influenceItems(chains));
        rules.set("servedUnverified", servedUnverified(chains));
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

    /** A chain and the blocks sent beside it, one per stamp, which need not be the ones its stamps commit to. */
    record Sent(List<Stamp> chain, List<Block> blocks) {

        /** The same chain sent with orders' block, the last, replaced by {@code block}, which it did not sign. */
        Sent altered(Block block) {
            List<Block> others = new ArrayList<>(blocks);
            others.set(others.size() - 1, block);
            return new Sent(chain, List.copyOf(others));
        }
    }

    /** The request chains the receiver cases send to {@code payment}, stamped once with fixed clocks. */
    static final class Chains {

        final Fixtures fx;
        final Material shop;
        /** gateway's stamp to orders, its block naming influence with nothing added: what orders receives. */
        final List<Stamp> toOrders;
        /** gateway, orders, payment, every block naming influence and holding nothing. */
        final Sent clean;
        /** The same, orders' block holding {@link #OWNED}. */
        final Sent owned;
        /** The same, orders' block holding {@link #STEERED}. */
        final Sent steered;
        /** {@link #owned}, but gateway's block is the empty block, which does not name influence. */
        final Sent unnamedOrigin;
        /** {@link #owned}, but gateway's block is {@link #PASS_ALONG}, which does not name influence either. */
        final Sent passAlong;
        /** orders' block holding one item that is not an entry, a string. */
        final Sent unread;
        /** orders' block holding one item that is an array of entries, not an entry. */
        final Sent unreadList;
        /** orders' block holding one entry whose owner is empty. */
        final Sent unreadOwner;
        /** orders' block naming influence with nothing added, and requiring {@link #EXAMPLE} of payment. */
        final Sent requiring;
        /** {@link #clean} with orders' stamp signed with the gateway's key. */
        final Sent forged;
        /** {@link #owned}, forged as {@link #forged} is. */
        final Sent forgedOwned;
        /** {@link #steered}, forged as {@link #forged} is. */
        final Sent forgedSteered;
        /** {@link #unread}, forged as {@link #forged} is. */
        final Sent forgedUnread;
        /** A forged chain whose every block is the empty block, so every stamp's ext is "". */
        final Sent forgedBare;
        /** {@link #forgedBare}, but orders' block names influence, so its ext is not "". */
        final Sent forgedOneExt;
        /** One origin stamp from the gateway straight to payment, a route the policy does not hold. */
        final Sent direct;
        /** One gateway stamp to payment with an empty signature and the empty block. */
        final Sent unsigned;

        Chains(Fixtures fx) {
            this.fx = fx;
            this.shop = fx.material("shop");
            this.toOrders = gateway(NAMED);
            List<Stamp> bareToOrders = gateway(Block.EMPTY);
            PrivateKey ordersKey = fx.privateKey("orders");
            PrivateKey gatewayKey = fx.privateKey("gateway");
            this.clean = orders(toOrders, NAMED, Influence.block(List.of(), List.of()), ordersKey);
            this.owned = orders(toOrders, NAMED, Influence.block(OWNED, List.of()), ordersKey);
            this.steered = orders(toOrders, NAMED, Influence.block(STEERED, List.of()), ordersKey);
            this.unnamedOrigin = orders(bareToOrders, Block.EMPTY, Influence.block(OWNED, List.of()), ordersKey);
            this.passAlong = orders(gateway(PASS_ALONG), PASS_ALONG, Influence.block(OWNED, List.of()), ordersKey);
            this.unread = orders(toOrders, NAMED, items("\"not an entry\""), ordersKey);
            this.unreadList = orders(toOrders, NAMED, items("[" + OWNED.get(0).toJson() + "]"), ordersKey);
            this.unreadOwner = orders(toOrders, NAMED,
                    items("{\"cls\":\"private\",\"h\":\"h-order-1\",\"owner\":\"\",\"src\":\"http:orders\"}"),
                    ordersKey);
            this.requiring = orders(toOrders, NAMED, Influence.block(List.of(), List.of(EXAMPLE)), ordersKey);
            this.forged = orders(toOrders, NAMED, Influence.block(List.of(), List.of()), gatewayKey);
            this.forgedOwned = orders(toOrders, NAMED, Influence.block(OWNED, List.of()), gatewayKey);
            this.forgedSteered = orders(toOrders, NAMED, Influence.block(STEERED, List.of()), gatewayKey);
            this.forgedUnread = orders(toOrders, NAMED, items("\"not an entry\""), gatewayKey);
            this.forgedBare = orders(bareToOrders, Block.EMPTY, Block.EMPTY, gatewayKey);
            this.forgedOneExt = orders(bareToOrders, Block.EMPTY, Influence.block(List.of(), List.of()), gatewayKey);
            String bind = RequestBinding.compute("POST", "/pay", PAY);
            this.direct = new Sent(new Stamper("gateway", "gw-1", gatewayKey, true, () -> RID, () -> ORDERS_TS)
                    .next(List.of(), "payment", bind, NAMED, null).chain(), List.of(NAMED));
            this.unsigned = new Sent(List.of(new Stamp("gateway", "gw-1", RID, ORDERS_TS, "", "payment", bind, "", "",
                    "")), List.of(Block.EMPTY));
        }

        private List<Stamp> gateway(Block block) {
            return new Stamper("gateway", "gw-1", fx.privateKey("gateway"), true, () -> RID, () -> GATEWAY_TS)
                    .next(List.of(), "orders", "bind-gateway-to-orders", block, null).chain();
        }

        /** orders' stamp to payment after {@code toOrders}, signed with {@code key}, committing to {@code block}. */
        private static Sent orders(List<Stamp> toOrders, Block gatewayBlock, Block block, PrivateKey key) {
            List<Stamp> chain = new Stamper("orders", "ord-1", key, false, () -> RID, () -> ORDERS_TS)
                    .next(toOrders, "payment", RequestBinding.compute("POST", "/pay", PAY), block, null).chain();
            return new Sent(chain, List.of(gatewayBlock, block));
        }

        /** A block naming influence with the one item {@code item}, a value's JCS text, whatever it holds. */
        private static Block items(String item) {
            return Block.of(Map.of(Influence.NAME, List.of(item)), List.of());
        }

        /** {@code POST /pay} with the chain, the mesh route's proof and the blocks sent beside it. */
        ObjectNode request(Sent sent) {
            return request(headers(HttpWire.encodeChain(sent.chain()), shop.proofHeader(MESH_ROUTE),
                    HttpWire.encodeBlocks(sent.blocks())), PAY);
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

    /** The settings of a receiver that acts on influence and carries any name, as every receiver here but one does. */
    static final ExtensionSettings ACTS_ON_INFLUENCE = ExtensionSettings.of(Set.of(Influence.NAME), null);

    /**
     * A receiver case's inputs, with the mesh defaults: a service that acts on influence, no peer, no spent keys,
     * one use, nothing read, and a guarded write asked about for {@link #DESTINATION_OWNER}.
     */
    static ObjectNode receiverCase(String name, Service service, String mode, JsonNode request) {
        ObjectNode c = obj();
        c.put("name", name);
        c.put("material", "shop");
        c.set("service", service.json());
        putSettings(c, ACTS_ON_INFLUENCE);
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
        c.put("destinationOwner", DESTINATION_OWNER);
        return c;
    }

    /**
     * A served request's answer: whether its chain verified here, what the service is handed, whether it attests,
     * and the handler's two answers, null where it asks neither.
     */
    static ObjectNode served(boolean verified, JsonNode handedOn, boolean attests, ReasonCode publicWrite,
            Boolean trusted) {
        ObjectNode e = obj();
        e.putNull("refusal");
        e.put("verified", verified);
        e.set("handedOn", handedOn);
        e.put("attests", attests);
        putAnswers(e, publicWrite == null ? null : publicWrite.name(), trusted);
        return e;
    }

    private static void putAnswers(ObjectNode e, String publicWrite, Boolean trusted) {
        if (publicWrite == null) {
            e.putNull("publicWrite");
        } else {
            e.put("publicWrite", publicWrite);
        }
        if (trusted == null) {
            e.putNull("trustedRecord");
        } else {
            e.put("trustedRecord", trusted);
        }
    }

    /** A refusal: the status and its body, with nothing handed on, nothing attested, and no handler to ask. */
    static ObjectNode refused(int status, ReasonCode reason) {
        ObjectNode e = obj();
        e.set("refusal", VectorsHttpV4Export.refusal(status, reason));
        e.put("verified", false);
        e.putNull("handedOn");
        e.put("attests", false);
        putAnswers(e, null, null);
        return e;
    }

    /** Nothing handed on: an origin's request, and one whose chain did not read. */
    static JsonNode nothing() {
        return JsonNodeFactory.instance.nullNode();
    }

    /** One stamp's entry of a hand-over: its signer, and its block's entries under influence, null for none. */
    static ObjectNode stamp(String svc, List<InfluenceEntry> items) {
        ObjectNode s = obj();
        s.put("svc", svc);
        if (items == null) {
            s.putNull("items");
        } else {
            s.set("items", entriesJson(items));
        }
        return s;
    }

    /** A hand-over under influence alone, one entry per stamp in chain order. */
    static ObjectNode handed(ObjectNode... stamps) {
        ObjectNode h = obj();
        ArrayNode a = h.putArray(Influence.NAME);
        for (ObjectNode s : stamps) {
            a.add(s);
        }
        return h;
    }

    /** What gateway, then orders, hand on when both blocks name influence, orders' holding {@code orders}. */
    static ObjectNode handed(List<InfluenceEntry> orders) {
        return handed(stamp("gateway", List.of()), stamp("orders", orders));
    }

    private static ObjectNode expect(ObjectNode c, ObjectNode expected) {
        c.set("expected", expected);
        return c;
    }

    private static ObjectNode headers(String chain, String proof, String blocks) {
        ObjectNode h = obj();
        if (chain != null) {
            h.put(PaztportHeaders.CHAIN, chain);
        }
        if (proof != null) {
            h.put(PaztportHeaders.PROOF, proof);
        }
        if (blocks != null) {
            h.put(PaztportHeaders.EXTENSIONS, blocks);
        }
        return h;
    }

    private static String b64(String text) {
        return Base64Url.encode(utf8(text));
    }

    /** verification.md, a request at the receiver: the nonce key and how each unreadable header is read. */
    private static ArrayNode requests(Chains ch) {
        String chain = HttpWire.encodeChain(ch.clean.chain());
        String blocks = HttpWire.encodeBlocks(ch.clean.blocks());
        String proof = ch.shop.proofHeader(MESH_ROUTE);
        ArrayNode a = arr();
        a.add(expect(receiverCase("verified", Service.PAYMENT, "enforce", ch.request(ch.clean)),
                served(true, handed(List.of()), true, ReasonCode.OK, true)));
        ObjectNode twice = receiverCase("the same request twice", Service.PAYMENT, "enforce", ch.request(ch.clean));
        twice.put("uses", 2);
        a.add(expect(twice, refused(403, ReasonCode.REPLAY)));
        ObjectNode spent = receiverCase("its nonce key [rid, last svc, last rcv, \"req\"] already spent",
                Service.PAYMENT, "enforce", ch.request(ch.clean));
        spent.set("spent", texts(nonceKey(RID, "orders", "payment", "req")));
        a.add(expect(spent, refused(403, ReasonCode.REPLAY)));
        ObjectNode others = receiverCase("other directions', hops' and operations' keys are not its own",
                Service.PAYMENT, "enforce", ch.request(ch.clean));
        others.set("spent", texts(nonceKey(RID, "orders", "resp"), nonceKey(RID, "payment", "req"),
                nonceKey(RID, "gateway", "req"), nonceKey(RID, "orders"), nonceKey(RID, "orders", "local"),
                nonceKey(RID, "orders", "payment#pay", "req"), nonceKey(RID, "orders", "req")));
        a.add(expect(others, served(true, handed(List.of()), true, ReasonCode.OK, true)));
        a.add(expect(receiverCase("no chain header", Service.PAYMENT, "enforce",
                Chains.request(headers(null, proof, null), PAY)), refused(403, ReasonCode.CHAIN_MISSING)));
        a.add(expect(receiverCase("a chain header that is not base64url", Service.PAYMENT, "enforce",
                Chains.request(headers("not*base64url", proof, blocks), PAY)),
                refused(403, ReasonCode.CHAIN_MISSING)));
        a.add(expect(receiverCase("a chain header that is not JSON", Service.PAYMENT, "enforce",
                Chains.request(headers(b64("not json"), proof, blocks), PAY)),
                refused(403, ReasonCode.CHAIN_MISSING)));
        a.add(expect(receiverCase("no proof header", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, null, blocks), PAY)), refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        a.add(expect(receiverCase("a proof header that is not base64url is no proof", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, "not*base64url", blocks), PAY)),
                refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        a.add(expect(receiverCase("a proof header that is not JSON is no proof", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, b64("{"), blocks), PAY)), refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        // A header that is present but does not decode is not an absent one.
        a.add(expect(receiverCase("an extensions header that is not base64url", Service.PAYMENT, "enforce",
                Chains.request(headers(chain, proof, "not*base64url"), PAY)),
                refused(403, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("no extensions header where the stamps commit to blocks", Service.PAYMENT,
                "enforce", Chains.request(headers(HttpWire.encodeChain(ch.owned.chain()), proof, null), PAY)),
                refused(403, ReasonCode.EXTENSION_MISMATCH)));
        return a;
    }

    /**
     * influence.md, Entries: a service that acts on influence reads every item it is handed, verified or not, and
     * refuses one that does not read 400 in every mode, wherever nothing refused first; one that does not act on
     * influence reads none.
     */
    private static ArrayNode influenceItems(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("enforce: an item that is not an entry, on a chain that verifies", Service.PAYMENT,
                "enforce", ch.request(ch.unread)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("enforce: an earlier check refuses first", Service.PAYMENT, "enforce",
                ch.request(ch.forgedUnread)), refused(403, ReasonCode.BAD_SIGNATURE)));
        a.add(expect(receiverCase("audit, on a chain that verifies otherwise", Service.PAYMENT, "audit",
                ch.request(ch.unread)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("audit, on a chain that fails, its blocks matching", Service.PAYMENT, "audit",
                ch.request(ch.forgedUnread)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("audit: an item that is an array of entries, not an entry", Service.PAYMENT,
                "audit", ch.request(ch.unreadList)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("audit: an entry with an empty owner", Service.PAYMENT, "audit",
                ch.request(ch.unreadOwner)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("a service that verifies only to attest", Service.PAYMENT, null,
                ch.request(ch.unread)), refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("a service with no verifier", Service.NO_VERIFIER, null, ch.request(ch.unread)),
                refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("off", Service.PAYMENT, "off", ch.request(ch.unread)),
                refused(400, ReasonCode.INFLUENCE_MISMATCH)));
        a.add(expect(receiverCase("an origin carries none, so has none to read", Service.ORIGIN, null,
                ch.request(ch.unread)), served(false, nothing(), false, ReasonCode.OK, false)));
        // The first case's input at a service whose settings do not name influence: it reads no item, is handed
        // nothing under the name, and its handler asks no influence question.
        ObjectNode notActing = receiverCase("enforce, at a service that does not act on influence", Service.PAYMENT,
                "enforce", ch.request(ch.unread));
        putSettings(notActing, ExtensionSettings.NONE);
        a.add(expect(notActing, served(true, obj(), true, null, null)));
        return a;
    }

    /**
     * verification.md, "A service never serves a request whose blocks fail check 9a" and "What a request served
     * without verifying is handed": every service about to serve a request it did not verify applies check 9a
     * itself, or requires an array of blocks where the chain did not read, and answers 400; what it then serves is
     * handed on as not verified.
     */
    private static ArrayNode servedUnverified(Chains ch) {
        String proof = ch.shop.proofHeader(MESH_ROUTE);
        String bare = HttpWire.encodeChain(ch.forgedBare.chain());
        String unreadable = b64("not json");
        ArrayNode a = arr();
        a.add(expect(receiverCase("audit after a bad signature, its blocks matching", Service.PAYMENT, "audit",
                ch.request(ch.forgedOwned)), served(false, handed(OWNED), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("audit after a bad signature, orders' block altered", Service.PAYMENT, "audit",
                ch.request(ch.forgedOwned.altered(NAMED))), refused(400, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("audit after a bad signature, no extensions header, every ext empty",
                Service.PAYMENT, "audit", Chains.request(headers(bare, proof, null), PAY)),
                served(false, handed(stamp("gateway", null), stamp("orders", null)), false,
                        ReasonCode.INFLUENCE_DENIED, false)));
        a.add(expect(receiverCase("audit after a bad signature, no extensions header, one ext not empty",
                Service.PAYMENT, "audit", Chains.request(headers(HttpWire.encodeChain(ch.forgedOneExt.chain()),
                        proof, null), PAY)), refused(400, ReasonCode.EXTENSION_MISMATCH)));
        // Present but not decoding, beside the absent header two cases up.
        a.add(expect(receiverCase("audit after a bad signature, an extensions header that is not base64url",
                Service.PAYMENT, "audit", Chains.request(headers(bare, proof, "not*base64url"), PAY)),
                refused(400, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("audit after a bad signature, blocks that are JSON null", Service.PAYMENT, "audit",
                Chains.request(headers(bare, proof, b64("null")), PAY)), refused(400, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("audit, a chain that does not read, blocks that are an array", Service.PAYMENT,
                "audit", Chains.request(headers(unreadable, proof, HttpWire.encodeBlocks(List.of(Block.EMPTY))), PAY)),
                served(false, nothing(), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("audit, a chain that does not read, blocks that are an object", Service.PAYMENT,
                "audit", Chains.request(headers(unreadable, proof, b64(Block.EMPTY.toJson())), PAY)),
                refused(400, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("audit, no chain and no blocks", Service.PAYMENT, "audit",
                Chains.request(headers(null, proof, null), PAY)), served(false, nothing(), false, ReasonCode.OK,
                        false)));
        // orders' block with its third-party entry dropped: the claim a hop that alters a block would hide.
        Sent hidden = ch.steered.altered(Influence.block(OWNED, List.of()));
        a.add(expect(receiverCase("a service that verifies only to attest, orders' block altered", Service.PAYMENT,
                null, ch.request(hidden)), refused(400, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("a service that verifies only to attest, verified", Service.PAYMENT, null,
                ch.request(ch.steered)), served(true, handed(STEERED), true, ReasonCode.INFLUENCE_DENIED, false)));
        a.add(expect(receiverCase("a service with no verifier, its blocks matching", Service.NO_VERIFIER, null,
                ch.request(ch.steered)), served(false, handed(STEERED), false, ReasonCode.INFLUENCE_DENIED, false)));
        a.add(expect(receiverCase("a service with no verifier, orders' block altered", Service.NO_VERIFIER, null,
                ch.request(hidden)), refused(400, ReasonCode.EXTENSION_MISMATCH)));
        a.add(expect(receiverCase("off, orders' block altered", Service.PAYMENT, "off",
                ch.request(ch.clean.altered(Influence.block(STEERED, List.of())))),
                refused(400, ReasonCode.EXTENSION_MISMATCH)));
        // Check 9c is not check 9a: it follows the mode, refusing in enforce and serving in audit.
        a.add(expect(receiverCase("enforce, a last block requiring an extension not acted on", Service.PAYMENT,
                "enforce", ch.request(ch.requiring)), refused(403, ReasonCode.EXTENSION_REQUIRED)));
        a.add(expect(receiverCase("audit, a last block requiring an extension not acted on", Service.PAYMENT,
                "audit", ch.request(ch.requiring)), served(false, handed(List.of()), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("an origin sent blocks that are an object", Service.ORIGIN, null,
                Chains.request(headers(HttpWire.encodeChain(ch.clean.chain()), proof, b64("{}")), PAY)),
                served(false, nothing(), false, ReasonCode.OK, false)));
        return a;
    }

    /** verification.md, who attests: only a chain that passed the live order at this service. */
    private static ArrayNode attestation(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("enforce, refused", Service.PAYMENT, "enforce", ch.request(ch.forged)),
                refused(403, ReasonCode.BAD_SIGNATURE)));
        a.add(expect(receiverCase("audit, verified", Service.PAYMENT, "audit", ch.request(ch.owned)),
                served(true, handed(OWNED), true, ReasonCode.OK, true)));
        a.add(expect(receiverCase("audit, failed: served with what came, unattested", Service.PAYMENT, "audit",
                ch.request(ch.forgedSteered)), served(false, handed(STEERED), false, ReasonCode.INFLUENCE_DENIED,
                        false)));
        a.add(expect(receiverCase("no mode, verified for attestation alone", Service.PAYMENT, null,
                ch.request(ch.owned)), served(true, handed(OWNED), true, ReasonCode.OK, true)));
        a.add(expect(receiverCase("no mode, a forged chain: served, unattested", Service.PAYMENT, null,
                ch.request(ch.forged)), served(false, handed(List.of()), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("no mode, a one-stamp chain with an empty signature", Service.PAYMENT, null,
                ch.request(ch.unsigned)), served(false, handed(stamp("gateway", null)), false,
                        ReasonCode.INFLUENCE_DENIED, false)));
        a.add(expect(receiverCase("no verifier: nothing to verify with, so never attests", Service.NO_VERIFIER, null,
                ch.request(ch.owned)), served(false, handed(OWNED), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("an origin never attests", Service.ORIGIN, null, ch.request(ch.owned)),
                served(false, nothing(), false, ReasonCode.OK, false)));
        return a;
    }

    /** verification.md, what a refusal carries: the code, and no attribution even where the result names one. */
    private static ArrayNode refusals(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("a route not allowed names its last signer, but not to the caller",
                Service.PAYMENT, "enforce", Chains.request(headers(HttpWire.encodeChain(ch.direct.chain()), null,
                        HttpWire.encodeBlocks(ch.direct.blocks())), PAY)), refused(403, ReasonCode.PATH_NOT_ALLOWED)));
        ObjectNode peer = receiverCase("a peer that is not the last signer is named, but not to the caller",
                Service.PAYMENT, "enforce", ch.request(ch.clean));
        ObjectNode p = peer.putObject("peer");
        p.put("svc", "gateway");
        p.put("inst", "10.1.0.9");
        a.add(expect(peer, refused(403, ReasonCode.PEER_MISMATCH)));
        ObjectNode late = receiverCase("an expired chain", Service.PAYMENT, "enforce", ch.request(ch.clean));
        late.put("now", NOW + 10_000);
        a.add(expect(late, refused(403, ReasonCode.EXPIRED)));
        ObjectNode altered = Chains.request(headers(HttpWire.encodeChain(ch.clean.chain()),
                ch.shop.proofHeader(MESH_ROUTE), HttpWire.encodeBlocks(ch.clean.blocks())), utf8("{\"amount\":999}"));
        a.add(expect(receiverCase("a body altered in transit", Service.PAYMENT, "enforce", altered),
                refused(403, ReasonCode.BINDING_MISMATCH)));
        return a;
    }

    /**
     * influence.md, Trusted records and The every-stamp rule: a verified chain whose every stamp names influence, and
     * no untrusted content in what it holds, the handler's reads included; a guarded public write is refused too
     * unless every stamp names influence.
     */
    private static ArrayNode trustedRecord(Chains ch) {
        ArrayNode a = arr();
        a.add(expect(receiverCase("verified, private and public with owners", Service.PAYMENT, "enforce",
                ch.request(ch.owned)), served(true, handed(OWNED), true, ReasonCode.OK, true)));
        // The case above with only gateway's block changed, to one that does not name influence.
        a.add(expect(receiverCase("verified, only trusted entries, the origin's block not naming influence",
                Service.PAYMENT, "enforce", ch.request(ch.unnamedOrigin)),
                served(true, handed(stamp("gateway", null), stamp("orders", OWNED)), true,
                        ReasonCode.INFLUENCE_DENIED, false)));
        a.add(expect(receiverCase("verified, only trusted entries, the origin's block a pass-along block",
                Service.PAYMENT, "enforce", ch.request(ch.passAlong)),
                served(true, handed(stamp("gateway", null), stamp("orders", OWNED)), true,
                        ReasonCode.INFLUENCE_DENIED, false)));
        a.add(expect(receiverCase("verified, third-party content", Service.PAYMENT, "enforce",
                ch.request(ch.steered)), served(true, handed(STEERED), true, ReasonCode.INFLUENCE_DENIED, false)));
        List<InfluenceEntry> untrusted = List.of(
                new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:search", "h-search-1", null, null));
        ObjectNode readUntrusted = receiverCase("verified, then a local-untrusted read", Service.PAYMENT,
                "enforce", ch.request(ch.owned));
        readUntrusted.set("read", entriesJson(untrusted));
        a.add(expect(readUntrusted, served(true, handed(OWNED), true, ReasonCode.INFLUENCE_DENIED, false)));
        List<InfluenceEntry> card = List.of(
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:cards", "h-card-1", null, "bob"));
        ObjectNode readPrivate = receiverCase("verified, then a private read of someone else's", Service.PAYMENT,
                "enforce", ch.request(ch.owned));
        readPrivate.set("read", entriesJson(card));
        a.add(expect(readPrivate, served(true, handed(OWNED), true, ReasonCode.OK, true)));
        a.add(expect(receiverCase("a chain that failed in audit mode", Service.PAYMENT, "audit",
                ch.request(ch.forged)), served(false, handed(List.of()), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("a hop that is off", Service.PAYMENT, "off", ch.request(ch.clean)),
                served(false, handed(List.of()), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("a service with no verifier", Service.NO_VERIFIER, null, ch.request(ch.clean)),
                served(false, handed(List.of()), false, ReasonCode.OK, false)));
        a.add(expect(receiverCase("an origin", Service.ORIGIN, null, ch.request(ch.clean)),
                served(false, nothing(), false, ReasonCode.OK, false)));
        ObjectNode outside = receiverCase("work outside any request", Service.PAYMENT, "enforce", null);
        outside.putNull("request");
        a.add(expect(outside, served(false, nothing(), false, null, false)));
        return a;
    }

    /** Runs one receiver case and answers in the shape of its {@code expected}. */
    static ObjectNode runReceiver(JsonNode c, Fixtures fx) {
        HttpReceiver receiver = receiver(c, fx);
        String svc = c.get("service").get("svc").asText();
        boolean acts = settings(c).actsOn().contains(Influence.NAME);
        JsonNode request = c.get("request");
        if (request.isNull()) {
            return answer(null, null, acts ? new PublicWrites(svc).shapedOnlyByTrusted() : null);
        }
        Accepted last = null;
        String write = null;
        Boolean trusted = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            try (RequestContext.Entered<Accepted> entered = RequestContext.accept(receiver, inbound(request),
                    peer(c.get("peer")), mode(c.get("mode")))) {
                last = entered.result();
                write = null;
                trusted = null;
                if (last.refusal() == null) {
                    RequestContext.addInfluence(entries(c.get("read")).toArray(InfluenceEntry[]::new));
                    if (acts) {
                        PublicWrites writes = new PublicWrites(svc);
                        write = writes.decide(c.get("destinationOwner").asText()).name();
                        trusted = writes.shapedOnlyByTrusted();
                    }
                }
            }
        }
        return answer(last, write, trusted);
    }

    private static ObjectNode answer(Accepted a, String publicWrite, Boolean trusted) {
        ObjectNode e = obj();
        if (a == null || a.refusal() == null) {
            e.putNull("refusal");
        } else {
            ObjectNode r = e.putObject("refusal");
            r.put("status", a.refusal().status());
            r.put("body", hex(a.refusal().json()));
        }
        e.put("verified", a != null && a.verifiedChain() != null);
        e.set("handedOn", VectorsHttpV4Export.handOverJson(a == null ? null : a.handOver()));
        e.put("attests", a != null && a.attests());
        putAnswers(e, publicWrite, trusted);
        return e;
    }

    /**
     * The receiver a case names, with the case's extension settings: in its verifier, pinned to the case's material
     * over a cache holding {@code spent}, or given to the builder where it has none.
     */
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
                    c.get("runMaxAgeMs").asLong(), settings(c))));
        } else {
            b.extensions(settings(c));
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

    /** sessions.md, over HTTP: an endpoint is the method and the dispatched handler's pattern. */
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

    /**
     * A caller case's inputs: orders, acting on influence, calls payment after the gateway's stamp with what it has
     * added so far, on the shop's material and holding no operation table.
     */
    private static ObjectNode callerCase(String name, boolean verifier, Map<String, String> receivers, String uri,
            int status, String header, byte[] body, Chains ch) {
        return callerCase(name, "shop", List.of(), verifier, receivers, uri, status, header, body, ch);
    }

    /** The same, on {@code material}, the caller holding the tables {@code operations} names. */
    private static ObjectNode callerCase(String name, String material, List<String> operations, boolean verifier,
            Map<String, String> receivers, String uri, int status, String header, byte[] body, Chains ch) {
        ObjectNode c = obj();
        c.put("name", name);
        c.put("material", material);
        ObjectNode caller = c.putObject("caller");
        caller.put("svc", "orders");
        caller.put("inst", "ord-1");
        caller.put("verifier", verifier);
        ObjectNode map = caller.putObject("receivers");
        receivers.forEach(map::put);
        caller.set("operations", texts(operations.toArray(String[]::new)));
        putSettings(c, ACTS_ON_INFLUENCE);
        c.set("allowedOrigins", texts("gateway"));
        c.put("ts", ORDERS_TS);
        c.set("inbound", stamps(ch.toOrders));
        c.set("inboundBlocks", tree(Block.toJson(List.of(NAMED))));
        c.set("added", entriesJson(OWNED));
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
                s.get("ext").asText(), s.get("prev").asText(), s.get("sig").asText())));
        return out;
    }

    private static ObjectNode callerExpected(String reason, boolean refused, List<InfluenceEntry> influence) {
        return callerExpected("payment", reason, refused, influence);
    }

    /**
     * What a caller case expects: the {@code rcv} of the stamp the caller signed, the check's reason, whether the
     * caller refused the response, and the entries it adds.
     */
    private static ObjectNode callerExpected(String rcv, String reason, boolean refused,
            List<InfluenceEntry> influence) {
        ObjectNode e = obj();
        e.put("rcv", rcv);
        if (reason == null) {
            e.putNull("reason");
        } else {
            e.put("reason", reason);
        }
        e.put("refused", refused);
        e.set("influence", entriesJson(influence));
        return e;
    }

    /** payment's attestation of {@code status} and {@code body} with {@code block}, over what orders sent. */
    private static String attestation(Chains ch, int status, byte[] body, Block block) {
        return attestation(ch, "payment", status, body, block);
    }

    /**
     * The same, over what orders sent addressed to {@code rcv}: payment, or one of its operations. orders acts on
     * influence, so its own block names it with what it added.
     */
    private static String attestation(Chains ch, String rcv, int status, byte[] body, Block block) {
        List<Stamp> sent = new Stamper("orders", "ord-1", ch.fx.privateKey("orders"), false, () -> RID,
                () -> ORDERS_TS).next(ch.toOrders, rcv, RequestBinding.compute("POST", "/pay", PAY),
                Influence.block(OWNED, List.of()), null).chain();
        Stamp stamp = new Stamper("payment", "pay-1", ch.fx.privateKey("payment"), false, () -> RID,
                () -> RESPONSE_TS).respond(sent, HttpWire.resultHash(status, body), RID, block);
        return HttpWire.encodeResponse(stamp, block);
    }

    /** verification.md, a response at the caller, and influence.md, Content labels: what a response adds. */
    private static ArrayNode callerInfluence(Chains ch) {
        List<ContentLabel> labels = List.of(new ContentLabel(InfluenceClass.PRIVATE, "cid-receipt-1", "alice"),
                new ContentLabel(InfluenceClass.PUBLIC, "cid-terms-1", null));
        Block labelled = ContentLabel.block(labels, List.of());
        String ok = attestation(ch, 200, PAID, labelled);
        String okHash = HttpWire.resultHash(200, PAID);
        String uri = "https://payment/pay";
        List<InfluenceEntry> fromLabels = List.of(
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:payment", okHash, "cid-receipt-1", "alice"),
                new InfluenceEntry(InfluenceClass.PUBLIC, "http:payment", okHash, "cid-terms-1", null));
        List<InfluenceEntry> untrusted = List.of(untrusted(okHash));
        ArrayNode a = arr();
        a.add(callerCase("each label becomes an entry", true, Map.of(), uri, 200, ok, PAID, ch)
                .set("expected", callerExpected("OK", false, fromLabels)));
        a.add(callerCase("the receiver's policy name, by configuration", true, Map.of("pay.internal", "payment"),
                "https://pay.internal:8443/pay", 200, ok, PAID, ch)
                .set("expected", callerExpected("OK", false, fromLabels)));
        a.add(callerCase("verified, naming influence with no labels, adds nothing", true, Map.of(), uri, 200,
                attestation(ch, 200, PAID, ContentLabel.block(List.of(), List.of())), PAID, ch)
                .set("expected", callerExpected("OK", false, List.of())));
        // A response that verifies but whose block does not name influence says nothing of what it holds.
        a.add(callerCase("silent: verified, its block not naming influence", true, Map.of(), uri, 200,
                attestation(ch, 200, PAID, Block.EMPTY), PAID, ch)
                .set("expected", callerExpected("OK", false, untrusted)));
        // An item that is not a label beside one that is; none of them is believed.
        Block mixed = Block.of(Map.of(Influence.NAME, List.of(labels.get(0).toJson(), fromLabels.get(1).toJson())),
                List.of(Influence.NAME));
        a.add(callerCase("verified, a label beside an entry", true, Map.of(), uri, 200,
                attestation(ch, 200, PAID, mixed), PAID, ch)
                .set("expected", callerExpected("OK", false, untrusted)));
        // The first case's response, its block also requiring an extension the caller does not act on.
        a.add(callerCase("refused at check 9c", true, Map.of(), uri, 200,
                attestation(ch, 200, PAID, ContentLabel.block(labels, List.of(EXAMPLE))), PAID, ch)
                .set("expected", callerExpected("EXTENSION_REQUIRED", true, untrusted)));
        a.add(callerCase("unattested", true, Map.of(), uri, 200, null, PAID, ch).set("expected",
                callerExpected("CHAIN_MISSING", false, untrusted)));
        String hash500 = HttpWire.resultHash(500, PAID);
        a.add(callerCase("failing: the attestation is for another status", true, Map.of(), uri, 500, ok, PAID, ch)
                .set("expected", callerExpected("BINDING_MISMATCH", false, List.of(untrusted(hash500)))));
        byte[] refusalBody = utf8("{\"reason\":\"BAD_SIGNATURE\"}");
        a.add(callerCase("a refusal", true, Map.of(), uri, 403, null, refusalBody, ch).set("expected",
                callerExpected("CHAIN_MISSING", false, List.of(untrusted(HttpWire.resultHash(403, refusalBody))))));
        a.add(callerCase("a caller with no verifier checks nothing", false, Map.of(), uri, 200, ok, PAID, ch)
                .set("expected", callerExpected(null, false, untrusted)));
        // A caller that holds payment's table names the operation in its stamp; the source stays the service.
        String pay = "payment#pay";
        a.add(callerCase("an operation named: the source is the service", "shop-operations", List.of("shared"), true,
                Map.of(), uri, 200, attestation(ch, pay, 200, PAID, labelled), PAID, ch)
                .set("expected", callerExpected(pay, "OK", false, fromLabels)));
        a.add(callerCase("an operation named, unattested: the source is the service", "shop-operations",
                List.of("shared"), true, Map.of(), uri, 200, null, PAID, ch)
                .set("expected", callerExpected(pay, "CHAIN_MISSING", false, untrusted)));
        return a;
    }

    private static InfluenceEntry untrusted(String hash) {
        return new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:payment", hash, null, null);
    }

    /** Runs one caller case: the caller's settings are in its verifier where it has one, and given otherwise. */
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
        List<OperationTable> tables = new ArrayList<>();
        s.get("operations").forEach(t -> tables.add(
                OperationTable.read(fx.http.get("operations").get(t.asText()).get("file").asText())));
        HttpCaller.Builder b = HttpCaller.builder(svc, stamper).bundle(m.bundle(svc)).receivers(receivers)
                .operations(tables);
        if (s.get("verifier").asBoolean()) {
            b.verifier(new Verifier(VerifierConfig.pinned(List.of(m.keyring()), List.of(m.root()), m.policyKey(),
                    now, textSet(c.get("allowedOrigins")), "", new InMemoryNonceCache(c.get("nonceTtlMs").asLong()),
                    () -> now, c.get("callMaxAgeMs").asLong(), c.get("runMaxAgeMs").asLong(), settings(c))));
        } else {
            b.extensions(settings(c));
        }
        HttpCaller caller = b.build();
        JsonNode call = c.get("call");
        HttpCaller.Outbound sent = caller.stamp(call.get("method").asText(), URI.create(call.get("uri").asText()),
                unhex(call.get("body")), stamps(c.get("inbound")), Block.parseAll(Vectors.text(c.get("inboundBlocks"))),
                entries(c.get("added")));
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
        e.put("refused", received.refused());
        e.set("influence", entriesJson(received.influence()));
        return e;
    }

    // --- Replay ---

    /** Replays every kind in {@code rules}. */
    static void assertAll(JsonNode rules, JsonNode http, JsonNode core) {
        Fixtures fx = new Fixtures(rules, http, core);
        for (String kind : List.of("requests", "influenceItems", "servedUnverified", "attestation", "refusals",
                "trustedRecord")) {
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
