// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.Jcs;
import org.paztport.core.influence.Influence;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;

/**
 * Every wire object in {@code v3.json} that has an SDK value type is read by that type and written back, and the
 * JCS of what comes back is the JCS of what went in. This pins the JSON forms while the public API changes from
 * Jackson trees to JSON text: the cases and their outcomes stay fixed, and only the adapters at the bottom follow
 * the API.
 *
 * <p>An object is one of three things. Most round-trip exactly. A few are refused, being the vectors' deliberately
 * malformed inputs. The rest are normalised: an extra field dropped, or a number written {@code 1798761600000.0} read
 * by value and written back as plain digits; writing those back again changes nothing. Each object is read from its own
 * text in the file, so two that differ only in how they are written are two cases. A whole session reply has no reader
 * in the SDK, since the client checks a reply as received, so a reply is built here from its fields and written back
 * with {@code SessionReply.toJson()}, which pins the reply's wire form as well.
 */
class JsonTextRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The objects the readers refuse, by case. */
    private static final Set<String> REFUSED = Set.of(
            "keyring/no notAfter",
            "keyring/notAfter 2^53",
            "keyring/notAfter not an integer",
            "root/no notAfter",
            "root/notAfter 2^53",
            "root/notAfter not an integer",
            // The whole replies refused are exactly the vectors' MALFORMED_REPLY cases.
            "sessionReply/notAfter not an integer/reply",
            "sessionReply/server root notAfter dropped/reply",
            "sessionReply/server root notAfter not an integer/reply",
            "sessionReply/serverKeyringNotAfter dropped/reply",
            "sessionReply/serverKeyringNotAfter not an integer/reply",
            "sessionReply/serverKeyringNotAfter null/reply",
            "sessionReply/serverKeyringSig null/reply",
            "sessionReply/serverReplyCert null/reply",
            "sessionReply/notAfter not an integer/reply/serverReplyCert",
            "sessionReply/server root notAfter dropped/reply/serverRoot",
            "sessionReply/server root notAfter not an integer/reply/serverRoot",
            "sessionReply/serverReplyCert null/reply/serverReplyCert",
            "verify/non-string rcv/1",
            "verify/rcv holding the delimiter/1",
            "verify/stamp ts of -2^63/1",
            "verify/v3 stamp with no rcv/1");

    /** The objects that come back normalised, by case. */
    private static final Set<String> NORMALISED = Set.of(
            "keyring/notAfter written 1798761600000.0",
            "replyCert/an extra field is ignored",
            "root/notAfter written 1798761600000.0",
            "sessionReply/entry named in the reply is ignored/reply");

    /** How many distinct objects of each kind are checked, so a case can't silently fall out of the walk. */
    private static final Map<Kind, Integer> CASES = Map.of(Kind.KEYRING, 13, Kind.ROOT, 26, Kind.PROOF, 5,
            Kind.STAMP, 18, Kind.INFLUENCE, 9, Kind.REQUEST, 7, Kind.CERT, 12, Kind.REPLY, 36);

    private enum Outcome { SAME, NORMALISED, REFUSED }

    @Test
    void everyWireObjectRoundTrips() throws IOException {
        Map<String, Case> cases = cases(Vectors.load("v3.json"));
        Set<String> refused = new TreeSet<>();
        Set<String> normalised = new TreeSet<>();
        for (Case c : cases.values()) {
            switch (outcome(c)) {
                case REFUSED -> refused.add(c.name());
                case NORMALISED -> normalised.add(c.name());
                case SAME -> { }
            }
        }
        assertEquals(new TreeSet<>(REFUSED), refused, "refused");
        assertEquals(new TreeSet<>(NORMALISED), normalised, "normalised");
        Map<Kind, Integer> counts = new EnumMap<>(Kind.class);
        cases.values().forEach(c -> counts.merge(c.kind(), 1, Integer::sum));
        assertEquals(CASES, counts, "objects checked");
    }

    private static Outcome outcome(Case c) {
        String back;
        try {
            back = c.kind().roundTrip.apply(c.json());
        } catch (IllegalArgumentException e) {
            return Outcome.REFUSED;
        }
        byte[] wrote = jcs(back);
        if (same(c.json(), wrote)) {
            return Outcome.SAME;
        }
        assertArrayEquals(wrote, jcs(c.kind().roundTrip.apply(back)), c.name() + ": written again");
        return Outcome.NORMALISED;
    }

    private static boolean same(String json, byte[] wrote) {
        try {
            return Arrays.equals(jcs(json), wrote);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private record Case(String name, Kind kind, String json) {
    }

    /**
     * Each object once, named by where it first appears; the same object reached from another case is the same
     * check.
     */
    private static Map<String, Case> cases(JsonNode v) {
        Map<String, Case> out = new LinkedHashMap<>();
        Set<String> seen = new TreeSet<>();
        for (JsonNode c : v.get("keyring")) {
            add(out, seen, Kind.KEYRING, "keyring/" + c.get("name").textValue(), c.get("signed"));
        }
        for (JsonNode c : v.get("root")) {
            add(out, seen, Kind.ROOT, "root/" + c.get("name").textValue(), c.get("signed"));
        }
        v.get("policies").properties().forEach(p -> p.getValue().get("proofs").properties().forEach(
                q -> add(out, seen, Kind.PROOF, "policies/" + p.getKey() + "/" + q.getKey(), q.getValue())));
        for (String section : List.of("verify", "offline")) {
            for (JsonNode c : v.get(section)) {
                JsonNode chain = c.get("chain");
                for (int i = 0; chain.isArray() && i < chain.size(); i++) {
                    // A stamp whose v is not 3 is only ever read; nothing writes one.
                    if (chain.get(i).path("v").asInt() == 3) {
                        add(out, seen, Kind.STAMP, section + "/" + c.get("name").textValue() + "/" + i,
                                chain.get(i));
                    }
                }
            }
        }
        for (JsonNode c : v.get("influence")) {
            add(out, seen, Kind.INFLUENCE, "influence/" + c.get("name").textValue() + "/entries", c.get("entries"));
            add(out, seen, Kind.INFLUENCE, "influence/" + c.get("name").textValue() + "/normalized",
                    c.get("normalized"));
        }
        for (String section : List.of("verify", "offline")) {
            for (JsonNode c : v.get(section)) {
                add(out, seen, Kind.INFLUENCE, section + "/" + c.get("name").textValue() + "/influence",
                        c.get("influence"));
            }
        }
        for (JsonNode c : v.get("replyCert")) {
            add(out, seen, Kind.CERT, "replyCert/" + c.get("name").textValue(), c.get("cert"));
        }
        for (String section : List.of("sessionReply", "sessionStatus")) {
            for (JsonNode c : v.get(section)) {
                String name = section + "/" + c.get("name").textValue();
                JsonNode req = c.get("request");
                add(out, seen, Kind.REQUEST, name + "/request", req);
                if (req.path("clientRoot").isObject()) {
                    add(out, seen, Kind.ROOT, name + "/request/clientRoot", req.get("clientRoot"));
                }
                JsonNode reply = c.path("reply");
                if (!reply.isMissingNode()) {
                    add(out, seen, Kind.REPLY, name + "/reply", reply);
                }
                if (reply.path("serverRoot").isObject()) {
                    add(out, seen, Kind.ROOT, name + "/reply/serverRoot", reply.get("serverRoot"));
                }
                if (reply.has("serverReplyCert")) {
                    add(out, seen, Kind.CERT, name + "/reply/serverReplyCert", reply.get("serverReplyCert"));
                }
                if (c.path("serverRoot").isObject()) {
                    add(out, seen, Kind.ROOT, name + "/serverRoot", c.get("serverRoot"));
                }
                if (c.path("serverKeyring").isObject()) {
                    add(out, seen, Kind.KEYRING, name + "/serverKeyring", c.get("serverKeyring"));
                }
            }
        }
        return out;
    }

    private static void add(Map<String, Case> out, Set<String> seen, Kind kind, String name, JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return;
        }
        String json = Vectors.json(node);
        if (seen.add(kind + " " + json) && out.put(name, new Case(name, kind, json)) != null) {
            throw new IllegalStateException("two objects named " + name);
        }
    }

    // --- Adapters: JSON text in, JSON text out, through each value type's own reader and writer. ---

    private enum Kind {
        KEYRING(json -> KeyringFile.parse(json).toJson()),
        ROOT(json -> SignedRoot.parse(json).toJson()),
        PROOF(json -> MerkleProof.parse(json).toJson()),
        STAMP(json -> {
            ParsedChain parsed = Chains.parse("[" + json + "]");
            if (!parsed.ok()) {
                throw new IllegalArgumentException(parsed.failure().name());
            }
            return parsed.stamps().get(0).toJson();
        }),
        INFLUENCE(json -> Influence.toJson(Influence.parse(json))),
        REQUEST(json -> SessionRequest.parse(json).toJson()),
        CERT(json -> ReplyCert.parse(json).toJson()),
        REPLY(json -> reply(json).toJson());

        final UnaryOperator<String> roundTrip;

        Kind(UnaryOperator<String> roundTrip) {
            this.roundTrip = roundTrip;
        }
    }

    /**
     * A session reply built from its wire form, for the round trip only. The SDK has no reply reader, since the
     * client checks a reply as received, so the fields are read here; a root and a certificate go through their
     * own readers, and anything not shaped like a reply is refused, a keyring signature without its window included.
     */
    private static SessionReply reply(String json) {
        JsonNode r = exact(json);
        if (!r.isObject()) {
            throw new IllegalArgumentException("not an object");
        }
        if (r.has("serverKeyringSig") && !r.has("serverKeyringNotAfter")) {
            throw new IllegalArgumentException("a keyring signature without its window");
        }
        JsonNode root = r.path("serverRoot");
        Map<String, String> ring = new LinkedHashMap<>();
        r.path("serverKeyring").properties().forEach(e -> ring.put(e.getKey(), text(e.getValue())));
        List<String> disabled = new ArrayList<>();
        r.path("disabled").forEach(d -> disabled.add(text(d)));
        return new SessionReply(root.isNull() ? null : SignedRoot.parse(Vectors.json(root)),
                text(r.get("serverPolicyKey")), ring, optionalText(r, "serverKeyringSig"),
                r.has("serverKeyringNotAfter") ? notAfter(r.get("serverKeyringNotAfter")) : null,
                r.has("serverReplyCert") ? ReplyCert.parse(Vectors.json(r.get("serverReplyCert"))) : null,
                text(r.get("nonce")), text(r.get("sess")), text(r.get("status")), disabled, optionalText(r, "sig"));
    }

    /** The reply's tree, each part keeping its own text, so a root or certificate reaches its reader as written. */
    private static JsonNode exact(String json) {
        try {
            return Vectors.read(json);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static String text(JsonNode n) {
        if (n == null || !n.isTextual()) {
            throw new IllegalArgumentException("not a string: " + n);
        }
        return n.textValue();
    }

    private static String optionalText(JsonNode o, String name) {
        return o.has(name) ? text(o.get(name)) : null;
    }

    private static Long notAfter(JsonNode n) {
        Long v = JsonIntegers.notAfter(n);
        if (v == null) {
            throw new IllegalArgumentException("not a notAfter: " + n);
        }
        return v;
    }

    private static byte[] jcs(String json) {
        return Jcs.bytes(json);
    }

    private static JsonNode tree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
