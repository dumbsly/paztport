// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
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
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;
import org.paztport.core.stamp.StampV3;

/**
 * Every wire object in {@code v3.json} that has an SDK value type is read by that type and written back, and the
 * JCS of what comes back is the JCS of what went in. This pins the JSON forms while the public API changes from
 * Jackson trees to JSON text: the cases and their outcomes stay fixed, and only the adapters at the bottom follow
 * the API.
 *
 * <p>An object is one of three things. Most round-trip exactly. A few are refused, being the vectors' deliberately
 * malformed inputs. The rest are normalised: an extra field dropped, or a number written {@code 1798761600000.0} read
 * by value and written back as plain digits; writing those back again changes nothing. Each object is read from its own
 * text in the file, so two that differ only in how they are written are two cases. A whole session reply has no value
 * type, since the client checks it as received, so its parts (the root and certificate) are read instead.
 */
class JsonTextRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The objects the readers refuse, by case. */
    private static final Set<String> REFUSED = Set.of(
            "keyring/notAfter 2^53",
            "keyring/notAfter not an integer",
            "root/notAfter 2^53",
            "root/notAfter not an integer",
            "sessionReply/notAfter not an integer/reply/serverReplyCert",
            "sessionReply/server root notAfter not an integer/reply/serverRoot",
            "sessionReply/serverReplyCert null/reply/serverReplyCert",
            "verify/non-string rcv/1",
            "verify/rcv holding the delimiter/1",
            "verify/v3 stamp with no rcv/1");

    /** The objects that come back normalised, by case. */
    private static final Set<String> NORMALISED = Set.of(
            "keyring/notAfter written 1798761600000.0",
            "replyCert/an extra field is ignored",
            "root/notAfter written 1798761600000.0");

    /** How many distinct objects of each kind are checked, so a case can't silently fall out of the walk. */
    private static final Map<Kind, Integer> CASES = Map.of(Kind.KEYRING, 15, Kind.ROOT, 29, Kind.PROOF, 5,
            Kind.STAMP, 18, Kind.INFLUENCE, 10, Kind.REQUEST, 9, Kind.CERT, 12);

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
                    // A v2 stamp is only ever read, as legacy evidence; nothing writes one.
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
            ParsedChain parsed = Chains.parse("[" + json + "]", false);
            if (!parsed.ok()) {
                throw new IllegalArgumentException(parsed.failure().name());
            }
            return ((StampV3) parsed.stamps().get(0)).toJson();
        }),
        INFLUENCE(json -> Influence.toJson(Influence.parse(json))),
        REQUEST(json -> SessionRequest.parse(json).toJson()),
        CERT(json -> ReplyCert.parse(json).toJson());

        final UnaryOperator<String> roundTrip;

        Kind(UnaryOperator<String> roundTrip) {
            this.roundTrip = roundTrip;
        }
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
