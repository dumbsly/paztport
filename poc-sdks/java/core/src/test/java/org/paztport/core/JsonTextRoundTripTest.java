// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.Influence;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.ParsedChain;

/**
 * Every wire object in {@code v3.json} that has an SDK value type is read by that type and written back; what comes
 * back is canonical text, and the value read from it is the value that went in, or the one the type normalises it
 * to. This pins the JSON forms while the public API changes from Jackson trees to JSON text: the cases and their
 * outcomes stay fixed, and only the adapters at the bottom follow the API.
 *
 * <p>An object is one of three things. Most round-trip exactly. A few are refused, being the vectors' deliberately
 * malformed inputs. Any other would be normalised, which none is: writing it back again would change nothing. A
 * session request or reply is read from the token its case carries, as received; every other object from the JCS
 * text of its value, or, for a value no JSON value holds, from the text Jackson gives it, which its reader refuses as
 * it refuses the value.
 */
class JsonTextRoundTripTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The objects the readers refuse, by case. */
    private static final Set<String> REFUSED = Set.of(
            "keyring/no notAfter",
            "keyring/notAfter 2^53",
            "keyring/notAfter not an integer",
            // A member the certificate does not define.
            "replyCert/an extra field",
            "root/no notAfter",
            "root/notAfter 2^53",
            "root/notAfter not an integer",
            // The whole replies refused are exactly the vectors' MALFORMED_REPLY cases.
            "sessionReply/a member the reply does not have/reply",
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
    private static final Set<String> NORMALISED = Set.of();

    /** How many distinct objects of each kind are checked, so a case can't silently fall out of the walk. */
    private static final Map<Kind, Integer> CASES = Map.of(Kind.KEYRING, 12, Kind.ROOT, 22, Kind.PROOF, 5,
            Kind.STAMP, 18, Kind.INFLUENCE, 9, Kind.REQUEST, 7, Kind.CERT, 10, Kind.REPLY, 36);

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
        // What an object is written as reads back as the canonical bytes of what it holds.
        JsonReader.wireText(back);
        if (tree(back).equals(tree(c.json()))) {
            return Outcome.SAME;
        }
        assertEquals(back, c.kind().roundTrip.apply(back), c.name() + ": written again");
        return Outcome.NORMALISED;
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
                add(out, seen, Kind.REQUEST, name + "/request", Vectors.tokenText(c.get("requestToken")));
                if (req.path("clientRoot").isObject()) {
                    add(out, seen, Kind.ROOT, name + "/request/clientRoot", req.get("clientRoot"));
                }
                JsonNode reply = c.path("reply");
                if (!reply.isMissingNode()) {
                    add(out, seen, Kind.REPLY, name + "/reply", Vectors.tokenText(c.get("replyToken")));
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
        add(out, seen, kind, name, text(node));
    }

    private static void add(Map<String, Case> out, Set<String> seen, Kind kind, String name, String json) {
        if (seen.add(kind + " " + json) && out.put(name, new Case(name, kind, json)) != null) {
            throw new IllegalStateException("two objects named " + name);
        }
    }

    /**
     * The JCS text of an object's value. A value no JSON value holds (a stamp ts of &minus;2^63, a {@code notAfter}
     * of {@code 1.5}) gets the text Jackson gives it, which its reader refuses as it refuses the value.
     */
    private static String text(JsonNode node) {
        try {
            return Vectors.text(node);
        } catch (IllegalArgumentException e) {
            return node.toString();
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
        REPLY(json -> SessionReply.parse(json).toJson());

        final UnaryOperator<String> roundTrip;

        Kind(UnaryOperator<String> roundTrip) {
            this.roundTrip = roundTrip;
        }
    }

    private static JsonNode tree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
