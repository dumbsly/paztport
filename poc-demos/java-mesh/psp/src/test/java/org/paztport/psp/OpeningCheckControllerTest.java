// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.springframework.http.MediaType;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

// The shop's side is played here by the SDK: it reduces its originals to what the PSP receives, and opens one
// group the way the egress's client does, from the same key, rid, partner and group.
class OpeningCheckControllerTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String RID = "rid-1";
    private static final List<InfluenceEntry> ORIGINALS = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", "cid-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", "cid-2", "alice"));

    private final byte[] shopKey = Crypto.randomBytes(BoundaryInfluence.KEY_LENGTH);
    private final ReceivedInfluence received = new ReceivedInfluence();
    private MockMvc mvc;

    @BeforeEach
    void theCallArrived() {
        received.record(RID, BoundaryInfluence.reduce(ORIGINALS, shopKey, RID, "psp", "payment"));
        mvc = MockMvcBuilders.standaloneSetup(new OpeningCheckController(received)).build();
    }

    private BoundaryInfluence.Opening aliceOpening(List<InfluenceEntry> originals) {
        List<InfluenceEntry> group = originals.stream()
                .filter(e -> e.cls() == InfluenceClass.PRIVATE && Objects.equals(e.owner(), "alice")).toList();
        byte[] salt = BoundaryInfluence.salt(shopKey, RID, "psp", InfluenceClass.PRIVATE, "alice");
        return new BoundaryInfluence.Opening(InfluenceClass.PRIVATE, "alice", Base64Url.encode(salt), group);
    }

    private ResultActions check(String rid, String body) throws Exception {
        return mvc.perform(post("/debug/check-opening").param("rid", rid)
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    /** The opening's JCS text with one string member set, as a shop misstating it would send it. */
    private static String with(BoundaryInfluence.Opening opening, String field, String value) throws Exception {
        return jcs(((ObjectNode) JSON.readTree(opening.toJson())).put(field, value));
    }

    /** The opening's JCS text without one member. */
    private static String without(BoundaryInfluence.Opening opening, String field) throws Exception {
        return jcs(((ObjectNode) JSON.readTree(opening.toJson())).without(field));
    }

    /** The object's members in name order, compact: the JCS text of an object whose names and strings are ASCII. */
    private static String jcs(ObjectNode object) {
        ObjectNode sorted = JSON.createObjectNode();
        new TreeSet<>(names(object)).forEach(n -> sorted.set(n, object.get(n)));
        return sorted.toString();
    }

    private static List<String> names(ObjectNode object) {
        List<String> names = new ArrayList<>();
        object.fieldNames().forEachRemaining(names::add);
        return names;
    }

    @Test
    void aGenuineOpeningOpens() throws Exception {
        check(RID, aliceOpening(ORIGINALS).toJson())
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":true}", JsonCompareMode.STRICT));
    }

    @Test
    void aTamperedOpeningDoesNotOpen() throws Exception {
        List<InfluenceEntry> tampered = List.of(ORIGINALS.get(0),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", Base64Url.encode(new byte[32]), "cid-2",
                        "alice"));
        check(RID, aliceOpening(tampered).toJson())
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":false}", JsonCompareMode.STRICT));
    }

    @Test
    void anUnknownRidOrGroupIsNotFound() throws Exception {
        check("rid-2", aliceOpening(ORIGINALS).toJson()).andExpect(status().isNotFound());
        check(RID, with(aliceOpening(ORIGINALS), "owner", "bob")).andExpect(status().isNotFound());
    }

    @Test
    void anObjectThatIsNotAnOpeningDoesNotOpen() throws Exception {
        String[] notOpenings = {
            with(aliceOpening(ORIGINALS), "salt", "AAAA"),
            with(aliceOpening(ORIGINALS), "extra", "member"),
            without(aliceOpening(ORIGINALS), "salt"),
            without(aliceOpening(ORIGINALS), "originals"),
            "{}"
        };
        for (String body : notOpenings) {
            check(RID, body).andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(content().json("{\"opens\":false}", JsonCompareMode.STRICT));
        }
    }

    /** An opening with a member it does not define is canonical, so it is read and does not open. */
    @Test
    void anOpeningWithAnExtraMemberDoesNotOpen() throws Exception {
        check(RID, with(aliceOpening(ORIGINALS), "extra", "member")).andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().json("{\"opens\":false}", JsonCompareMode.STRICT));
    }

    /** An opening pasted with its whitespace is not the JCS bytes, so it is malformed, not a non-opening. */
    @Test
    void aPrettyPrintedOpeningIsMalformed() throws Exception {
        String pretty = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(
                JSON.readTree(aliceOpening(ORIGINALS).toJson()));
        check(RID, pretty).andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
    }

    /** The same members in the order the SDK's own readers refuse are malformed too. */
    @Test
    void anOpeningInWireMemberOrderIsMalformed() throws Exception {
        String wireOrder = JSON.readTree(aliceOpening(ORIGINALS).toJson()).toString();
        String reordered = "{\"salt\":" + JSON.readTree(wireOrder).get("salt") + "," + wireOrder.substring(1);
        check(RID, reordered).andExpect(status().isBadRequest())
                .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
    }

    /** Only a valid opening is looked up by {@code rid}; an invalid one is answered whatever the rid. */
    @Test
    void anInvalidOpeningForAnUnknownRidDoesNotOpen() throws Exception {
        check("rid-2", "{}").andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":false}", JsonCompareMode.STRICT));
        check("rid-2", with(aliceOpening(ORIGINALS), "extra", "member")).andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":false}", JsonCompareMode.STRICT));
    }

    /** An empty body, a whitespace-only one, and no body at all are malformed, not a framework refusal. */
    @Test
    void anEmptyBodyIsABadRequest() throws Exception {
        for (String body : List.of("", " \n")) {
            check(RID, body).andExpect(status().isBadRequest())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
        }
        mvc.perform(post("/debug/check-opening").param("rid", RID).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
    }

    /** Without a body the content type is still checked: only JSON is taken. */
    @Test
    void aBodilessRequestOfAnotherContentTypeIsUnsupported() throws Exception {
        mvc.perform(post("/debug/check-opening").param("rid", RID).contentType(MediaType.TEXT_PLAIN))
                .andExpect(status().isUnsupportedMediaType());
        mvc.perform(post("/debug/check-opening").param("rid", RID))
                .andExpect(status().isUnsupportedMediaType());
    }

    /** A canonical value that is not one JSON object is a malformed opening. */
    @Test
    void aValueThatIsNotAnObjectIsMalformed() throws Exception {
        for (String body : List.of("[]", "42", "\"text\"", "true", "null")) {
            check(RID, body).andExpect(status().isBadRequest())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
        }
    }

    @Test
    void aBodyOfAnotherContentTypeIsUnsupported() throws Exception {
        mvc.perform(post("/debug/check-opening").param("rid", RID)
                        .contentType(MediaType.TEXT_PLAIN).content(aliceOpening(ORIGINALS).toJson()))
                .andExpect(status().isUnsupportedMediaType());
    }

    /** The body is exactly the JCS bytes of one value: no whitespace around it, nothing after it. */
    @Test
    void aBodyIsReadStrictly() throws Exception {
        String json = aliceOpening(ORIGINALS).toJson();
        for (String body : List.of(json + " ", json + "\n", " " + json, json + " trailing, not JSON",
                json + " {\"second\":\"value\"}", json + "}")) {
            check(RID, body).andExpect(status().isBadRequest())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
        }
        for (Charset charset : List.of(StandardCharsets.UTF_16BE, StandardCharsets.UTF_16LE,
                Charset.forName("UTF-32BE"))) {
            mvc.perform(post("/debug/check-opening").param("rid", RID)
                            .contentType(MediaType.APPLICATION_JSON).content(json.getBytes(charset)))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
        }
        mvc.perform(post("/debug/check-opening").param("rid", RID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(("\uFEFF" + json).getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isBadRequest())
                .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
    }

    /** A number where the opening or one of its originals holds a string is not an opening and does not open. */
    @Test
    void aNumberWhereAStringBelongsDoesNotOpen() throws Exception {
        String json = aliceOpening(ORIGINALS).toJson();
        List<String> bad = List.of(
                json.replaceFirst("\"owner\":\"alice\"", "\"owner\":5"),
                json.replace("\"src\":\"http:orders\"", "\"src\":5"),
                json.replace("\"h\":\"b3JkZXI\"", "\"h\":7"),
                json.replace("\"cid\":\"cid-2\"", "\"cid\":0"));
        for (String body : bad) {
            assertNotEquals(json, body);
            check(RID, body).andExpect(status().isOk())
                    .andExpect(content().json("{\"opens\":false}", JsonCompareMode.STRICT));
        }
    }

    /** A number the wire form does not write, such as a negative one or one too large for a double, is malformed. */
    @Test
    void aNumberTheWireFormDoesNotWriteIsMalformed() throws Exception {
        String json = aliceOpening(ORIGINALS).toJson();
        for (String body : List.of(
                json.replaceFirst("\"owner\":\"alice\"", "\"owner\":1e400"),
                json.replace("\"h\":\"b3JkZXI\"", "\"h\":-1e400"),
                json.replace("\"h\":\"b3JkZXI\"", "\"h\":-5"),
                json.replace("\"cid\":\"cid-2\"", "\"cid\":1.5"))) {
            assertNotEquals(json, body);
            check(RID, body).andExpect(status().isBadRequest())
                    .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
        }
    }

    @Test
    void aBodyThatIsNotUtf8IsABadRequest() throws Exception {
        byte[] latin1 = aliceOpening(ORIGINALS).toJson().replace("\"alice\"", "\"al\u00efce\"")
                .getBytes(StandardCharsets.ISO_8859_1);
        mvc.perform(post("/debug/check-opening").param("rid", RID)
                        .contentType(MediaType.APPLICATION_JSON).content(latin1))
                .andExpect(status().isBadRequest())
                .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
    }

    @Test
    void aBodyThatIsNotJsonIsABadRequest() throws Exception {
        mvc.perform(post("/debug/check-opening").param("rid", RID)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"cls\":"))
                .andExpect(status().isBadRequest())
                .andExpect(content().json("{\"reason\":\"MALFORMED_OPENING\"}", JsonCompareMode.STRICT));
    }
}
