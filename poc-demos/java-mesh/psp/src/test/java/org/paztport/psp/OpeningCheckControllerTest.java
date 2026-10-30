// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
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

    /** The opening's JSON with one field changed, as a shop misstating it would send it. */
    private static String with(BoundaryInfluence.Opening opening, String field, String value) throws Exception {
        return ((ObjectNode) JSON.readTree(opening.toJson())).put(field, value).toString();
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
    void aMalformedOpeningIsABadRequest() throws Exception {
        check(RID, with(aliceOpening(ORIGINALS), "salt", "AAAA")).andExpect(status().isBadRequest());
        check(RID, "[]").andExpect(status().isBadRequest());
    }

    @Test
    void aBodyOfAnotherContentTypeIsUnsupported() throws Exception {
        mvc.perform(post("/debug/check-opening").param("rid", RID)
                        .contentType(MediaType.TEXT_PLAIN).content(aliceOpening(ORIGINALS).toJson()))
                .andExpect(status().isUnsupportedMediaType());
    }

    /**
     * The body is read as it always has been: up to the end of the first JSON value, whatever follows it, and in
     * whichever Unicode encoding its first bytes show.
     */
    @Test
    void aBodyIsReadLeniently() throws Exception {
        String json = aliceOpening(ORIGINALS).toJson();
        check(RID, json + " trailing, not JSON")
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":true}", JsonCompareMode.STRICT));
        check(RID, json + " {\"second\":\"value\"}")
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":true}", JsonCompareMode.STRICT));
        for (Charset charset : List.of(StandardCharsets.UTF_16BE, StandardCharsets.UTF_16LE,
                Charset.forName("UTF-32BE"))) {
            mvc.perform(post("/debug/check-opening").param("rid", RID)
                            .contentType(MediaType.APPLICATION_JSON).content(json.getBytes(charset)))
                    .andExpect(status().isOk())
                    .andExpect(content().json("{\"opens\":true}", JsonCompareMode.STRICT));
        }
        mvc.perform(post("/debug/check-opening").param("rid", RID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(("\uFEFF" + json).getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":true}", JsonCompareMode.STRICT));
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
