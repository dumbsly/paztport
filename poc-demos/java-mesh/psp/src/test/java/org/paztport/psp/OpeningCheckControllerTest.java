// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.BoundaryInfluence;
import org.paztport.core.Crypto;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.springframework.http.MediaType;
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

    private ResultActions check(String rid, Object body) throws Exception {
        return mvc.perform(post("/debug/check-opening").param("rid", rid)
                .contentType(MediaType.APPLICATION_JSON).content(JSON.writeValueAsString(body)));
    }

    @Test
    void aGenuineOpeningOpens() throws Exception {
        check(RID, aliceOpening(ORIGINALS).toJson())
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":true}", true));
    }

    @Test
    void aTamperedOpeningDoesNotOpen() throws Exception {
        List<InfluenceEntry> tampered = List.of(ORIGINALS.get(0),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", Base64Url.encode(new byte[32]), "cid-2",
                        "alice"));
        check(RID, aliceOpening(tampered).toJson())
                .andExpect(status().isOk())
                .andExpect(content().json("{\"opens\":false}", true));
    }

    @Test
    void anUnknownRidOrGroupIsNotFound() throws Exception {
        check("rid-2", aliceOpening(ORIGINALS).toJson()).andExpect(status().isNotFound());
        ObjectNode bob = aliceOpening(ORIGINALS).toJson().put("owner", "bob");
        check(RID, bob).andExpect(status().isNotFound());
    }

    @Test
    void aMalformedOpeningIsABadRequest() throws Exception {
        ObjectNode shortSalt = aliceOpening(ORIGINALS).toJson().put("salt", "AAAA");
        check(RID, shortSalt).andExpect(status().isBadRequest());
        check(RID, List.of()).andExpect(status().isBadRequest());
    }
}
