// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.StamperV3;
import org.paztport.spring.outbound.PooledTlsClient;
import org.paztport.spring.partner.BoundaryClient;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

// A real egress client, which never calls out here: an opening needs only its boundary key and partner. Its
// TLS material is read on the first call, so the bundle is never read.
class OpeningControllerTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String RID = "rid-1";
    private static final List<InfluenceEntry> ORIGINALS = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", "cid-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", "cid-2", "alice"),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "aGlzdG9yeQ", "cid-3", "alice"));

    private final byte[] boundaryKey = Crypto.randomBytes(BoundaryInfluence.KEY_LENGTH);
    private final BoundaryOpenings openings = new BoundaryOpenings();
    private BoundaryClient client;
    private MockMvc mvc;

    @BeforeEach
    void start() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair payment = Crypto.generateEd25519KeyPair();
        String policyPub = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("payment", "psp")), 4,
                NOT_AFTER, policy.getPrivate());
        KeyringFile keyring = KeyringFile.sign(
                Map.of("payment", Base64Url.encode(Crypto.encodePublicKey(payment.getPublic()))), policyPub, NOT_AFTER,
                policy.getPrivate());
        client = new BoundaryClient(
                new StamperV3("payment", "payment-1", payment.getPrivate(), false, () -> "unused",
                        System::currentTimeMillis),
                built.bundles().get("payment"), built.signedRoot(), keyring, policyPub, "psp",
                URI.create("https://psp:8080"), policyPub, boundaryKey, openings,
                PooledTlsClient.of(SslBundle.of(null)), 600_000);
        StaticListableBeanFactory beans = new StaticListableBeanFactory(Map.of("client", client));
        mvc = MockMvcBuilders.standaloneSetup(
                new OpeningController(openings, beans.getBeanProvider(BoundaryClient.class), "psp")).build();
        // As the egress tells its listener before an attested call goes.
        openings.sent(RID, "psp", ORIGINALS, sent());
    }

    @AfterEach
    void stop() {
        client.close();
    }

    /** What the PSP received for the call: the reduced list, built from the originals as the egress builds it. */
    private List<InfluenceEntry> sent() {
        return BoundaryInfluence.reduce(ORIGINALS, boundaryKey, RID, "psp", "payment");
    }

    private InfluenceEntry sentFor(InfluenceClass cls, String owner) {
        return sent().stream().filter(e -> e.cls() == cls && Objects.equals(e.owner(), owner))
                .findFirst().orElseThrow();
    }

    /** The opening served for {@code query}, which must be JSON in exactly the SDK's own rendering of it. */
    private BoundaryInfluence.Opening fetch(String query) throws Exception {
        String body = mvc.perform(get("/debug/boundary-opening?" + query))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString();
        BoundaryInfluence.Opening opening = BoundaryInfluence.Opening.parse(JSON.readTree(body));
        assertEquals(opening.toJson().toString(), body);
        return opening;
    }

    @Test
    void theOpeningOpensTheEntryThePartnerHolds() throws Exception {
        BoundaryInfluence.Opening alice = fetch("rid=" + RID + "&cls=private&owner=alice");
        assertEquals(2, alice.originals().size());
        assertTrue(BoundaryInfluence.opens(sentFor(InfluenceClass.PRIVATE, "alice"), alice));

        BoundaryInfluence.Opening ticket = fetch("rid=" + RID + "&cls=third-party");
        assertTrue(BoundaryInfluence.opens(sentFor(InfluenceClass.THIRD_PARTY, null), ticket));
        // One group's opening opens only its own entry.
        assertFalse(BoundaryInfluence.opens(sentFor(InfluenceClass.PRIVATE, "alice"), ticket));
    }

    @Test
    void aTamperedOpeningOpensNothing() throws Exception {
        BoundaryInfluence.Opening tampered = fetch("rid=" + RID + "&cls=private&owner=alice&tamper=true");
        assertEquals(Base64Url.encode(new byte[32]), tampered.originals().get(0).h());
        assertFalse(BoundaryInfluence.opens(sentFor(InfluenceClass.PRIVATE, "alice"), tampered));
    }

    @Test
    void anUnknownRidOrGroupIsNotFound() throws Exception {
        mvc.perform(get("/debug/boundary-opening?rid=rid-2&cls=private&owner=alice"))
                .andExpect(status().isNotFound());
        mvc.perform(get("/debug/boundary-opening?rid=" + RID + "&cls=private&owner=mallory"))
                .andExpect(status().isNotFound());
        mvc.perform(get("/debug/boundary-opening?rid=" + RID + "&cls=private"))
                .andExpect(status().isNotFound());
    }

    @Test
    void anUnknownClassIsABadRequest() throws Exception {
        mvc.perform(get("/debug/boundary-opening?rid=" + RID + "&cls=secret&owner=alice"))
                .andExpect(status().isBadRequest());
    }
}
