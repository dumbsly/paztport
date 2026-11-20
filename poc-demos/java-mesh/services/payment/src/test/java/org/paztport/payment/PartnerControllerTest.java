// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.ServletException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.http.OriginIntent;
import org.paztport.http.RequestContext;
import org.paztport.http.TestScopes;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.boundary.RequirementUnmetException;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

// Payment is the shop's egress, and the hop where the gateway's facts are compared with the charge orders asks for:
// a charge that differs from them is refused before the PSP is asked, and the charge that goes on is built from the
// facts, never relayed. Payment also requires influence of the PSP, so the egress withholds a call when the PSP's
// session does not give it; only the egress makes that refusal (its constructor is the SDK's), so the client here is
// a mock that throws it.
class PartnerControllerTest {

    private static final ExtensionSettings ACTS_ON = ExtensionSettings.of(Set.of(Influence.NAME, Intent.NAME), null);
    /** What the gateway sealed for alice's purchase of order 123, which costs 100. */
    private static final IntentFacts FACTS =
            IntentFacts.builder().put("amount", 100).put("customer", "alice").put("order", "123").build();
    private static final String ALICE_CARD = "4242 4242 4242 4242";

    private final BoundaryClient client = mock(BoundaryClient.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PartnerController(
            new StaticListableBeanFactory(Map.of("client", client)).getBeanProvider(BoundaryClient.class),
            new OriginIntent("payment"))).build();

    private static String charge(String customer, String order, String card, long amount) {
        return "{\"customer\":\"" + customer + "\",\"order\":\"" + order + "\",\"card\":\"" + card + "\",\"amount\":"
                + amount + "}";
    }

    private static MockHttpServletRequestBuilder charge(String body) {
        return post("/charge").contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static MockHttpServletRequestBuilder charge() {
        return charge(charge("alice", "123", ALICE_CARD, 100));
    }

    /**
     * Performs {@code request} in a scope opened as the receiver opens one for a chain that verified here: gateway,
     * then orders, the gateway's block holding {@link #FACTS} under {@code intent}.
     */
    private ResultActions verified(MockHttpServletRequestBuilder request) throws Exception {
        List<Stamp> chain = List.of(
                Stamp.sign("gateway", "gw-1", "rid-1", 1L, "", "orders#purchase", "b", "", "",
                        Crypto.generateEd25519KeyPair().getPrivate()),
                Stamp.sign("orders", "ord-1", "rid-1", 2L, "", "payment#charge", "b", "", "",
                        Crypto.generateEd25519KeyPair().getPrivate()));
        Block origin = Block.of(Map.of(Intent.NAME, List.of(FACTS.toItem())), List.of());
        try (RequestContext.Scope scope = RequestContext.open()) {
            TestScopes.verified(chain, new HandOver(true, chain, List.of(origin, Block.EMPTY), ACTS_ON));
            return mvc.perform(request);
        }
    }

    private static BoundaryClient.Response charged() {
        return new BoundaryClient.Response(200, "{\"status\":\"CHARGED\"}".getBytes(StandardCharsets.UTF_8), true);
    }

    /** The body payment sent the PSP's {@code /charge}, as text. */
    private String sentCharge() {
        ArgumentCaptor<byte[]> sent = ArgumentCaptor.forClass(byte[].class);
        verify(client).post(eq("/charge"), sent.capture());
        return new String(sent.getValue(), StandardCharsets.UTF_8);
    }

    @Test
    void aChangedAmountIsDeniedAndThePartnerIsNotCalled() throws Exception {
        verified(charge(charge("alice", "123", ALICE_CARD, 9900)))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"reason\":\"INTENT_DENIED\"}"));

        verify(client, never()).post(any(), any());
    }

    // Payment has no order book: it compares the order as well as the amount, so a charge for another order at the
    // price the customer was shown is refused too.
    @Test
    void anotherOrderOfTheSamePriceIsDenied() throws Exception {
        verified(charge(charge("alice", "456", ALICE_CARD, 100)))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"reason\":\"INTENT_DENIED\"}"));

        verify(client, never()).post(any(), any());
    }

    // The customer is a fact too, and the PSP registers a card to the customer of its first attested charge, so a
    // charge of the same order and amount for another customer is refused.
    @Test
    void anotherCustomerIsDenied() throws Exception {
        verified(charge(charge("mallory", "123", ALICE_CARD, 100)))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"reason\":\"INTENT_DENIED\"}"));

        verify(client, never()).post(any(), any());
    }

    // The body orders sent is spelt differently, its members in another order and spaced, so a relay of its bytes
    // is told apart from a body built from the compared values.
    @Test
    void theChargeSentOnIsBuiltFromTheFacts() throws Exception {
        when(client.post(eq("/charge"), any())).thenReturn(charged());

        verified(charge("{ \"amount\": 100, \"card\": \"" + ALICE_CARD + "\", \"order\": \"123\", \"customer\": \"alice\" }"))
                .andExpect(status().isOk())
                .andExpect(content().string("{\"status\":\"CHARGED\"}"));

        assertEquals(charge("alice", "123", ALICE_CARD, 100), sentCharge());
    }

    // The card is not a fact, so a card orders changed is not one payment can tell from the customer's.
    @Test
    void aSwappedCardIsServed() throws Exception {
        when(client.post(eq("/charge"), any())).thenReturn(charged());

        verified(charge(charge("alice", "123", "4000 0000 0000 0002", 100)))
                .andExpect(status().isOk());

        assertEquals(charge("alice", "123", "4000 0000 0000 0002", 100), sentCharge());
    }

    @Test
    void aBodyThatDoesNotReadIsRefused() throws Exception {
        for (String body : List.of("not json", "{\"order\":\"123\"}",
                "{\"customer\":\"alice\",\"order\":\"123\",\"card\":\"" + ALICE_CARD + "\",\"amount\":\"lots\"}")) {
            verified(charge(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string("{\"reason\":\"BAD_CHARGE\"}"));
        }

        verify(client, never()).post(any(), any());
    }

    // A refund is not compared with any fact, so its bytes go on as they came.
    @Test
    void aRefundStillGoesOnUnchanged() throws Exception {
        String refund = "{ \"order\": \"123\" }";
        when(client.post(eq("/refund"), any())).thenReturn(
                new BoundaryClient.Response(200, "{\"status\":\"REFUNDED\"}".getBytes(StandardCharsets.UTF_8), true));

        verified(post("/refund").contentType(MediaType.APPLICATION_JSON).content(refund))
                .andExpect(status().isOk());

        ArgumentCaptor<byte[]> sent = ArgumentCaptor.forClass(byte[].class);
        verify(client).post(eq("/refund"), sent.capture());
        assertEquals(refund, new String(sent.getValue(), StandardCharsets.UTF_8));
    }

    @Test
    void aCallTheEgressWithholdsIs502ExtensionRequired() throws Exception {
        when(client.post(eq("/charge"), any())).thenThrow(RequirementUnmetException.class);

        verified(charge())
                .andExpect(status().isBadGateway())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().string("{\"reason\":\"EXTENSION_REQUIRED\"}"));
    }

    // The egress's other refusals to send are IllegalStateExceptions too, and none of them is about the PSP's
    // extensions, so none is answered as one.
    @Test
    void anotherRefusalToSendIsNotAnsweredAsAMissingExtension() {
        when(client.post(eq("/charge"), any())).thenThrow(new IllegalStateException("no session could be opened"));

        ServletException thrown = assertThrows(ServletException.class, () -> verified(charge()));
        assertInstanceOf(IllegalStateException.class, thrown.getCause());
    }
}
