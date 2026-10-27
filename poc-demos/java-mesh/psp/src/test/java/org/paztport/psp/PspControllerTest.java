// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.spring.PaztportContext;
import org.paztport.spring.PublicWrites;
import org.springframework.http.ResponseEntity;

// The influence a hijacked assistant's refund carries: a ticket's untrusted text beside alice's order.
class PspControllerTest {

    private CardRecords records;
    private PspController controller;

    @BeforeEach
    void alicePaidForOrder123() {
        records = new CardRecords();
        records.charge("alice", "123", "4242 4242 4242 4242", true);
        controller = new PspController(records, new PublicWrites("psp"));
    }

    private static final InfluenceEntry TICKET =
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", null, null);

    private ResponseEntity<Map<String, String>> refundAfterTicket(String order, String card) {
        return refundWith(order, card, TICKET,
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", null, "alice"));
    }

    private ResponseEntity<Map<String, String>> refundWith(String order, String card, InfluenceEntry... influence) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.addInfluence(influence);
            return controller.refund(new PspController.Refund(order, card));
        }
    }

    @Test
    void refundToTheOriginalCardIsRefunded() {
        ResponseEntity<Map<String, String>> byOrder = refundAfterTicket("123", null);
        assertEquals(200, byOrder.getStatusCode().value());
        assertEquals(Map.of("status", "REFUNDED"), byOrder.getBody());

        ResponseEntity<Map<String, String>> byCard = refundAfterTicket("123", "4242-4242-4242-4242");
        assertEquals(200, byCard.getStatusCode().value());
        assertEquals(Map.of("status", "REFUNDED"), byCard.getBody());
    }

    @Test
    void refundToAnUnknownCardIsDenied() {
        ResponseEntity<Map<String, String>> response = refundAfterTicket("123", "4000 0000 0000 0002");
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "INFLUENCE_DENIED"), response.getBody());
    }

    // A ticket that reads nobody's private data shapes the refund only with untrusted text, which the rule lets
    // through: who may receive the money is the PSP's own question, and a card nobody paid with is not the payer's.
    @Test
    void refundShapedByNoPrivateDataToAnUnknownCardIsNotThePayers() {
        ResponseEntity<Map<String, String>> response = refundWith("123", "4000 0000 0000 0002", TICKET);
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "NOT_PAYER"), response.getBody());
    }

    // Mallory's ticket reads only her own history, so the rule passes a refund to her own card; it did not pay
    // for alice's order.
    @Test
    void refundToAnotherCustomersCardIsNotThePayers() {
        records.charge("mallory", "456", "4000 0000 0000 0002", true);
        ResponseEntity<Map<String, String>> response = refundWith("123", "4000 0000 0000 0002", TICKET,
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", null, "mallory"));
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "NOT_PAYER"), response.getBody());
    }

    @Test
    void refundOfAnOrderWithNoChargeIsNotThePayers() {
        records.charge("mallory", "456", "4000 0000 0000 0002", false);
        ResponseEntity<Map<String, String>> response = refundWith("789", "4242 4242 4242 4242", TICKET);
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "NOT_PAYER"), response.getBody());
    }

    @Test
    void honestRefundShapedOnlyByTheTicketIsRefunded() {
        ResponseEntity<Map<String, String>> response = refundWith("123", null, TICKET);
        assertEquals(200, response.getStatusCode().value());
        assertEquals(Map.of("status", "REFUNDED"), response.getBody());
    }

    @Test
    void unknownOrderHasNoCharge() {
        ResponseEntity<Map<String, String>> response = refundAfterTicket("999", null);
        assertEquals(404, response.getStatusCode().value());
        assertEquals(Map.of("reason", "NO_CHARGE"), response.getBody());
    }

    // No verified chain here, as in an unsafe session: the charge is taken but makes no card anyone's. (A verified
    // chain with untrusted influence registers nothing either; the SDK's trusted-record question is tested there.)
    @Test
    void unverifiedChargeIsTakenButRegistersNothing() {
        ResponseEntity<Map<String, String>> response;
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            response = controller.charge(new PspController.Charge("mallory", "456", "4000 0000 0000 0002", 40L));
        }
        assertEquals(200, response.getStatusCode().value());
        assertEquals(Map.of("status", "CHARGED"), response.getBody());
        assertNull(records.ownerOf("4000000000000002"));
        assertNull(records.cardFor("456"));
    }
}
