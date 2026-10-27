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

    private ResponseEntity<Map<String, String>> refundAfterTicket(String order, String card) {
        try (PaztportContext.Scope scope = PaztportContext.open()) {
            PaztportContext.addInfluence(
                    new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", null, null),
                    new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", null, "alice"));
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

    @Test
    void unknownOrderHasNoCharge() {
        ResponseEntity<Map<String, String>> response = refundAfterTicket("999", null);
        assertEquals(404, response.getStatusCode().value());
        assertEquals(Map.of("reason", "NO_CHARGE"), response.getBody());
    }

    // No verified chain here, as in an unsafe session: the charge is taken but makes no card anyone's.
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
