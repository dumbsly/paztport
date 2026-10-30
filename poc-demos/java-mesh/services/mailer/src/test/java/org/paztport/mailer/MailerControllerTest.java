// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.mailer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.http.PublicWrites;
import org.paztport.http.RequestContext;
import org.springframework.http.ResponseEntity;

// The influence a hijacked assistant's email carries: a ticket's untrusted text beside alice's order.
class MailerControllerTest {

    private final MailerController controller = new MailerController(
            new Recipients(Map.of("alice@shop.example", "alice", "mallory@mail.example", "mallory")),
            new PublicWrites("mailer"));

    private ResponseEntity<Map<String, String>> sendAfterTicket(String to) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.addInfluence(
                    new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:t-1", "aGFzaA", null, null),
                    new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "b3JkZXI", null, "alice"));
            return controller.send(new MailerController.Mail(to, "Order history", "order 123"));
        }
    }

    @Test
    void mailToTheOwnerIsSent() {
        ResponseEntity<Map<String, String>> response = sendAfterTicket("alice@shop.example");
        assertEquals(200, response.getStatusCode().value());
        assertEquals(Map.of("status", "SENT"), response.getBody());
    }

    @Test
    void theAddressIsTrimmedAndLowerCasedBeforeItIsLookedUp() {
        ResponseEntity<Map<String, String>> response = sendAfterTicket(" Alice@Shop.Example ");
        assertEquals(200, response.getStatusCode().value());
        assertEquals(Map.of("status", "SENT"), response.getBody());
    }

    @Test
    void mailToSomeoneElseIsDenied() {
        ResponseEntity<Map<String, String>> response = sendAfterTicket("mallory@mail.example");
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "INFLUENCE_DENIED"), response.getBody());
    }

    @Test
    void mailToAnAddressWithNoOwnerIsDenied() {
        ResponseEntity<Map<String, String>> response = sendAfterTicket("nobody@x.example");
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "INFLUENCE_DENIED"), response.getBody());
    }
}
