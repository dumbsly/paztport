// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.mailer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.http.PublicWrites;
import org.paztport.http.RequestContext;
import org.paztport.http.TestScopes;
import org.springframework.http.ResponseEntity;

// The influence a hijacked assistant's email carries: a ticket's untrusted text beside alice's order. The mailer acts
// on influence, as the demo's configuration says.
class MailerControllerTest {

    private static final ExtensionSettings INFLUENCE = ExtensionSettings.of(Set.of(Influence.NAME), null);

    private final MailerController controller = new MailerController(
            new Recipients(Map.of("alice@shop.example", "alice", "mallory@mail.example", "mallory")),
            new PublicWrites("mailer"));

    private ResponseEntity<Map<String, String>> sendAfterTicket(String to) {
        return sendAfterTicket(to, INFLUENCE);
    }

    /** Sends to {@code to} in a scope of a service with {@code settings}; null leaves the scope with none. */
    private ResponseEntity<Map<String, String>> sendAfterTicket(String to, ExtensionSettings settings) {
        try (RequestContext.Scope scope = RequestContext.open()) {
            if (settings != null) {
                TestScopes.actOn(settings);
            }
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

    // A scope opened with no settings is a service acting on nothing, which is refused every guarded write: even
    // mail to the owner is denied.
    @Test
    void mailToTheOwnerInAScopeWithNoSettingsIsDenied() {
        ResponseEntity<Map<String, String>> response = sendAfterTicket("alice@shop.example", null);
        assertEquals(403, response.getStatusCode().value());
        assertEquals(Map.of("reason", "INFLUENCE_DENIED"), response.getBody());
    }
}
