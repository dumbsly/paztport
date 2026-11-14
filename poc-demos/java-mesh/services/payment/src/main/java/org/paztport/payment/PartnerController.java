// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import java.util.Map;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.boundary.RequirementUnmetException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Payment as the shop's egress: charges and refunds go on to the PSP, another organisation, through the
 * {@link BoundaryClient}, which is the only way out. The body goes on unchanged, so what the shop's chain bound is
 * what the PSP is asked to do, and the PSP's answer comes back as it is.
 *
 * <p>Payment verifies every request in enforce mode, so a handler here runs only for a chain that verified; the
 * boundary client signs nothing over anything else. Without a configured partner there is nowhere to send these.
 *
 * <p>Payment requires {@code influence} of the PSP ({@code paztport.boundary.requires}), so that what the shop's
 * chain read reaches the PSP's rule. When the PSP's session does not give it, the egress withholds the call, and the
 * answer is {@code 502 EXTENSION_REQUIRED}: the PSP was not asked, and asking again in the same session would be
 * withheld the same way.
 */
@RestController
public class PartnerController {

    private final ObjectProvider<BoundaryClient> boundary;

    public PartnerController(ObjectProvider<BoundaryClient> boundary) {
        this.boundary = boundary;
    }

    @PostMapping("/charge")
    public ResponseEntity<?> charge(@RequestBody(required = false) byte[] body) {
        return relay("/charge", body);
    }

    @PostMapping("/refund")
    public ResponseEntity<?> refund(@RequestBody(required = false) byte[] body) {
        return relay("/refund", body);
    }

    private ResponseEntity<?> relay(String path, byte[] body) {
        BoundaryClient client = boundary.getIfAvailable();
        if (client == null) {
            return ResponseEntity.status(503).body(Map.of("reason", "NO_PARTNER"));
        }
        BoundaryClient.Response response;
        try {
            response = client.post(path, body == null ? new byte[0] : body);
        } catch (RequirementUnmetException e) {
            return ResponseEntity.status(502).body(Map.of("reason", ReasonCode.EXTENSION_REQUIRED.name()));
        }
        return ResponseEntity.status(response.status())
                .contentType(MediaType.APPLICATION_JSON)
                .body(response.body());
    }
}
