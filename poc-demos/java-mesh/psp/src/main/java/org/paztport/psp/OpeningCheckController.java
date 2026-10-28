// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.paztport.core.BoundaryInfluence;
import org.paztport.core.InfluenceEntry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks an opening the shop shows against the entry the PSP received, so the demo can show the shop proving what
 * a blinded entry stood for, and failing to when it misstates it. Whether it opens is the SDK's question
 * ({@link BoundaryInfluence#opens}); this only finds the entry of the opening's class and owner among what
 * {@link ReceivedInfluence} recorded for the rid.
 *
 * <p>Present only when {@code paztport.openings=true}, under {@code /debug}, which the partner filter skips as
 * control plane: a demo stand-in for a dispute the PSP would settle by its own process, not part of the
 * attestation model.
 */
@RestController
@ConditionalOnProperty(name = "paztport.openings", havingValue = "true")
public class OpeningCheckController {

    private final ReceivedInfluence received;

    public OpeningCheckController(ReceivedInfluence received) {
        this.received = received;
    }

    /**
     * {@code {"opens": true|false}}; {@code 404} when no call of {@code rid} was recorded, or it carried no entry
     * of the opening's class and owner; {@code 400} for a body that is not an opening.
     */
    @PostMapping("/debug/check-opening")
    public ResponseEntity<Map<String, Object>> check(@RequestParam String rid, @RequestBody JsonNode body) {
        BoundaryInfluence.Opening opening;
        try {
            opening = BoundaryInfluence.Opening.parse(body);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("reason", "MALFORMED_OPENING"));
        }
        List<InfluenceEntry> entries = received.received(rid).orElse(null);
        if (entries == null) {
            return ResponseEntity.notFound().build();
        }
        // One entry per class and owner, so the first match is the only one.
        InfluenceEntry sent = entries.stream()
                .filter(e -> e.cls() == opening.cls() && Objects.equals(e.owner(), opening.owner()))
                .findFirst().orElse(null);
        if (sent == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("opens", BoundaryInfluence.opens(sent, opening)));
    }
}
