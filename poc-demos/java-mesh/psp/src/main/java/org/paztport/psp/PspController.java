// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import java.util.Map;
import org.paztport.core.ReasonCode;
import org.paztport.spring.PaztportContext;
import org.paztport.spring.PublicWrites;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The PSP's API to the shop. The partner filter has already put the call in its session: in an attested one the
 * shop's boundary stamp verified and the handler sees the shop's influence and chain; in an unsafe one there is no
 * chain, and the gate has already refused {@code POST /refund}.
 *
 * <p>A refund sends money to a card, so it is a public write: the owner-aware rule decides it, over the influence
 * the shop sent, with the card's owner taken from the PSP's own records and never from the request. A card the
 * records do not know has no owner, so a request shaped by someone else's private data cannot refund to it.
 */
@RestController
public class PspController {

    /** A charge: who pays, for which order, with which card, and how much. */
    public record Charge(String customer, String order, String card, Long amount) {
    }

    /** A refund of an order's charge, to the card named, or to the card that paid when none is. */
    public record Refund(String order, String card) {
    }

    private final CardRecords records;
    private final PublicWrites writes;

    public PspController(CardRecords records, PublicWrites writes) {
        this.records = records;
        this.writes = writes;
    }

    /** Always taken; it registers the card only when the shop vouched for the request. */
    @PostMapping("/charge")
    public ResponseEntity<Map<String, String>> charge(@RequestBody Charge charge) {
        records.charge(charge.customer(), charge.order(), charge.card(), PaztportContext.verifiedChain() != null);
        return ResponseEntity.ok(Map.of("status", "CHARGED"));
    }

    @PostMapping("/refund")
    public ResponseEntity<Map<String, String>> refund(@RequestBody Refund refund) {
        String target = refund.card() != null ? CardRecords.normalise(refund.card()) : records.cardFor(refund.order());
        if (target == null || target.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("reason", "NO_CHARGE"));
        }
        if (writes.decide(records.ownerOf(target)) != ReasonCode.OK) {
            return ResponseEntity.status(403).body(Map.of("reason", ReasonCode.INFLUENCE_DENIED.name()));
        }
        return ResponseEntity.ok(Map.of("status", "REFUNDED"));
    }
}
