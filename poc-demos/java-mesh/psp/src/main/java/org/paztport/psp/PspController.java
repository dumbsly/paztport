// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import java.util.Map;
import org.paztport.core.ReasonCode;
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
 * <p>A refund sends money to a card, so it is a public write: the owner-aware rule decides it first, over the
 * influence the shop sent, with the card's owner taken from the PSP's own records and never from the request. A
 * card the records do not know has no owner, so a request shaped by someone else's private data cannot refund to
 * it. The rule judges only whose data shaped the request, though: a request that read no private data passes it
 * whatever card it names. Who may receive the money is the PSP's own business, so a refund then goes only to a
 * card held by whoever paid for the order, and is refused {@code 403 NOT_PAYER} otherwise.
 *
 * <p>A charge registers its card's owner only when the SDK says nothing untrusted shaped it, since a charge a
 * hijacked model asked for could otherwise register its own card to whoever it named.
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

    /** Always taken; it registers the card only when the shop vouched for a request no untrusted content shaped. */
    @PostMapping("/charge")
    public ResponseEntity<Map<String, String>> charge(@RequestBody Charge charge) {
        records.charge(charge.customer(), charge.order(), charge.card(), writes.shapedOnlyByTrusted());
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
        // Business, not security: the money goes back only to a card held by whoever paid for the order.
        String paid = records.cardFor(refund.order());
        String payer = paid == null ? null : records.ownerOf(paid);
        if (payer == null || !payer.equals(records.ownerOf(target))) {
            return ResponseEntity.status(403).body(Map.of("reason", "NOT_PAYER"));
        }
        return ResponseEntity.ok(Map.of("status", "REFUNDED"));
    }
}
