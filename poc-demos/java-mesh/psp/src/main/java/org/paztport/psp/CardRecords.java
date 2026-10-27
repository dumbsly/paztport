// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * The PSP's own records of who holds each card and which card paid for each order. They are the trusted source of
 * a refund's destination owner and of who paid, so they are written only from a charge the caller vouched for and
 * no untrusted content shaped: any other charge is taken but recorded nowhere, so it can never make a card
 * someone's nor become a refund target. The first owner a card is charged for keeps it, so a later charge cannot
 * claim a card that is already someone else's; and the first card an order is charged to stays its payer's, so a
 * later charge cannot re-point a refund.
 *
 * <p>Held in memory: a stand-in for the PSP's card ledger, which the demo does not build.
 */
@Component
public class CardRecords {

    private final Map<String, String> owners = new ConcurrentHashMap<>();
    private final Map<String, String> charges = new ConcurrentHashMap<>();

    /**
     * Records a charge. Only when {@code attested} does it register the card's owner and the order's card, each
     * unless already recorded; otherwise it records nothing.
     */
    public void charge(String customer, String order, String card, boolean attested) {
        if (!attested || customer == null || order == null || card == null) {
            return;
        }
        String number = normalise(card);
        owners.putIfAbsent(number, customer);
        charges.putIfAbsent(order, number);
    }

    /** The normalised card that paid for {@code order}, or null when none did in an attested session. */
    public String cardFor(String order) {
        return order == null ? null : charges.get(order);
    }

    /** The owner of {@code card} (normalised), or null when no attested charge registered one. */
    public String ownerOf(String card) {
        return card == null ? null : owners.get(card);
    }

    /** Card numbers arrive however people type them; only the digits name the card. */
    public static String normalise(String card) {
        return card.replaceAll("\\D", "");
    }
}
