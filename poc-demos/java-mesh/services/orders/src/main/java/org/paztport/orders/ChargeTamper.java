// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Code in orders that changes the next charge it sends payment, after orders has compared that charge with the facts
 * and its order book. It exists only when {@code attack.enabled=true}, and models a compromised orders sending the
 * call its route allows with arguments of its choosing. The {@code /attack/alter-amount} and {@code /attack/swap-card}
 * endpoints arm it ({@link AttackController}).
 *
 * <p>The change is made in the live purchase, not by replaying one: payment has already spent the nonce of a finished
 * purchase's call. One change is armed at a time, a later arming replacing an earlier one, and it is spent on the
 * first charge it is applied to.
 */
@Component
@ConditionalOnProperty(name = "attack.enabled", havingValue = "true")
public class ChargeTamper {

    private final AtomicReference<Consumer<Map<String, Object>>> armed = new AtomicReference<>();

    /** Arms a change of the next charge's amount to {@code amount}. */
    public void armAmount(long amount) {
        armed.set(charge -> charge.put("amount", amount));
    }

    /** Arms a change of the next charge's card to {@code card}. */
    public void armCard(String card) {
        armed.set(charge -> charge.put("card", card));
    }

    /** Applies the armed change to {@code charge}, if there is one, and disarms it; otherwise leaves it as it is. */
    public void apply(Map<String, Object> charge) {
        Consumer<Map<String, Object>> change = armed.getAndSet(null);
        if (change != null) {
            change.accept(charge);
        }
    }
}
