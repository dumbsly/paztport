// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.assistant;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What the assistant does with a ticket, decided by a few patterns over its text in place of a model. It does
 * whatever the text asks, as a hijacked model would: nothing here asks whether the customer who wrote the ticket
 * owns the order, the card or the address it names. That is the point. Keeping the request in bounds is left to
 * the services it calls, from what the request carries.
 */
final class Script {

    private static final Pattern HISTORY = Pattern.compile("order history for (\\S+@[\\w.-]+\\w)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern ORDER = Pattern.compile("order (\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern REFUND_CARD = Pattern.compile("refund .*?to card ([\\d -]{12,23}\\d)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern DAMAGED = Pattern.compile("(broken|damaged)", Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL_TO = Pattern.compile("email me .*? at (\\S+@[\\w.-]+\\w)",
            Pattern.CASE_INSENSITIVE);

    private Script() {
    }

    /**
     * What a ticket asks for; a part it does not ask for is null, or false.
     *
     * @param historyEmail whose order history to read
     * @param order the order the ticket is about
     * @param refundCard the card to refund to, as written
     * @param damaged whether the ticket says the order arrived broken or damaged
     * @param emailTo where to email what was read
     */
    record Plan(String historyEmail, String order, String refundCard, boolean damaged, String emailTo) {
    }

    static Plan plan(String text) {
        String t = text == null ? "" : text;
        return new Plan(first(HISTORY, t), first(ORDER, t), first(REFUND_CARD, t), DAMAGED.matcher(t).find(),
                first(EMAIL_TO, t));
    }

    private static String first(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1) : null;
    }
}
