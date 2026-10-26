// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

/**
 * Makes an event field safe to put in a log line. Event fields are chosen by
 * whoever signed or sent the event, and the responder's log is the audit trail,
 * so a raw newline would let a sender write lines of its own (a fake
 * {@code ESCALATE}, say). Control and line-separator characters are written as
 * unicode escapes and the value is capped in length. Only what is logged
 * changes; what is signed, verified and acted on stays as received.
 */
final class LogSafe {

    /** Longest stretch of a value that is logged before it is cut off. */
    static final int MAX_CHARS = 128;

    private LogSafe() {
    }

    static String of(Object value) {
        String s = String.valueOf(value);
        boolean cut = s.length() > MAX_CHARS;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(s.length(), MAX_CHARS); i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) || c == ' ' || c == ' ') {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return cut ? out.append("...").toString() : out.toString();
    }
}
