// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.mailer;

/**
 * Makes a field safe to put in a log line. An email's address and subject are
 * whatever the request said, and a sent email is a log line, so a raw newline
 * would let a sender write lines of its own (a fake {@code MAIL}, say). Control
 * and line-separator characters are written as unicode escapes and the value is
 * capped in length. Only what is logged changes. The SDK keeps its own copy
 * internal, so the mailer has this one, as the responder does.
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
