// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.internal;

/**
 * Makes an event field safe to put in a log line. The suspect and {@code rid}
 * come from stamps, which say whatever their signer chose, and the
 * {@code PAZTPORT_EVENT} line is what operators and the demo read, so a raw
 * newline would let a signer write lines of its own. Control and
 * line-separator characters are written as unicode escapes and the value is
 * capped in length. Only what is logged changes; what is signed, verified and
 * acted on stays as received.
 */
public final class LogSafe {

    /** Longest stretch of a value that is logged before it is cut off. */
    public static final int MAX_CHARS = 128;

    private LogSafe() {
    }

    public static String of(Object value) {
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
