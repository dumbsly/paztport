// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

/**
 * String checks shared by the canonical-JSON and influence code. A lone surrogate has no UTF-8 encoding, so
 * two implementations would hash it differently (or one would throw); refusing it keeps the bytes agreed.
 */
public final class Text {

    private Text() {
    }

    /** False when the string holds a surrogate that is not half of a valid pair. */
    public static boolean isWellFormed(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    return false;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }
}
