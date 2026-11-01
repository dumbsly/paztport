// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

/**
 * String checks shared by the canonical-JSON and influence code. A lone surrogate has no UTF-8 encoding, so
 * two implementations would hash it differently (or one would throw); refusing it keeps the bytes agreed. A
 * noncharacter is refused wherever Paztport reads or writes JSON (RFC 7493 section 2.1).
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

    /**
     * True when the string holds a noncharacter: U+FDD0 to U+FDEF, or a code point whose last four hex digits are
     * FFFE or FFFF. A lone surrogate is not one; see {@link #isWellFormed}.
     */
    public static boolean hasNoncharacter(String s) {
        return s.codePoints().anyMatch(Text::isNoncharacter);
    }

    /** True for a noncharacter code point: the one test the JSON reader, the writer and {@link #hasNoncharacter} share. */
    public static boolean isNoncharacter(int cp) {
        return cp >= 0xfdd0 && cp <= 0xfdef || (cp & 0xfffe) == 0xfffe;
    }
}
