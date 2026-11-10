// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

/** The wire header names. */
public final class PaztportHeaders {

    /** A request's chain of stamps, origin first, whose last stamp names the receiver and binds the request. */
    public static final String CHAIN = "X-Path-Chain";
    /** The proof of a request's full route, the receiving service included, against the signed root. */
    public static final String PROOF = "X-Path-Proof";
    /** The influence entries a request commits to. */
    public static final String INFLUENCE = "X-Path-Influence";
    /** A response's attestation stamp and content labels. */
    public static final String RESPONSE = "X-Path-Response";

    /** The id of the session a call to a partner organisation is made in. */
    public static final String SESSION = "X-Path-Session";

    private static final String PREFIX = "X-Path-";

    /**
     * Whether {@code name} is one of Paztport's headers: every header whose name begins with {@code X-Path-} is. Names
     * compare case-insensitively over ASCII, as HTTP compares field names (RFC 9110 section 5.1), and only the ASCII
     * letters fold, so no Unicode case mapping or lookalike matches. A {@code null} name is no header.
     */
    public static boolean isPaztport(String name) {
        if (name == null || name.length() < PREFIX.length()) {
            return false;
        }
        for (int i = 0; i < PREFIX.length(); i++) {
            if (fold(name.charAt(i)) != fold(PREFIX.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static char fold(char c) {
        return c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c;
    }

    private PaztportHeaders() {
    }
}
