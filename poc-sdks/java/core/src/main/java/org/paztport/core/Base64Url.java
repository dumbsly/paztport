// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Base64url encoding without padding, the wire encoding used by both headers.
 * Decoding fails closed: any character outside the url-safe alphabet throws.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_-]*={0,2}");

    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    /**
     * Strict-alphabet decode matching the TypeScript SDK exactly: url-safe characters followed by at most two
     * {@code =}, which are tolerated and ignored, and a body whose length is never 1 modulo 4. Throws
     * {@link IllegalArgumentException} otherwise, so both SDKs accept and refuse the same text.
     */
    public static byte[] decode(String text) {
        if (!VALID.matcher(text).matches()) {
            throw new IllegalArgumentException("invalid base64url");
        }
        int end = text.length();
        while (end > 0 && text.charAt(end - 1) == '=') {
            end--;
        }
        if (end % 4 == 1) {
            throw new IllegalArgumentException("invalid base64url length");
        }
        return DECODER.decode(text.substring(0, end));
    }
}
