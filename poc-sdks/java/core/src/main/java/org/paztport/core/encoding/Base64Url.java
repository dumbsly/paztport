// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.encoding;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Base64url encoding without padding, the wire encoding used by both headers.
 * Decoding fails closed: anything but the canonical encoding throws.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_-]*");

    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    /**
     * Decodes the one canonical encoding of RFC 4648 §3.5: url-safe characters only, no padding, a length that is
     * never 1 modulo 4, and zero in the unused bits of the last character. Throws {@link IllegalArgumentException}
     * otherwise, so both SDKs accept and refuse the same text.
     */
    public static byte[] decode(String text) {
        if (!VALID.matcher(text).matches()) {
            throw new IllegalArgumentException("invalid base64url");
        }
        if (text.length() % 4 == 1) {
            throw new IllegalArgumentException("invalid base64url length");
        }
        byte[] data = DECODER.decode(text);
        if (!encode(data).equals(text)) {
            throw new IllegalArgumentException("non-zero unused bits in base64url");
        }
        return data;
    }
}
