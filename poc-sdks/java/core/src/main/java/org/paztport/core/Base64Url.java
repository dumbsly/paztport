// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Base64;

/**
 * Base64url encoding without padding, the wire encoding used by both headers.
 * Decoding fails closed: any character outside the url-safe alphabet throws.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    public static byte[] decode(String text) {
        return DECODER.decode(text);
    }
}
