// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.nio.charset.StandardCharsets;

/**
 * What a stamp's {@code bind} field commits to, by kind. Each kind hashes a distinct domain prefix, so a binding
 * of one kind can never be replayed as another.
 */
public final class Bindings {

    private Bindings() {
    }

    /** The prompt binding the origin stamp carries: {@code b64url(SHA-256(utf8("prompt\n" + text)))}. */
    public static String prompt(String text) {
        return Base64Url.encode(Crypto.sha256(("prompt\n" + text).getBytes(StandardCharsets.UTF_8)));
    }
}
