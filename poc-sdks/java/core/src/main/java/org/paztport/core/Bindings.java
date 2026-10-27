// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * What a stamp's {@code bind} field commits to, by kind. Each kind hashes a distinct domain prefix, so a binding
 * of one kind can never be replayed as another.
 */
public final class Bindings {

    private Bindings() {
    }

    /**
     * The prompt binding the origin stamp carries: {@code b64url(SHA-256(utf8("prompt\n" + text)))}. A string with a
     * lone surrogate has no UTF-8 form, and encoding it would silently turn it into {@code ?}, so it would share a
     * binding with another prompt; it is refused with {@link IllegalArgumentException}, never signed.
     */
    public static String prompt(String text) {
        if (!Text.isWellFormed(text)) {
            throw new IllegalArgumentException("prompt: not well-formed Unicode");
        }
        return Base64Url.encode(Crypto.sha256(("prompt\n" + text).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * The response binding: {@code b64url(SHA-256(utf8(resultHash + "\n" + callId + "\n" + JCS(labels))))}. A newline
     * in the call id would let two (hash, id) pairs share bytes, and a lone surrogate would encode as {@code ?}, so
     * both are refused with {@link IllegalArgumentException}.
     */
    public static String response(String resultHash, String callId, List<ContentLabel> labels) {
        if (!Text.isWellFormed(resultHash) || !Text.isWellFormed(callId)) {
            throw new IllegalArgumentException("response: not well-formed Unicode");
        }
        if (callId.contains("\n")) {
            throw new IllegalArgumentException("response: callId must not contain newlines");
        }
        String text = resultHash + "\n" + callId + "\n" + Jcs.canonicalize(ContentLabel.toJson(labels));
        return Base64Url.encode(Crypto.sha256(text.getBytes(StandardCharsets.UTF_8)));
    }
}
