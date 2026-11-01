// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

/**
 * The range of a protocol integer, shared by the stamp {@code v} and {@code ts} and every {@code notAfter}: the
 * reply certificate's, a root's and a keyring's. {@link JsonReader} reads no other number, so this is the check for
 * a value about to be signed, or pinned in a verifier's config.
 */
public final class JsonIntegers {

    /** 2^53 &minus; 1, the largest integer both SDKs read and print the same way. */
    public static final long MAX_SAFE = (1L << 53) - 1;

    private JsonIntegers() {
    }

    /**
     * True when {@code v} is a protocol integer: in [0, 2^53 &minus; 1]. The one range check every window and every
     * stamp {@code ts} is held to, whether read from the wire, about to be signed or pinned in a verifier's config,
     * so that no value one SDK accepts is one the other refuses.
     */
    public static boolean inRange(long v) {
        return v >= 0 && v <= MAX_SAFE;
    }
}
