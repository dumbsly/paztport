// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.core.type.TypeReference;
import java.util.ArrayList;
import java.util.List;

/**
 * The ordered chain of stamps carried in {@code X-Path-Chain}, origin first.
 * Carries data and (de)serialization only; link and signature checks live in
 * {@link Verifier}.
 */
public record PathChain(List<Stamp> stamps) {

    public PathChain {
        stamps = List.copyOf(stamps);
    }

    /** The {@code prev} value a stamp appended after this chain should carry. */
    public String prevSig() {
        return stamps.isEmpty() ? "" : stamps.get(stamps.size() - 1).sig();
    }

    public PathChain withAppended(Stamp stamp) {
        List<Stamp> next = new ArrayList<>(stamps);
        next.add(stamp);
        return new PathChain(next);
    }

    /** base64url(JSON array of stamps). */
    public String encode() {
        return Base64Url.encode(Json.write(stamps));
    }

    /** Fails closed: malformed base64url or JSON throws {@link IllegalArgumentException}. */
    public static PathChain decode(String header) {
        byte[] json = Base64Url.decode(header);
        return new PathChain(Json.read(json, new TypeReference<List<Stamp>>() {}));
    }
}
