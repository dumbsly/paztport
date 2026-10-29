// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import com.fasterxml.jackson.core.type.TypeReference;
import java.util.ArrayList;
import java.util.List;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.Json;
import org.paztport.core.verify.VerifierV1;

/**
 * The ordered chain of stamps carried in {@code X-Path-Chain}, origin first.
 * Carries data and (de)serialization only; link and signature checks live in
 * {@link VerifierV1}.
 */
public record PathChainV1(List<StampV1> stamps) {

    public PathChainV1 {
        stamps = List.copyOf(stamps);
    }

    /** The {@code prev} value a stamp appended after this chain should carry. */
    public String prevSig() {
        return stamps.isEmpty() ? "" : stamps.get(stamps.size() - 1).sig();
    }

    public PathChainV1 withAppended(StampV1 stamp) {
        List<StampV1> next = new ArrayList<>(stamps);
        next.add(stamp);
        return new PathChainV1(next);
    }

    /** base64url(JSON array of stamps). */
    public String encode() {
        return Base64Url.encode(Json.write(stamps));
    }

    /** Fails closed: malformed base64url or JSON throws {@link IllegalArgumentException}. */
    public static PathChainV1 decode(String header) {
        byte[] json = Base64Url.decode(header);
        return new PathChainV1(Json.read(json, new TypeReference<List<StampV1>>() {}));
    }
}
