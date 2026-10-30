// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * One request as a receiver reads it, taken from whatever framework received it.
 *
 * @param method the request method, as sent
 * @param target the raw path, plus {@code ?} and the raw query when there is one, as the caller's binding covers it
 *     ({@link RequestBinding}); not decoded or normalised, since the binding is over what was sent
 * @param headers the request's headers by name, in any case, each with its first value; a receiver reads only the
 *     {@link PaztportHeaders}, so an adapter may pass only those. Two names that differ only in case are one header,
 *     and the later wins.
 * @param body the body, whole; the receiver does not change it, and the record does not copy it
 */
public record InboundRequest(String method, String target, Map<String, String> headers, byte[] body) {

    public InboundRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(body, "body");
        TreeMap<String, String> byName = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.forEach((name, value) -> {
            if (value != null) {
                byName.put(name, value);
            }
        });
        headers = Collections.unmodifiableMap(byName);
    }

    /** The header's value, its name in any case, or null when it was not sent. */
    public String header(String name) {
        return headers.get(name);
    }
}
