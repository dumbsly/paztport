// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.util.List;
import org.paztport.core.verify.ReasonCode;

/**
 * The operations a partner switches off for unsafe sessions, and the rule that says whether a request is one. An
 * operation is {@code <METHOD> <route pattern>}: the pattern of the handler the framework actually dispatched to, not
 * the path the caller wrote, so that {@code /refund;x=1} or {@code //refund}, which reach the {@code /refund} handler,
 * are refused as {@code POST /refund}, and a path that matches no handler reaches none. Only the framework knows that
 * pattern, so it hands it over. A {@code HEAD} runs the {@code GET} handler, so it is refused wherever that
 * {@code GET} is.
 */
public final class UnsafeOperations {

    private final List<String> disabled;

    /** @param disabled the operations switched off, as {@code <METHOD> <route pattern>} */
    public UnsafeOperations(List<String> disabled) {
        this.disabled = List.copyOf(disabled);
    }

    /** Whether a request with {@code method} that reached the handler for {@code routePattern} is switched off. */
    public boolean refuses(String method, String routePattern) {
        return disabled.contains(method + " " + routePattern)
                || ("HEAD".equals(method) && disabled.contains("GET " + routePattern));
    }

    /**
     * The answer to a request this refuses, sent before its handler runs: {@code 403 {"reason":"UNSAFE_SESSION"}}.
     */
    public static HttpAnswer refusal() {
        return HttpAnswer.refusal(403, ReasonCode.UNSAFE_SESSION);
    }

    /** The operations switched off, as the replies list them. */
    public List<String> disabled() {
        return disabled;
    }
}
