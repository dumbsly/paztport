// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import org.paztport.core.PathChainV1;

/**
 * Request-scoped carrier of the inbound chain. The inbound filter stores the
 * chain a service received; the outbound interceptor reads it to append the
 * next stamp. Calls are synchronous on the request thread, so a thread-local
 * is sufficient. The filter must {@link #clear()} in a finally block.
 */
public final class PaztportContext {

    private static final ThreadLocal<PathChainV1> INBOUND = new ThreadLocal<>();

    private PaztportContext() {
    }

    public static void setInboundChain(PathChainV1 chain) {
        INBOUND.set(chain);
    }

    /** The inbound chain for this request, or null if none was received (e.g. at the origin). */
    public static PathChainV1 inboundChain() {
        return INBOUND.get();
    }

    public static void clear() {
        INBOUND.remove();
    }
}
