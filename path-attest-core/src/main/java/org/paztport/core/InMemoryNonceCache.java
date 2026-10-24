// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory, process-local replay guard. Unbounded; fine for the POC. */
public final class InMemoryNonceCache implements NonceCache {

    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    @Override
    public boolean seenBefore(String rid, String svc) {
        return !seen.add(rid + "|" + svc);
    }
}
