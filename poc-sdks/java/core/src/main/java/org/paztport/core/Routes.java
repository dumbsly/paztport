// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.List;

/**
 * The one place a route becomes a string. A policy leaf, a stamp chain plus its
 * receiver at verification, and an outbound proof lookup must all agree on the
 * exact text, since the Merkle leaf is the route string itself: service names
 * joined with {@code /}.
 */
public final class Routes {

    private Routes() {
    }

    public static String join(List<String> services) {
        return String.join("/", services);
    }
}
