// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

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

    /**
     * Refuses a route node the spec forbids: empty, {@code .} or {@code ..}, or holding {@code /}, {@code \},
     * {@code |} or a lone surrogate. Node names become route segments and file names ({@code proofs-<svc>.json}),
     * so one that could climb a directory, or run two nodes into one route, must never reach a signed policy.
     * A well-formed surrogate pair is an ordinary character and is allowed. The policy owner checks this where it
     * builds a policy; a verifier rebuilds routes only from signed stamps and does not use it.
     *
     * @throws IllegalArgumentException naming the node and the rule it broke
     */
    public static void requireValidNode(String node) {
        if (node == null || node.isEmpty()) {
            throw new IllegalArgumentException("route node must not be empty");
        }
        if (node.equals(".") || node.equals("..")) {
            throw new IllegalArgumentException("route node must not be \"" + node + "\"");
        }
        for (int i = 0; i < node.length(); i++) {
            char c = node.charAt(i);
            if (c == '/' || c == '\\' || c == '|') {
                throw new IllegalArgumentException("route node \"" + node + "\" must not contain '" + c + "'");
            }
            if (Character.isHighSurrogate(c) && i + 1 < node.length()
                    && Character.isLowSurrogate(node.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                throw new IllegalArgumentException("route node must not contain a lone surrogate");
            }
        }
    }

    public static String join(List<String> services) {
        return String.join("/", services);
    }
}
