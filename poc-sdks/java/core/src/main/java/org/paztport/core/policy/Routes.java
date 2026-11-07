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
     * @throws IllegalArgumentException naming the rule the node broke, and the node itself where it can be shown:
     *     not an empty one, nor one with a lone surrogate, which UTF-8 could not carry intact
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

    /**
     * The service a route node names: the text before the first {@code #}, or the whole node when it has none. A
     * node is {@code <service>} or {@code <service>#<operation>}; policy, keyrings and bundles are keyed by service.
     */
    public static String service(String node) {
        int hash = node.indexOf('#');
        return hash < 0 ? node : node.substring(0, hash);
    }

    /**
     * A service name: a valid route node that holds no {@code #}, as that separates it from an operation.
     *
     * @throws IllegalArgumentException as {@link #requireValidNode} does, or when the name holds {@code #}
     */
    public static void requireValidService(String name) {
        requireValidNode(name);
        requireNoHash(name, "service name");
    }

    /**
     * An operation name: a valid route node that holds no {@code #}, so a node splits at its first {@code #}
     * unambiguously.
     *
     * @throws IllegalArgumentException as {@link #requireValidNode} does, or when the name holds {@code #}
     */
    public static void requireValidOperation(String name) {
        requireValidNode(name);
        requireNoHash(name, "operation name");
    }

    private static void requireNoHash(String name, String role) {
        if (name.indexOf('#') >= 0) {
            throw new IllegalArgumentException(role + " \"" + name + "\" must not contain '#'");
        }
    }

    public static String join(List<String> services) {
        return String.join("/", services);
    }
}
