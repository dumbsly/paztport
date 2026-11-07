// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.util.List;

/**
 * The one place a route becomes a string. A policy leaf, a chain's origin service
 * then each stamp's {@code rcv} at verification, and an outbound proof lookup must
 * all agree on the exact text, since the Merkle leaf is the route string itself:
 * nodes joined with {@code /}, each a service or {@code <service>#<operation>}.
 */
public final class Routes {

    private Routes() {
    }

    /**
     * Refuses a route node the spec forbids: empty, {@code .} or {@code ..}, or holding {@code /}, {@code \},
     * {@code |} or a lone surrogate. Node names become route segments and file names ({@code proofs-<svc>.json}),
     * so one that could climb a directory, or run two nodes into one route, must never reach a signed policy.
     * A well-formed surrogate pair is an ordinary character and is allowed. The policy owner checks this where it
     * builds a policy; a verifier rebuilds routes only from signed stamps, and checks only that an {@code rcv}
     * names a valid operation ({@link #isValidOperation}).
     *
     * @throws IllegalArgumentException naming the rule the node broke, and the node itself where it can be shown:
     *     not an empty one, nor one with a lone surrogate, which UTF-8 could not carry intact
     */
    public static void requireValidNode(String node) {
        String problem = nodeProblem(node);
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
    }

    /** The rule a route node breaks, as {@link #requireValidNode} words it, or null for a valid node. */
    private static String nodeProblem(String node) {
        if (node == null || node.isEmpty()) {
            return "route node must not be empty";
        }
        if (node.equals(".") || node.equals("..")) {
            return "route node must not be \"" + node + "\"";
        }
        for (int i = 0; i < node.length(); i++) {
            char c = node.charAt(i);
            if (c == '/' || c == '\\' || c == '|') {
                return "route node \"" + node + "\" must not contain '" + c + "'";
            }
            if (Character.isHighSurrogate(c) && i + 1 < node.length()
                    && Character.isLowSurrogate(node.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                return "route node must not contain a lone surrogate";
            }
        }
        return null;
    }

    /**
     * The service a route node names: the text before the first {@code #}, or the whole node when it has none. A
     * node is {@code <service>} or {@code <service>#<operation>}; policy bundles and keyrings are keyed by service.
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

    /**
     * Whether {@code name} is an operation name, by the rule {@link #requireValidOperation} enforces; a verifier
     * asks this of the text after {@code #} in an {@code rcv}.
     */
    public static boolean isValidOperation(String name) {
        return nodeProblem(name) == null && name.indexOf('#') < 0;
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
