// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { RULES_ROUTE_PREFIX } from "./local-rules.ts";

/** The one place a route becomes a string: the Merkle leaf is the route itself, so policy, stamps and proof lookups all join here. */
export function routeOf(services: readonly string[]): string {
  return services.join("/");
}

/** The nodes of the route a session's local rules are pinned under: the client chain, then `rules:<hash>`. */
export function rulesRouteNodes(clientChain: readonly string[], hash: string): string[] {
  return [...clientChain, RULES_ROUTE_PREFIX + hash];
}

/** The route a session's local rules are pinned under, as a string: `<chain>/rules:<hash>`. */
export function rulesRoute(clientChain: readonly string[], hash: string): string {
  return routeOf(rulesRouteNodes(clientChain, hash));
}

/**
 * Refuses a route node the spec forbids: empty, `.` or `..`, or holding `/`, `\`, `|` or a lone surrogate. Node names become route segments and
 * file names (`proofs-<svc>.json`), so one that could climb a directory, or run two nodes into one route, must never reach a signed policy. A
 * well-formed surrogate pair is an ordinary character. The policy owner checks this where it builds a policy; a verifier rebuilds routes only
 * from signed stamps and does not use it. The message names the rule and the node, except for an empty one or a lone surrogate.
 */
export function requireValidNode(node: string): void {
  if (typeof node !== "string" || node === "") throw new Error("route node must not be empty");
  if (node === "." || node === "..") throw new Error(`route node must not be "${node}"`);
  for (let i = 0; i < node.length; i++) {
    const c = node[i]!;
    if (c === "/" || c === "\\" || c === "|") throw new Error(`route node "${node}" must not contain '${c}'`);
    const code = node.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < node.length && node.charCodeAt(i + 1) >= 0xdc00 && node.charCodeAt(i + 1) <= 0xdfff) {
      i++;
    } else if (code >= 0xd800 && code <= 0xdfff) {
      throw new Error("route node must not contain a lone surrogate");
    }
  }
}
