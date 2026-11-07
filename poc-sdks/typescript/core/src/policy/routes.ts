// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { RULES_ROUTE_PREFIX } from "./local-rules.ts";

/** The one place a route becomes a string: the Merkle leaf is the route itself, so policy, stamps and proof lookups all join here. */
export function routeOf(services: readonly string[]): string {
  return services.join("/");
}

/** The service of a route node or an `rcv`: the text before the first `#`, or all of it when it holds none. */
export function serviceOf(node: string): string {
  const i = node.indexOf("#");
  return i < 0 ? node : node.slice(0, i);
}

/** Whether an `rcv` addresses a service: the service itself, or `<service>#` and an operation name. */
export function addressedTo(rcv: string, svc: string): boolean {
  return rcv === svc || (rcv.startsWith(svc + "#") && isValidOperation(rcv.slice(svc.length + 1)));
}

/** Whether `name` is an operation name: a valid route node (see `requireValidNode`) that holds no `#`. */
export function isValidOperation(name: string): boolean {
  return nodeProblem(name) === undefined && !name.includes("#");
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
 * Refuses a route node the spec forbids: empty, `.` or `..`, or holding `/`, `\`, `|` or a lone surrogate. Node names
 * become route segments and file names (`proofs-<svc>.json`), so one that could climb a directory, or run two nodes
 * into one route, must never reach a signed policy. A well-formed surrogate pair is an ordinary character. The policy
 * owner checks this where it builds a policy; a verifier rebuilds routes only from signed stamps, and checks only that
 * an `rcv` names a valid operation (`isValidOperation`). The message names the rule and the node, except for an empty
 * one or a lone surrogate.
 */
export function requireValidNode(node: string): void {
  const problem = nodeProblem(node);
  if (problem !== undefined) throw new Error(problem);
}

/** The rule a route node breaks, as `requireValidNode` words it, or undefined for a valid node. */
function nodeProblem(node: string): string | undefined {
  if (typeof node !== "string" || node === "") return "route node must not be empty";
  if (node === "." || node === "..") return `route node must not be "${node}"`;
  for (let i = 0; i < node.length; i++) {
    const c = node[i]!;
    if (c === "/" || c === "\\" || c === "|") return `route node "${node}" must not contain '${c}'`;
    const code = node.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < node.length && node.charCodeAt(i + 1) >= 0xdc00 && node.charCodeAt(i + 1) <= 0xdfff) {
      i++;
    } else if (code >= 0xd800 && code <= 0xdfff) {
      return "route node must not contain a lone surrogate";
    }
  }
  return undefined;
}
