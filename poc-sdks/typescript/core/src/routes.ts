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
