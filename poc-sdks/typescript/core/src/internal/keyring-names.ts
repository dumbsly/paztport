// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { requireValidNode } from "../policy/routes.ts";

/** Refuses a keyring (the `services` of a file, a request's `clientKeyring`, a reply's `serverKeyring`) naming a service by something that is not a route node. The name is data, so the refusal names the member, not the name. */
export function requireRouteNodeNames(keyring: Record<string, string>, member: string): void {
  for (const name of Object.keys(keyring)) {
    try {
      requireValidNode(name);
    } catch {
      throw new Error(`member ${member} holds a name that is not a route node`);
    }
  }
}
