// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isExtensionName } from "../stamp/block.ts";
import type { ReplyCheck } from "./reply-check.ts";

/** Marks a requirement `requirement` built, so `callsAfter` never meets one whose names were not checked. */
declare const BUILT: unique symbol;

/**
 * What a client requires of a server: the extensions it must act on, each once and sorted, and whether the client
 * goes on without them (`continueWithout`, the configuration switch). Built by `requirement` only.
 */
export type Requirement = {
  readonly extensions: readonly string[];
  readonly continueWithout: boolean;
  readonly [BUILT]: true;
};

/**
 * A client's requirement, built and checked once (spec sessions.md, A client that requires extensions): `extensions`
 * with each name once, sorted, and the switch `continueWithout`, false unless given. Throws on a name that is not an
 * extension name, so a bad configuration fails where it is read, not at the first call's stamp.
 */
export function requirement(extensions: Iterable<string>, continueWithout = false): Requirement {
  const names = new Set<string>();
  for (const name of extensions) {
    if (typeof name !== "string" || !isExtensionName(name)) throw new Error("a name that is not an extension name");
    names.add(name);
  }
  return Object.freeze({ extensions: Object.freeze([...names].sort()), continueWithout }) as Requirement;
}

/** A client that requires nothing. */
export const NO_REQUIREMENT: Requirement = requirement([]);

/**
 * What a client with `req` may do in the session a handshake left it (sessions.md, "A client that requires
 * extensions"): `check` is the first reply's, or null for a JSON-RPC error or a timeout, and `listed` that reply's
 * `extensions`, [] when it did not read. `calls` says whether it makes calls at all, `requires` the names its calls
 * carry. Only an attested session whose reply lists every required name lets a client make calls under its
 * requirement, so neither a server answering "unsafe" nor anyone who can make the handshake fail switches it off;
 * only `continueWithout` does, and then a call carries no `requires` for a name the client could not get.
 */
export function callsAfter(check: ReplyCheck | null, listed: readonly string[], req: Requirement): { calls: boolean; requires: string[] } {
  if (req.extensions.length === 0) return { calls: true, requires: [] };
  const required = [...req.extensions];
  if (check === "ATTESTED") return { calls: true, requires: required };
  if (!req.continueWithout) return { calls: false, requires: [] };
  if (check === "EXTENSION_REQUIRED") return { calls: true, requires: required.filter((name) => listed.includes(name)) };
  return { calls: true, requires: [] };
}
