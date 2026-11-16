// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// A verifier's extension settings, and what it hands a service on OK (spec verification.md, Inputs and The live
// order). The settings are built and checked here once, so a verifier never meets settings that break the rule.

import type { JsonValue } from "../encoding/json.ts";
import { isExtensionName } from "../stamp/block.ts";

/** The extension names a verifier acts on and carries, and whether it holds a sender to the last block's `requires`. */
export type ExtensionSettings = {
  /** The extensions this service acts on (`actsOn`): check 9c's set, and the names the hand-over holds. */
  readonly actsOn: ReadonlySet<string>;
  /** The names this verifier carries (`allowedExtensions`), check 9b's set; undefined carries any name. */
  readonly allowed: ReadonlySet<string> | undefined;
  /** Whether the live verifier runs check 9c: false only for a recorded response (`recordExtensionSettings`). */
  readonly enforceRequires: boolean;
};

function names(given: Iterable<string>): Set<string> {
  // a string iterates as one-letter names, each an extension name: "influence" would read as seven
  if (typeof given === "string") throw new TypeError("a string where a list of extension names is expected");
  const set = new Set<string>();
  for (const name of given) {
    if (typeof name !== "string" || !isExtensionName(name)) throw new Error("a name that is not an extension name");
    set.add(name);
  }
  return set;
}

function settings(
  actsOn: Iterable<string>,
  allowed: Iterable<string> | undefined,
  enforceRequires: boolean,
): ExtensionSettings {
  const acts = names(actsOn);
  const carried = allowed === undefined ? undefined : names(allowed);
  // A service cannot act on an extension its own list refuses (spec verification.md, Inputs).
  if (carried !== undefined && [...acts].some((name) => !carried.has(name))) {
    throw new Error("a name in actsOn outside the allowed list");
  }
  return Object.freeze({ actsOn: acts, allowed: carried, enforceRequires });
}

/**
 * A live verifier's settings: the extensions it acts on and, when given, the names it carries. Throws on a name that
 * is not an extension name, and on a name in `actsOn` outside `allowed`; a TypeError for a string in place of either
 * list.
 */
export function extensionSettings(actsOn: Iterable<string>, allowed?: Iterable<string>): ExtensionSettings {
  return settings(actsOn, allowed, true);
}

/**
 * The settings a recorded response is checked with: as `extensionSettings`, but without check 9c, since the response
 * was held to the caller's `actsOn` live and the record does not hold it (spec verification.md, Offline
 * verification). `readAs` names the extensions whose items the hand-over holds.
 */
export function recordExtensionSettings(readAs: Iterable<string>, allowed?: Iterable<string>): ExtensionSettings {
  return settings(readAs, allowed, false);
}

/** The settings of a verifier that acts on no extension and carries any name. */
export const NO_EXTENSIONS: ExtensionSettings = extensionSettings([]);

/**
 * One stamp's entry in the hand-over: its signer, and the items its block holds under the name, or null when the
 * block does not name it.
 */
export type StampItems = { svc: string; items: readonly JsonValue[] | null };

/** What a verifier hands the service on OK: for each name in `actsOn`, one entry per stamp in chain order. */
export type HandOver = ReadonlyMap<string, readonly StampItems[]>;
