// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isExtensionName } from "../stamp/block.ts";

/**
 * The extension names `given` lists, each once, for a client's requirement and a verifier's settings (spec wire.md,
 * Blocks, Names). Throws a TypeError for a string or a String object, which iterates as one-letter names, each an
 * extension name: "influence" would read as seven. Throws an Error on a name that is not an extension name.
 * Internal: index.ts does not export it.
 */
export function extensionNames(given: Iterable<string>): Set<string> {
  if (typeof given === "string" || given instanceof String) {
    throw new TypeError("a string where a list of extension names is expected");
  }
  const names = new Set<string>();
  for (const name of given) {
    if (typeof name !== "string" || !isExtensionName(name)) throw new Error("a name that is not an extension name");
    names.add(name);
  }
  return names;
}
