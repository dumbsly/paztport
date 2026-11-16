// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// A block: the claims a stamp's signer attaches, and the commitment the stamp makes to it (spec wire.md, Blocks).
// The core never reads an item; what one means is its extension's to say.

import { encode } from "../encoding/b64url.ts";
import { sha256 } from "../crypto/crypto.ts";
import { writeToken, writeWire } from "../encoding/jcs.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { array, exactly, object } from "../internal/fields.ts";

/** The claims one stamp's signer attaches: its items by extension name, and what it requires of the next hop. */
export type Block = {
  /** The items by extension name, each list in the order its signer wrote it. Look a name up only with `itemsUnder`. */
  items: Readonly<Record<string, readonly JsonValue[]>>;
  /** The extensions the signer requires the next hop to act on, sorted by UTF-16 code units, none twice. */
  requires: readonly string[];
};

/** The block that attaches nothing, whose stamp commits to `""`. */
export const EMPTY_BLOCK: Block = Object.freeze({
  items: Object.freeze(Object.create(null)),
  requires: Object.freeze([]),
});

const NAME = /^[a-z0-9-]{1,32}$/;

/** Whether `name` is an extension name: 1 to 32 of `a` to `z`, `0` to `9` and `-` (spec wire.md, Blocks, Names). */
export function isExtensionName(name: string): boolean {
  return NAME.test(name);
}

function checkName(name: string): void {
  if (!isExtensionName(name)) throw new Error("a name that is not an extension name");
}

/**
 * A block of `items`, with `requires` sorted. Throws on a name that is not an extension name in either, and on a name
 * twice in `requires`. The items object has no prototype, as the reader's has, so both builds behave alike.
 */
export function makeBlock(items: Record<string, readonly JsonValue[]>, requires: readonly string[] = []): Block {
  const own: Record<string, readonly JsonValue[]> = Object.create(null);
  for (const name of Object.keys(items)) {
    checkName(name);
    own[name] = items[name]!;
  }
  const sorted = [...requires].sort();
  for (let i = 0; i < sorted.length; i++) {
    checkName(sorted[i]!);
    if (i > 0 && sorted[i] === sorted[i - 1]) throw new Error("a name twice in requires");
  }
  return { items: own, requires: sorted };
}

/**
 * A block by the block schema (spec wire.md, Blocks): exactly `items` and `requires`, every name an extension name,
 * every value in `items` an array, `requires` sorted with no name twice. Throws an Error naming what it refuses.
 */
export function blockOf(value: JsonValue): Block {
  const o = object(value);
  exactly(o, ["items", "requires"]);
  const items: Record<string, readonly JsonValue[]> = Object.create(null);
  const given = object(o, "items");
  for (const name of Object.keys(given)) {
    checkName(name);
    items[name] = array(given[name]!);
  }
  const requires: string[] = [];
  for (const name of array(o, "requires")) {
    if (typeof name !== "string") throw new Error("a name in requires that is not a string");
    checkName(name);
    // `<=` refuses both an unsorted pair and a repeated name.
    if (requires.length > 0 && name <= requires[requires.length - 1]!) {
      throw new Error("requires is unsorted or holds a name twice");
    }
    requires.push(name);
  }
  return { items, requires };
}

/** The blocks of a request or response as the reader gave them: an array of blocks, each by `blockOf`. */
export function blocksOf(value: JsonValue): Block[] {
  return array(value).map(blockOf);
}

/** Reads a token of blocks: MalformedJson for bytes that do not read, an Error naming what the schema refuses. */
export function readBlocks(token: string): Block[] {
  return blocksOf(readToken(token));
}

/**
 * The token of `blocks`, one per stamp in chain order: the token `readBlocks` reads. Throws, as `blockOf` does, for a
 * block built by hand that the block schema refuses, and as `writeToken` does for what JSON cannot carry.
 */
export function writeBlocks(blocks: readonly Block[]): string {
  const value = blocks as unknown as JsonValue[];
  // a Block is a type, not a checked value, so one written by hand is held to the schema the reader applies
  for (const block of value) blockOf(block);
  return writeToken(value);
}

/** A stamp's `ext` for `block`: `""` for the empty block, else `b64url(SHA-256(JCS(block)))`. */
export function commitBlock(block: Block): string {
  if (Object.keys(block.items).length === 0 && block.requires.length === 0) return "";
  return encode(sha256(writeWire(block as unknown as JsonValue)));
}

/**
 * The items `block` holds under `name`, or null when it does not name it. Only the block's own members count, so a
 * name such as `constructor` finds nothing where it is not listed.
 */
export function itemsUnder(block: Block, name: string): readonly JsonValue[] | null {
  return Object.hasOwn(block.items, name) ? block.items[name]! : null;
}
