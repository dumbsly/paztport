// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Influence, the extension that records what content shaped a request (spec influence.md). The core carries its
// items in blocks without reading them; this folder reads them, from what the verifier hands over.

import type { JsonObject, JsonValue } from "../encoding/json.ts";
import { exactly, object, str } from "../internal/fields.ts";
import { makeBlock, type Block } from "../stamp/block.ts";
import type { ContentLabel } from "./label.ts";

/** The extension's name, under which its items travel in a block (spec influence.md). */
export const INFLUENCE = "influence";

/**
 * The four classes, written here only (spec influence.md, Classes): content from outside the trust boundary, data that
 * must not reach a public destination unless its owner's, content already public, or content the client cannot vouch
 * for. Entries and labels both read `cls` with `classOf`.
 */
const CLASSES = ["third-party", "private", "public", "local-untrusted"] as const;

/** What kind of content an influence entry records: one of the four classes. */
export type InfluenceClass = (typeof CLASSES)[number];
/**
 * One record of content that shaped a call: its class, `src` naming the source (`server:<serverId>`, say), `h`
 * identifying the content, and, when it came from a label, the label's `cid` and any `owner`, a non-empty opaque id
 * of whose data it is.
 */
export type InfluenceEntry = { cls: InfluenceClass; src: string; h: string; cid?: string; owner?: string };

/** The member `cls` of `o`, one of the four classes. Internal: index.ts does not export it. */
export function classOf(o: JsonObject): InfluenceClass {
  const cls = str(o, "cls");
  if (!(CLASSES as readonly string[]).includes(cls)) throw new Error("member cls is not an influence class");
  return cls as InfluenceClass;
}

/**
 * The member `owner` of `o` when it has one, a non-empty string: an empty one is refused, not read as none, so it is
 * never taken for a known owner. Internal: index.ts does not export it.
 */
export function ownerOf(o: JsonObject): string | undefined {
  if (!Object.hasOwn(o, "owner")) return undefined;
  const owner = str(o, "owner");
  if (owner === "") throw new Error("member owner is empty");
  return owner;
}

/**
 * An item on a request's block, read as an entry (spec influence.md, Entries): an object with exactly a known `cls`,
 * `src` and `h`, and an optional `cid` and non-empty `owner`, all strings. Throws an Error naming what it refuses.
 */
export function entryOf(item: JsonValue): InfluenceEntry {
  const o = object(item);
  exactly(o, ["cls", "src", "h"], ["cid", "owner"]);
  const entry: InfluenceEntry = { cls: classOf(o), src: str(o, "src"), h: str(o, "h") };
  if (Object.hasOwn(o, "cid")) entry.cid = str(o, "cid");
  const owner = ownerOf(o);
  if (owner !== undefined) entry.owner = owner;
  return entry;
}

/** The distinct classes of `entries` (or labels). */
export function influenceClasses(entries: readonly { cls: InfluenceClass }[]): Set<InfluenceClass> {
  return new Set(entries.map((e) => e.cls));
}

/**
 * A block that names `influence` with `items`, the entries a hop adds to a request or the labels a responder puts on
 * a response, as written, and `requires` (spec influence.md, The every-stamp rule): `[]` names the extension with
 * nothing to add, so it is not the empty block.
 */
export function influenceBlock(
  items: readonly (InfluenceEntry | ContentLabel)[],
  requires: readonly string[] = [],
): Block {
  return makeBlock({ [INFLUENCE]: [...items] as unknown as JsonValue[] }, requires);
}
