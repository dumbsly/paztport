// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { randomBytes } from "../crypto/crypto.ts";
import type { JsonValue } from "../encoding/json.ts";
import { exactly, object, str } from "../internal/fields.ts";
import { classOf, ownerOf, type InfluenceClass } from "./influence.ts";

/**
 * What a responder says of the content it attests (spec influence.md, Content labels): its class, a fresh content id,
 * and whose data it is when the responder's own records say.
 */
export type ContentLabel = { cls: InfluenceClass; cid: string; owner?: string };

/** A fresh content id for a label: 16 random bytes, base64url. */
export function newContentId(): string {
  return encode(randomBytes(16));
}

/**
 * An item on a response's block, read as a label: an object with exactly a known `cls` and a string `cid`, and an
 * optional non-empty string `owner`. Throws an Error naming what it refuses.
 */
export function labelOf(item: JsonValue): ContentLabel {
  const o = object(item);
  exactly(o, ["cls", "cid"], ["owner"]);
  const label: ContentLabel = { cls: classOf(o), cid: str(o, "cid") };
  const owner = ownerOf(o);
  if (owner !== undefined) label.owner = owner;
  return label;
}
