// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceEntry } from "./influence.ts";
import type { ContentLabel } from "./label.ts";

/**
 * The influence entry a verified response's label adds: `{ cls, src, h: resultHash, cid, owner }`, with `owner` only
 * when the label has one. `src` names the service the request went to. responseEntries calls this only when the whole
 * response verified.
 */
export function labelToEntry(label: ContentLabel, src: string, h: string): InfluenceEntry {
  return { cls: label.cls, src, h, cid: label.cid, ...(label.owner === undefined ? {} : { owner: label.owner }) };
}
