// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { StampItems } from "../verify/extensions.ts";
import type { ReasonCode } from "../verify/reason.ts";
import type { InfluenceEntry } from "./influence.ts";
import { labelOf, type ContentLabel } from "./label.ts";
import { labelToEntry } from "./label-entry.ts";

/**
 * The labels a response that verified carries, from the items handed on under `influence`, one entry of `stamps` per
 * stamp of the response chain (spec influence.md, Content labels): every item of every block, in order, each read as
 * a label. Null, so that the response counts as one `local-untrusted` entry, when a block does not name `influence`
 * (a silent response) or an item is not a label. Over MCP the response chain's stamps are all the server's, so every
 * block must name it.
 */
export function readResponseLabels(stamps: readonly StampItems[]): ContentLabel[] | null {
  const labels: ContentLabel[] = [];
  for (const { items } of stamps) {
    if (items === null) return null;
    try {
      labels.push(...items.map(labelOf));
    } catch {
      return null;
    }
  }
  return labels;
}

/**
 * The labels a caller that acts on `influence` takes from a response (spec influence.md, Content labels): those
 * `readResponseLabels` reads from `stamps`, the items handed on under `influence`, when the response check gave
 * `reason` OK; null for every other response, which then counts as one `local-untrusted` entry. A label counts only
 * when the whole response verifies, so `stamps` is not read unless `reason` is OK.
 */
export function responseLabels(reason: ReasonCode, stamps: readonly StampItems[] | undefined): ContentLabel[] | null {
  return reason === "OK" && stamps !== undefined ? readResponseLabels(stamps) : null;
}

/**
 * The influence entries a caller that acts on `influence` adds for one response (spec influence.md, Content labels):
 * one per label `responseLabels` takes, `{ cls, src, h: resultHash, cid, owner }`, or else exactly one
 * `{ cls: "local-untrusted", src, h: resultHash }`. `src` is the caller's name for the service it called
 * (`server:<serverId>` over MCP, `http:<target>` over HTTP).
 */
export function responseEntries(
  reason: ReasonCode,
  stamps: readonly StampItems[] | undefined,
  src: string,
  resultHash: string,
): InfluenceEntry[] {
  const labels = responseLabels(reason, stamps);
  if (labels === null) return [{ cls: "local-untrusted", src, h: resultHash }];
  return labels.map((label) => labelToEntry(label, src, resultHash));
}
