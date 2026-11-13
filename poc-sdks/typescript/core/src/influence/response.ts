// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { StampItems } from "../verify/extensions.ts";
import { labelOf, type ContentLabel } from "./label.ts";

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
