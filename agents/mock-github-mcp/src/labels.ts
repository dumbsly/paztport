// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceClass } from "@paztport/path-attest";
import type { ToolOutcome } from "./github.ts";

/** Influence class of the content a tool result carries into the agent's context. */
export function labelFor(outcome: ToolOutcome): InfluenceClass {
  const r = outcome.read;
  if (!r) return "public";
  if (r.what === "issues") return "third-party";
  return r.includesPrivate ? "private" : "public";
}
