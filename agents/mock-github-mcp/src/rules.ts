// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { influenceClasses, type InfluenceEntry } from "@paztport/path-attest";
import type { GithubTool } from "./github.ts";

/**
 * The influence rule: a write to a public destination is denied when the agent's context mixes
 * private content with untrusted content (third-party, or local-untrusted which counts as such).
 */
export function influenceDecision(
  tool: GithubTool,
  destinationPublic: boolean,
  influence: InfluenceEntry[],
): "OK" | "INFLUENCE_DENIED" {
  if (tool.kind !== "write" || !destinationPublic) return "OK";
  const cls = influenceClasses(influence);
  const untrusted = cls.has("third-party") || cls.has("local-untrusted");
  return cls.has("private") && untrusted ? "INFLUENCE_DENIED" : "OK";
}
