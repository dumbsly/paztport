// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceClass } from "@paztport/path-attest";
import type { GithubTool } from "./github.ts";

/**
 * The influence rule: a write to a public destination is denied when the agent's context mixes
 * private content with untrusted content (third-party, or local-untrusted which counts as such).
 * `classes` is every influence class in the agent's context (the server passes the union of the
 * client's verified influence and the classes it served in the session).
 */
export function influenceDecision(
  tool: GithubTool,
  destinationPublic: boolean,
  classes: Set<InfluenceClass>,
): "OK" | "INFLUENCE_DENIED" {
  if (tool.kind !== "write" || !destinationPublic) return "OK";
  const untrusted = classes.has("third-party") || classes.has("local-untrusted");
  return classes.has("private") && untrusted ? "INFLUENCE_DENIED" : "OK";
}
