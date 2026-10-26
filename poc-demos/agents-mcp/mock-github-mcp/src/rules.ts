// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { publicWriteRefused, type InfluenceClass } from "@paztport/core";
import type { GithubTool } from "./github.ts";

/**
 * The influence rule applied to a GitHub tool call: only a write to a public destination is decided by it.
 * `classes` is every influence class in the agent's context (the server passes the union of the
 * client's verified influence and the classes it served in the session).
 */
export function influenceDecision(
  tool: GithubTool,
  destinationPublic: boolean,
  classes: Set<InfluenceClass>,
): "OK" | "INFLUENCE_DENIED" {
  if (tool.kind !== "write" || !destinationPublic) return "OK";
  return publicWriteRefused(classes) ? "INFLUENCE_DENIED" : "OK";
}
