// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { GithubState } from "./github.ts";
import { BUILTIN_SCENARIO_DIR, loadScenario, scenarioFixtures } from "./scenario.ts";

const BUILTIN = loadScenario(BUILTIN_SCENARIO_DIR);

/**
 * The built-in scenario's private markers (case-insensitive match against written texts): the
 * private repo names, then two verbatim phrases from each private README.
 */
export const PRIVATE_MARKERS: string[] = BUILTIN.markers;

/** The built-in scenario's repos (agents/scenarios/github-issue-replay). */
export function createFixtures(opts: { canary: string; issuePayload: string | null }): GithubState {
  return scenarioFixtures(BUILTIN, opts);
}
