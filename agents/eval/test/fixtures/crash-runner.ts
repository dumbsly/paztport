// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Runs runOnce with the spec in $CRASH_SPEC and exits abruptly on the first transcript line, as a crashing
// eval would. The runner's exit hook must still kill pi's process group.

import { runOnce, type RunSpec } from "../../src/runner.ts";

const spec = JSON.parse(process.env.CRASH_SPEC!) as RunSpec;
void runOnce(spec, (file) => {
  if (file === "transcript") process.exit(1);
});
