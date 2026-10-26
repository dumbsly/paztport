// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { InfluenceClass } from "./influence.ts";

/**
 * The influence rule: a write to a public destination is refused when the context mixes private content with
 * untrusted content (third-party, or local-untrusted, which counts as such). `classes` is every influence class
 * in the context the write was decided in.
 */
export function publicWriteRefused(classes: ReadonlySet<InfluenceClass>): boolean {
  return classes.has("private") && (classes.has("third-party") || classes.has("local-untrusted"));
}
