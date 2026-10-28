// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/** True when `n` is a valid `notAfter`: an integer in [0, 2^53 − 1], judged by value (1.0 and 1e3 are 1 and 1000). */
export function isNotAfter(n: unknown): n is number {
  return Number.isSafeInteger(n) && (n as number) >= 0;
}

/** True when `x` has a valid `notAfter` of its own and `at <= notAfter`; an old-form root or keyring, with none, is never current. Says nothing about the signature. */
export function isCurrent(x: { notAfter?: unknown }, at: number): boolean {
  return typeof x === "object" && x !== null && Object.hasOwn(x, "notAfter") && isNotAfter(x.notAfter) && at <= x.notAfter;
}
