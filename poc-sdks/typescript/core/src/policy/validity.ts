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

/** `o`'s own `key` as a notAfter, undefined when it has none; throws a TypeError naming `key` when it has one that is not an integer in [0, 2^53 − 1] (null included), since read as absent a damaged window would pass for the old form. */
export function readNotAfter(o: object, key: string): number | undefined {
  if (!Object.hasOwn(o, key)) return undefined;
  const n = (o as Record<string, unknown>)[key];
  if (!isNotAfter(n)) throw new TypeError(`${key} must be an integer in [0, 2^53 - 1]`);
  return n;
}

/** The earliest of `windows`, the policyNotAfter of a live verifier pinned to that material; undefined when any is undefined, since an old-form keyring or root has no window and so is never current. */
export function earliestNotAfter(...windows: (number | undefined)[]): number | undefined {
  return windows.some((w) => w === undefined) ? undefined : Math.min(...(windows as number[]));
}
