// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/** True when `n` is a valid `notAfter`: an in-memory integer in [0, 2^53 − 1]. */
export function isNotAfter(n: unknown): n is number {
  return Number.isSafeInteger(n) && (n as number) >= 0;
}

/** True when `x` has a valid `notAfter` of its own and `at <= notAfter`; a root or keyring without one is never current. Says nothing about the signature. */
export function isCurrent(x: { notAfter?: unknown }, at: number): boolean {
  return typeof x === "object" && x !== null && Object.hasOwn(x, "notAfter") && isNotAfter(x.notAfter) && at <= x.notAfter;
}

/** `o`'s own `key` as a notAfter; throws a TypeError naming `key` when it has none (an inherited one included) or one that is not an integer in [0, 2^53 − 1] (null included). */
export function readNotAfter(o: object, key: string): number {
  const n = Object.hasOwn(o, key) ? (o as Record<string, unknown>)[key] : undefined;
  if (!isNotAfter(n)) throw new TypeError(`${key} must be an integer in [0, 2^53 - 1]`);
  return n;
}

/** The earliest of `windows`, the policyNotAfter of a live verifier pinned to that material. */
export function earliestNotAfter(...windows: number[]): number {
  return Math.min(...windows);
}

/**
 * The policyNotAfter of a live verifier pinned to several keyrings and roots: the earlier of the latest keyring
 * notAfter and the latest root notAfter, the last moment the policy owner vouches for some keyring and some root.
 * With no keyring or no root it is -Infinity, which every live verifier refuses.
 */
export function pinnedNotAfter(keyrings: readonly { notAfter: number }[], roots: readonly { notAfter: number }[]): number {
  const latest = (members: readonly { notAfter: number }[]) => Math.max(...members.map((m) => m.notAfter));
  return Math.min(latest(keyrings), latest(roots));
}
