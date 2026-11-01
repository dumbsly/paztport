// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { printFile, type JsonValue, type SignedKeyring } from "@paztport/core";

const DAY_MS = 86_400_000;

/** Reads a base64url PKCS#8 key file, trimming surrounding whitespace. */
export function readKey(path: string): string {
  return readFileSync(path, "utf8").trim();
}

/** Writes a keyring over `path` in place, in the file format. */
export function writeKeyring(path: string, k: SignedKeyring): void {
  writeJson(path, { services: k.services, policy: k.policy, sig: k.sig, notAfter: k.notAfter });
}

/** Now plus `days` days (`fallback` when undefined), or undefined unless `days` is a positive whole number whose end is a safe integer. */
export function notAfterInDays(days: string | undefined, fallback: number): number | undefined {
  const d = days === undefined ? fallback : Number(days);
  const notAfter = Date.now() + d * DAY_MS;
  return days !== "" && Number.isSafeInteger(d) && d >= 1 && Number.isSafeInteger(notAfter) ? notAfter : undefined;
}

/** Writes `value` to `path` in the file format. */
export function writeJson(path: string, value: JsonValue): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, printFile(value));
}

/** Writes secret material owner-only; mode applies only on create, so chmod too. */
export function writePrivate(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
}
