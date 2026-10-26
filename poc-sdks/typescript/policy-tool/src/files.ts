// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export type Keyring = { services: Record<string, string>; policy: string };

/** Reads a base64url PKCS#8 key file, trimming surrounding whitespace. */
export function readKey(path: string): string {
  return readFileSync(path, "utf8").trim();
}

export function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export function readKeyring(path: string): Keyring {
  const ring = readJson<Keyring>(path);
  if (typeof ring.policy !== "string" || typeof ring.services !== "object" || ring.services === null) {
    throw new Error(`malformed keyring: ${path}`);
  }
  return ring;
}

export function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

/** Writes secret material owner-only; mode applies only on create, so chmod too. */
export function writePrivate(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
}
