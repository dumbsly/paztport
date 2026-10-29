// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { join } from "node:path";
import { parseArgs } from "node:util";
import { generateKeyPair, signKeyring } from "@paztport/core";
import { describeNotAfter, notAfterInDays, writeKeyring, writePrivate } from "./files.ts";

const USAGE = "Usage: node keygen.ts --out <dir> --services a,b,c [--policy-days 7]";

/** How long a keyring keygen writes stays valid unless `--policy-days` says otherwise: seven days. */
const DEFAULT_POLICY_DAYS = 7;

function main(): void {
  let out: string | undefined;
  let services: string | undefined;
  let days: string | undefined;
  try {
    ({ out, services, "policy-days": days } = parseArgs({
      options: { out: { type: "string" }, services: { type: "string" }, "policy-days": { type: "string" } },
      strict: true,
    }).values);
  } catch {
    // fall through to usage
  }
  const names = (services ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  const reserved = new Set([".", "..", "policy", "keyring"]);
  // Compare case-insensitively: on a case-insensitive filesystem "A.key" overwrites "a.key".
  const lower = names.map((n) => n.toLowerCase());
  const bad =
    new Set(lower).size !== lower.length ||
    lower.some((n) => reserved.has(n) || n.includes("/") || n.includes("\\"));
  const notAfter = notAfterInDays(days, DEFAULT_POLICY_DAYS);
  if (!out || names.length === 0 || bad || notAfter === undefined) {
    console.error(USAGE);
    process.exit(2);
  }

  const keys: Record<string, string> = {};
  for (const svc of names) {
    const kp = generateKeyPair();
    writePrivate(join(out, `${svc}.key`), kp.privateKey);
    keys[svc] = kp.publicKey;
  }
  const policy = generateKeyPair();
  writePrivate(join(out, "policy.key"), policy.privateKey);
  // the policy key has just made every listed key, so each is that service's current key
  writeKeyring(join(out, "keyring.json"), signKeyring(keys, policy.publicKey, policy.privateKey, notAfter));
  console.log(`keygen: wrote ${names.length} service keys, policy key and keyring (${describeNotAfter(notAfter)}) to ${out}`);
}

main();
