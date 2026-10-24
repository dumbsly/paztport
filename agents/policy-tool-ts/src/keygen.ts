// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { join } from "node:path";
import { parseArgs } from "node:util";
import { generateKeyPair } from "@paztport/path-attest";
import { writeJson, writePrivate } from "./files.ts";

const USAGE = "Usage: node keygen.ts --out <dir> --services a,b,c";

function main(): void {
  let out: string | undefined;
  let services: string | undefined;
  try {
    ({ out, services } = parseArgs({
      options: { out: { type: "string" }, services: { type: "string" } },
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
  if (!out || names.length === 0 || bad) {
    console.error(USAGE);
    process.exit(2);
  }

  const ring: { services: Record<string, string>; policy: string } = { services: {}, policy: "" };
  for (const svc of names) {
    const kp = generateKeyPair();
    writePrivate(join(out, `${svc}.key`), kp.privateKey);
    ring.services[svc] = kp.publicKey;
  }
  const policy = generateKeyPair();
  writePrivate(join(out, "policy.key"), policy.privateKey);
  ring.policy = policy.publicKey;
  writeJson(join(out, "keyring.json"), ring);
  console.log(`keygen: wrote ${names.length} service keys, policy key and keyring to ${out}`);
}

main();
