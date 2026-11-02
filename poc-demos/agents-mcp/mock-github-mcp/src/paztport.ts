// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  decode,
  keyFileText,
  readKeyringFile,
  readProofBundleFile,
  readReplyCertFile,
  readRootFile,
  routeOf,
  type ReplyCert,
} from "@paztport/core";
import { checkServerPolicy, type ServerPolicy } from "@paztport/mcp";

/** The two simulated services this server signs every response as, entry first. */
const HOPS = ["mcp-entry", "github-tools"] as const;
const ROUTE = routeOf(HOPS);
/** The fix for files that are missing, malformed, expired, or that do not agree with each other. */
const REGENERATE = "regenerate the demo keys with npm run setup-demo -- --force";

function readText(path: string): string {
  return keyFileText(readFileSync(path, "utf8"));
}

/** Whether `key` decodes as an Ed25519 SPKI public key, the form the policy-tool writes; never throws. */
function isPublicKey(key: string): boolean {
  try {
    return createPublicKey({ key: Buffer.from(decode(key)), format: "der", type: "spki" }).asymmetricKeyType === "ed25519";
  } catch {
    return false;
  }
}

/** Runs the SDK's whole server-policy check at `now`; its refusal is passed on with where the files came from and the fix. */
function validateServerConfig(cfg: ServerPolicy, dir: string, now: number): void {
  try {
    checkServerPolicy(cfg, now);
  } catch (e) {
    throw new Error(`${(e as Error).message} (loaded from ${dir}): ${REGENERATE}`);
  }
}

/** The file `name` in `dir` as `read` reads it; a file that does not read is refused naming the file and the fix. */
function readAs<T>(dir: string, name: string, read: (bytes: Uint8Array) => T): T {
  const bytes = readFileSync(join(dir, name));
  try {
    return read(bytes);
  } catch (e) {
    throw new Error(`malformed ${name} in ${dir}: ${(e as Error).message}: ${REGENERATE}`);
  }
}

/** Reads reply-cert.json; a missing or malformed one throws naming the fix. */
function readReplyCert(path: string): ReplyCert {
  if (!existsSync(path)) {
    throw new Error(`${path} is missing: ${REGENERATE}`);
  }
  try {
    return readReplyCertFile(readFileSync(path));
  } catch {
    throw new Error(`${path} is not a reply certificate: ${REGENERATE}`);
  }
}

/**
 * Loads and validates the files the policy-tool keygen and policy CLIs write into one directory, including the
 * reply certificate, and the client policy key the server pins (client-policy.pub, written by setup-demo). It reads
 * no policy private key, and leaves every judgement of the material, its signatures, lifetime and agreement, to the
 * SDK's checkServerPolicy at `now`. The root is read whole and the keyring's window kept; a window that is missing or
 * not an integer is refused.
 */
export function loadServerConfig(dir: string, now: number = Date.now()): ServerPolicy {
  const ring = readAs(dir, "keyring.json", readKeyringFile);
  const signedRoot = readAs(dir, "root.json", readRootFile);
  const bundle = readAs(dir, "proofs-mcp-entry.json", readProofBundleFile);
  const routeProof = Object.hasOwn(bundle.proofs, ROUTE) ? bundle.proofs[ROUTE] : undefined;
  if (routeProof === undefined) {
    throw new Error(`proofs-mcp-entry.json has no proof for ${ROUTE}`);
  }
  const certPath = join(dir, "reply-cert.json");
  const replyCert = readReplyCert(certPath);
  const pinPath = join(dir, "client-policy.pub");
  if (!existsSync(pinPath)) {
    throw new Error(`${pinPath} is missing: regenerate the demo keys with npm run setup-demo -- --force`);
  }
  const clientPin = readText(pinPath);
  if (!isPublicKey(clientPin)) {
    throw new Error(`${pinPath} is not a public key: regenerate the demo keys with npm run setup-demo -- --force`);
  }
  const cfg: ServerPolicy = {
    policyPublicKey: ring.policy,
    signingKeys: { "mcp-entry": readText(join(dir, "mcp-entry.key")), "github-tools": readText(join(dir, "github-tools.key")) },
    keyring: ring.services,
    keyringSig: ring.sig,
    keyringNotAfter: ring.notAfter,
    replyCert,
    signedRoot,
    routeProof,
    inst: "mock-github-1",
    hops: HOPS,
    serverId: "github",
    pinnedClientKeys: [clientPin],
    // the demo client's run origin signs as "session" (setup-demo names it in the client chain)
    clientOrigins: ["session"],
  };
  validateServerConfig(cfg, dir, now);
  return cfg;
}
