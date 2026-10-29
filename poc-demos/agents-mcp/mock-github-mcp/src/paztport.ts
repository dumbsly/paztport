// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  decode,
  isReplyCert,
  parseProof,
  parseSignedRoot,
  readNotAfter,
  routeOf,
  type MerkleProof,
  type ReplyCert,
  type SignedRoot,
} from "@paztport/core";
import { checkServerPolicy, type ServerPolicy } from "@paztport/mcp";

/** The two simulated services this server signs every response as, entry first. */
const HOPS = ["mcp-entry", "github-tools"] as const;
const ROUTE = routeOf(HOPS);
/** The fix for files from an older setup, or ones that no longer hold together. */
const REGENERATE = "regenerate the demo keys with npm run setup-demo -- --force";

function readText(path: string): string {
  return readFileSync(path, "utf8").trim();
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown, what: string): string {
  if (typeof v !== "string") {
    throw new Error(`${what} must be a string`);
  }
  return v;
}

/** Copies a string map into an object whose keys (even "__proto__") are ordinary own properties. */
function stringMap(v: Record<string, unknown>, what: string): Record<string, string> {
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, str(x, `${what} entry ${k}`)]));
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

/** Reads reply-cert.json; a missing or malformed one throws naming the fix. */
function readReplyCert(path: string): ReplyCert {
  if (!existsSync(path)) {
    throw new Error(`${path} is missing: ${REGENERATE}`);
  }
  let cert: unknown;
  try {
    cert = readJson(path);
  } catch {
    cert = undefined;
  }
  if (!isReplyCert(cert)) {
    throw new Error(`${path} is not a reply certificate: ${REGENERATE}`);
  }
  return cert;
}

/** Runs `read`, passing on its error after `prefix` and with the fix: a damaged keyring or root window is one regenerating repairs. */
function withFix<T>(read: () => T, prefix = ""): T {
  try {
    return read();
  } catch (e) {
    throw new Error(`${prefix}${(e as Error).message}: ${REGENERATE}`);
  }
}

/**
 * Loads and validates the files the policy-tool keygen and policy CLIs write into one directory, including the
 * reply certificate, and the client policy key the server pins (client-policy.pub, written by setup-demo). It reads
 * no policy private key, and leaves every judgement of the material, its signatures, lifetime and agreement, to the
 * SDK's checkServerPolicy at `now`. The root is read whole and the keyring's window kept; a window that is not an
 * integer is refused.
 */
export function loadServerConfig(dir: string, now: number = Date.now()): ServerPolicy {
  const ring = readJson(join(dir, "keyring.json"));
  if (!isObject(ring) || !isObject(ring.services)) {
    throw new Error("malformed keyring.json");
  }
  const keyring = stringMap(ring.services, "keyring");
  const keyringNotAfter = withFix(() => readNotAfter(ring, "notAfter"), "keyring.json ");
  const root = readJson(join(dir, "root.json"));
  if (!isObject(root)) {
    throw new Error("malformed root.json");
  }
  const signedRoot: SignedRoot = withFix(() => parseSignedRoot(root, "root.json"));
  const bundle = readJson(join(dir, "proofs-mcp-entry.json"));
  const rawProof = isObject(bundle) && isObject(bundle.proofs) && Object.hasOwn(bundle.proofs, ROUTE) ? bundle.proofs[ROUTE] : undefined;
  if (rawProof === undefined) {
    throw new Error(`proofs-mcp-entry.json has no proof for ${ROUTE}`);
  }
  let routeProof: MerkleProof;
  try {
    routeProof = parseProof(rawProof);
  } catch (e) {
    throw new Error(`malformed route proof for ${ROUTE} in proofs-mcp-entry.json: ${(e as Error).message}`);
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
    policyPublicKey: str(ring.policy, "keyring policy"),
    signingKeys: { "mcp-entry": readText(join(dir, "mcp-entry.key")), "github-tools": readText(join(dir, "github-tools.key")) },
    keyring,
    // an unsigned keyring reads as "", which never verifies
    keyringSig: typeof ring.sig === "string" ? ring.sig : "",
    // an old-form keyring has none; checkServerPolicy refuses that with the fix
    keyringNotAfter: keyringNotAfter as number,
    replyCert,
    signedRoot,
    routeProof,
    inst: "mock-github-1",
    hops: HOPS,
    serverId: "github",
    pinnedClientKeys: [clientPin],
  };
  validateServerConfig(cfg, dir, now);
  return cfg;
}
