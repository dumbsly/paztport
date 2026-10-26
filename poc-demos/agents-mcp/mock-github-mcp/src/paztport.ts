// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { decode, keyPairMatches, parseProof, provesPath, routeOf, verifyRoot, type MerkleProof, type SignedRoot } from "@paztport/core";
import type { ServerPolicy } from "@paztport/mcp";

/** The two simulated services this server signs every response as, entry first. */
const HOPS = ["mcp-entry", "github-tools"] as const;
const ROUTE = routeOf(HOPS);

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

/** Throws a clear Error unless the loaded files are mutually consistent. */
function validateServerConfig(cfg: ServerPolicy): void {
  if (!verifyRoot(cfg.signedRoot, cfg.policyPublicKey)) {
    throw new Error("root.json is not signed by the keyring.json policy key");
  }
  if (!keyPairMatches(cfg.policyPrivateKey, cfg.policyPublicKey)) {
    throw new Error("policy.key does not match the keyring.json policy key");
  }
  for (const svc of HOPS) {
    if (!Object.hasOwn(cfg.keyring, svc)) {
      throw new Error(`keyring.json has no entry for ${svc}`);
    }
    if (!keyPairMatches(cfg.signingKeys[svc]!, cfg.keyring[svc]!)) {
      throw new Error(`${svc}.key does not match its keyring.json entry`);
    }
  }
  let rootBytes: Uint8Array;
  try {
    rootBytes = decode(cfg.signedRoot.root);
  } catch {
    throw new Error("root.json root is not valid base64url");
  }
  if (!provesPath(cfg.routeProof, ROUTE, rootBytes, cfg.signedRoot.rootId)) {
    throw new Error(`route proof for ${ROUTE} does not verify against root.json`);
  }
}

/** Loads and validates the files the policy-tool keygen and policy CLIs write into one directory. */
export function loadServerConfig(dir: string): ServerPolicy {
  const ring = readJson(join(dir, "keyring.json"));
  if (!isObject(ring) || !isObject(ring.services)) {
    throw new Error("malformed keyring.json");
  }
  const keyring = stringMap(ring.services, "keyring");
  const root = readJson(join(dir, "root.json"));
  if (!isObject(root)) {
    throw new Error("malformed root.json");
  }
  const signedRoot: SignedRoot = { rootId: str(root.rootId, "rootId"), root: str(root.root, "root"), sig: str(root.sig, "sig") };
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
  const cfg: ServerPolicy = {
    policyPrivateKey: readText(join(dir, "policy.key")),
    policyPublicKey: str(ring.policy, "keyring policy"),
    signingKeys: { "mcp-entry": readText(join(dir, "mcp-entry.key")), "github-tools": readText(join(dir, "github-tools.key")) },
    keyring,
    signedRoot,
    routeProof,
    inst: "mock-github-1",
    hops: HOPS,
    serverId: "github",
  };
  validateServerConfig(cfg);
  return cfg;
}
