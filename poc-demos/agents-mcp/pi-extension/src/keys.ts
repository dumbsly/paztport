// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  decode,
  keyPairMatches,
  parseLocalRules,
  parseProof,
  ORIGIN_SVC,
  provesPath,
  rulesHash,
  rulesRoute,
  verifyKeyring,
  verifyRoot,
  type LocalRules,
  type MerkleProof,
  type SignedRoot,
} from "@paztport/core";

/** The service pi signs as: every call and local step, and the hop each run's origin names as its receiver. */
export const PI_SVC = "pi";

/** The client chain on every stamped call: the run's origin, then pi. Local rules are pinned under it too. */
export const CLIENT_CHAIN: readonly string[] = [ORIGIN_SVC, PI_SVC];

export type ClientMaterial = {
  sessionKey: string;
  piKey: string;
  /** The client policy public key; the policy private key (policy.key) is never read. */
  policyPublicKey: string;
  keyring: Record<string, string>;
  /** The policy key's signature over the keyring, sent in the session request. */
  keyringSig: string;
  signedRoot: SignedRoot;
  /** Keyed by route, "session/pi/mcp:<serverId>.<tool>". */
  proofs: Record<string, MerkleProof>;
  /** The local folder rules, present only when the policy dir holds a rules.json the signed root covers. */
  rules?: LocalRules;
};

function readText(dir: string, name: string): string {
  try {
    return readFileSync(join(dir, name), "utf8").trim();
  } catch (e) {
    throw new Error(`cannot read ${name} in ${dir}: ${(e as Error).message}`);
  }
}

function readJson(dir: string, name: string): unknown {
  try {
    return JSON.parse(readText(dir, name));
  } catch (e) {
    throw new Error(`cannot parse ${name} in ${dir}: ${(e as Error).message}`);
  }
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

/** Returns the trimmed key text of a pin file (the server policy public key). */
export function readPin(path: string): string {
  try {
    return readFileSync(path, "utf8").trim();
  } catch (e) {
    throw new Error(`cannot read pin file ${path}: ${(e as Error).message}`);
  }
}

/**
 * Loads and validates the files the policy-tool keygen and policy CLIs write for the client mesh
 * (session, pi). Throws a clear Error if they are not mutually consistent. Least privilege: the root
 * is checked with the policy public key alone, so the policy private key (policy.key) is not read.
 * Keys and keyring come from `dir`; root.json, proofs-pi.json and rules.json come from `policyDir`. The
 * keyring must be signed by its policy key, and a rules.json covered by a verifying proof for its hash, or
 * loading fails.
 */
export function loadClientMaterial(dir: string, policyDir: string = dir): ClientMaterial {
  const ring = readJson(dir, "keyring.json");
  if (!isObject(ring) || !isObject(ring.services)) {
    throw new Error("malformed keyring.json");
  }
  const keyring = Object.fromEntries(Object.entries(ring.services).map(([k, v]) => [k, str(v, `keyring.json entry ${k}`)]));
  const policyPublicKey = str(ring.policy, "keyring.json policy");
  if (ring.sig === undefined) {
    throw new Error(`${join(dir, "keyring.json")} has no sig: regenerate the demo keys with npm run setup-demo -- --force`);
  }
  const keyringSig = str(ring.sig, "keyring.json sig");
  const root = readJson(policyDir, "root.json");
  if (!isObject(root)) {
    throw new Error("malformed root.json");
  }
  const signedRoot: SignedRoot = { rootId: str(root.rootId, "root.json rootId"), root: str(root.root, "root.json root"), sig: str(root.sig, "root.json sig") };
  const m = {
    sessionKey: readText(dir, "session.key"),
    piKey: readText(dir, "pi.key"),
  };

  if (!verifyRoot(signedRoot, policyPublicKey)) {
    throw new Error("root.json is not signed by the keyring.json policy key");
  }
  for (const [svc, key] of [["session", m.sessionKey], ["pi", m.piKey]] as const) {
    if (!Object.hasOwn(keyring, svc)) {
      throw new Error(`keyring.json has no entry for ${svc}`);
    }
    if (!keyPairMatches(key, keyring[svc]!)) {
      throw new Error(`${svc}.key does not match its keyring.json entry`);
    }
  }
  if (!verifyKeyring({ policy: policyPublicKey, services: keyring, sig: keyringSig }, policyPublicKey)) {
    throw new Error("keyring.json is not signed by its policy key");
  }

  let rootBytes: Uint8Array;
  try {
    rootBytes = decode(signedRoot.root);
  } catch {
    throw new Error("root.json root is not valid base64url");
  }
  const bundle = readJson(policyDir, "proofs-pi.json");
  if (!isObject(bundle) || !isObject(bundle.proofs)) {
    throw new Error("malformed proofs-pi.json");
  }
  const proofs: Record<string, MerkleProof> = {};
  for (const [route, raw] of Object.entries(bundle.proofs)) {
    let proof: MerkleProof;
    try {
      proof = parseProof(raw);
    } catch (e) {
      throw new Error(`malformed proof for ${route} in proofs-pi.json: ${(e as Error).message}`);
    }
    if (!provesPath(proof, route, rootBytes, signedRoot.rootId)) {
      throw new Error(`proof for ${route} in proofs-pi.json does not verify against root.json`);
    }
    Object.defineProperty(proofs, route, { value: proof, enumerable: true, writable: true, configurable: true });
  }
  const material: ClientMaterial = { ...m, policyPublicKey, keyring, keyringSig, signedRoot, proofs };
  if (existsSync(join(policyDir, "rules.json"))) {
    let rules: LocalRules;
    try {
      rules = parseLocalRules(readJson(policyDir, "rules.json"));
    } catch (e) {
      throw new Error(`malformed rules.json in ${policyDir}: ${(e as Error).message}`);
    }
    // proofs were verified above, so a present key is a proof against the signed root
    if (!Object.hasOwn(proofs, rulesRoute(CLIENT_CHAIN, rulesHash(rules)))) {
      throw new Error("rules.json is not covered by the signed client root");
    }
    material.rules = rules;
  }
  return material;
}
