// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  decode,
  describeNotAfter,
  keyFileText,
  keyPairMatches,
  provesPath,
  readKeyringFile,
  readLocalRulesFile,
  readProofBundleFile,
  readRootFile,
  rulesHash,
  rulesRoute,
  verifyKeyring,
  verifyRoot,
  WARN_WITHIN_MS,
  type LocalRules,
  type MerkleProof,
  type SignedRoot,
} from "@paztport/core";

/** The service pi signs as: every call and local step, and the hop each run's origin names as its receiver. */
export const PI_SVC = "pi";

/** The service the demo's run origin signs as: the first in every client chain, and the origin its servers accept. */
export const ORIGIN_SVC = "session";

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
  /** The keyring's window, sent as `clientKeyringNotAfter`. */
  keyringNotAfter: number;
  /** The root whole, its own `notAfter` included. */
  signedRoot: SignedRoot;
  /** Keyed by route, "session/pi/mcp:<serverId>.<tool>". */
  proofs: Record<string, MerkleProof>;
  /** The local folder rules, present only when the policy dir holds a rules.json the signed root covers. */
  rules?: LocalRules;
};

/** The fix for a keyring.json or root.json that is unsigned, malformed, expired or not signed as it should be. */
const REGENERATE = "regenerate the demo keys with npm run setup-demo -- --force";

/**
 * Throws unless the window `notAfter` of the file at `path` is current at `now`: at `notAfter` it still is. Called only
 * once the signature over the window has verified, so the window read is the one the policy key signed.
 */
function requireCurrent(path: string, notAfter: number, now: number): void {
  if (!(now <= notAfter)) {
    throw new Error(`${path} expired at ${describeNotAfter(notAfter)}: ${REGENERATE}`);
  }
}

function readText(dir: string, name: string): string {
  try {
    return keyFileText(readFileSync(join(dir, name), "utf8"));
  } catch (e) {
    throw new Error(`cannot read ${name} in ${dir}: ${(e as Error).message}`);
  }
}

/** The file `name` in `dir` as `read` reads it; a file that does not read is refused naming the file and the fix. */
function readAs<T>(dir: string, name: string, read: (bytes: Uint8Array) => T): T {
  let bytes: Uint8Array;
  try {
    bytes = readFileSync(join(dir, name));
  } catch (e) {
    throw new Error(`cannot read ${name} in ${dir}: ${(e as Error).message}`);
  }
  try {
    return read(bytes);
  } catch (e) {
    throw new Error(`malformed ${name} in ${dir}: ${(e as Error).message}: ${REGENERATE}`);
  }
}

/** Returns the key text of a pin file without its surrounding JSON whitespace (the server policy public key). */
export function readPin(path: string): string {
  try {
    return keyFileText(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`cannot read pin file ${path}: ${(e as Error).message}`);
  }
}

/**
 * Loads and validates the files the policy-tool keygen and policy CLIs write for the client mesh
 * (session, pi). Throws a clear Error if they are not mutually consistent. Least privilege: the root
 * is checked with the policy public key alone, so the policy private key (policy.key) is not read.
 * Keys and keyring come from `dir`; root.json, proofs-pi.json and rules.json come from `policyDir` (the client root,
 * or the local-tools root that also binds the folder rules). The keyring must be signed by its policy key over its
 * notAfter, and a rules.json covered by a verifying proof for its hash, or loading fails. The root is read whole; a
 * window that is missing or not an integer is refused. At `now` the keyring and the root must each be current (at
 * their notAfter they still are), each judged only after its signature verified; otherwise loading fails naming the
 * file and the fix. Each with no more than WARN_WITHIN_MS left is passed to `warn` as one line
 * naming the file and its notAfter. The windows are what later checks rely on: the local gate re-reads them per call.
 */
export function loadClientMaterial(dir: string, policyDir: string = dir, now: number = Date.now(), warn: (message: string) => void = console.error): ClientMaterial {
  const ring = readAs(dir, "keyring.json", readKeyringFile);
  const keyring = ring.services;
  const policyPublicKey = ring.policy;
  const keyringSig = ring.sig;
  const keyringNotAfter = ring.notAfter;
  const signedRoot = readAs(policyDir, "root.json", readRootFile);
  const m = {
    sessionKey: readText(dir, "session.key"),
    piKey: readText(dir, "pi.key"),
  };

  if (!verifyRoot(signedRoot, policyPublicKey)) {
    throw new Error("root.json is not signed by the keyring.json policy key");
  }
  const rootPath = join(policyDir, "root.json");
  requireCurrent(rootPath, signedRoot.notAfter, now);
  for (const [svc, key] of [[ORIGIN_SVC, m.sessionKey], ["pi", m.piKey]] as const) {
    if (!Object.hasOwn(keyring, svc)) {
      throw new Error(`keyring.json has no entry for ${svc}`);
    }
    if (!keyPairMatches(key, keyring[svc]!)) {
      throw new Error(`${svc}.key does not match its keyring.json entry`);
    }
  }
  if (!verifyKeyring({ policy: policyPublicKey, services: keyring, sig: keyringSig, notAfter: keyringNotAfter }, policyPublicKey)) {
    throw new Error(`keyring.json is not signed by its policy key: ${REGENERATE}`);
  }
  const ringPath = join(dir, "keyring.json");
  requireCurrent(ringPath, keyringNotAfter, now);

  let rootBytes: Uint8Array;
  try {
    rootBytes = decode(signedRoot.root);
  } catch {
    throw new Error("root.json root is not valid base64url");
  }
  const bundle = readAs(policyDir, "proofs-pi.json", readProofBundleFile);
  const proofs: Record<string, MerkleProof> = {};
  for (const [route, proof] of Object.entries(bundle.proofs)) {
    if (!provesPath(proof, route, rootBytes, signedRoot.rootId)) {
      throw new Error(`proof for ${route} in proofs-pi.json does not verify against root.json`);
    }
    Object.defineProperty(proofs, route, { value: proof, enumerable: true, writable: true, configurable: true });
  }
  const material: ClientMaterial = { ...m, policyPublicKey, keyring, keyringSig, keyringNotAfter, signedRoot, proofs };
  if (existsSync(join(policyDir, "rules.json"))) {
    const rules: LocalRules = readAs(policyDir, "rules.json", readLocalRulesFile);
    // proofs were verified above, so a present key is a proof against the signed root
    if (!Object.hasOwn(proofs, rulesRoute(CLIENT_CHAIN, rulesHash(rules)))) {
      throw new Error("rules.json is not covered by the signed client root");
    }
    material.rules = rules;
  }
  for (const [path, notAfter] of [[ringPath, keyringNotAfter!], [rootPath, signedRoot.notAfter!]] as const) {
    if (notAfter - now <= WARN_WITHIN_MS) {
      warn(`paztport: ${path} expires soon (notAfter ${describeNotAfter(notAfter)}); ${REGENERATE}`);
    }
  }
  return material;
}
