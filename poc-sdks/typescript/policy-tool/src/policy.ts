// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  buildPolicy, DEFAULT_DEPTH, issueReplyCert, keyPairMatches, parseLocalRules, rulesHash, rulesRouteNodes, verifyKeyring, verifyReplyCert,
} from "@paztport/core";
import type { ReplyCert, SignedKeyring } from "@paztport/core";
import { parse } from "yaml";
import { readKey, readKeyring, writeJson } from "./files.ts";

/** The client chain a `local:` block is pinned under: the agents demo's client mesh, its run origin then pi. */
const DEFAULT_CLIENT_CHAIN: readonly string[] = ["session", "pi"];

const USAGE =
  "Usage: node policy.ts --paths <yaml> --policy-key <file> --out <dir> [--depth 8] " +
  "[--reply-cert-svc <name> --keyring <keyring.json> [--reply-cert-days 7]]";

const DAY_MS = 86_400_000;
const DEFAULT_REPLY_CERT_DAYS = 7;
/** How long a root this tool signs stays valid: seven days. */
const DEFAULT_ROOT_DAYS = 7;

/** Route node names become path segments, file names and "/"-joined routes: keep them unambiguous. */
function validNode(n: string): boolean {
  return (
    n.length > 0 &&
    n !== "." &&
    n !== ".." &&
    !n.includes("/") &&
    !n.includes("\\") &&
    !n.includes("|") &&
    !/\p{Surrogate}/u.test(n)
  );
}

function fail(): never {
  console.error(USAGE);
  process.exit(2);
}

function refuse(message: string): never {
  console.error(`policy: refused: ${message}`);
  process.exit(2);
}

/**
 * A reply certificate for `svc`'s key in the keyring, after the checks it vouches for: the keyring verifies under its own policy key,
 * that key is the one in `privateKey`, and the keyring names the service. Refuses, writing nothing, when any fails.
 */
function replyCert(keyringPath: string, svc: string, notAfter: number, privateKey: string): ReplyCert {
  let ring: ReturnType<typeof readKeyring>;
  try {
    ring = readKeyring(keyringPath);
  } catch {
    return refuse(`${keyringPath} is not a keyring`);
  }
  // read whole, so the signature is checked in the keyring's own form, over its notAfter when it has one
  if (typeof ring.sig !== "string" || !verifyKeyring(ring as SignedKeyring, ring.policy)) {
    return refuse(`${keyringPath} is not signed by its policy key`);
  }
  if (!keyPairMatches(privateKey, ring.policy)) return refuse(`${keyringPath} is not signed by this policy key (--policy-key)`);
  const key = Object.hasOwn(ring.services, svc) ? ring.services[svc] : undefined;
  if (typeof key !== "string") return refuse(`${keyringPath} has no key for service ${svc}`);
  const cert = issueReplyCert(ring.policy, svc, key, notAfter, privateKey);
  if (!verifyReplyCert(cert, ring.policy)) return refuse(`the certificate for ${svc} does not verify`);
  return cert;
}

function main(): void {
  let values: {
    paths?: string;
    "policy-key"?: string;
    out?: string;
    depth?: string;
    "reply-cert-svc"?: string;
    keyring?: string;
    "reply-cert-days"?: string;
  };
  try {
    values = parseArgs({
      options: {
        paths: { type: "string" },
        "policy-key": { type: "string" },
        out: { type: "string" },
        depth: { type: "string" },
        "reply-cert-svc": { type: "string" },
        keyring: { type: "string" },
        "reply-cert-days": { type: "string" },
      },
      strict: true,
    }).values;
  } catch {
    return fail();
  }
  const { paths, "policy-key": keyFile, out } = values;
  if (!paths || !keyFile || !out) fail();
  const depth = values.depth === undefined ? DEFAULT_DEPTH : Number(values.depth);
  if (!Number.isInteger(depth) || depth < 1) fail();
  const { "reply-cert-svc": certSvc, keyring: keyringPath } = values;
  if ((certSvc === undefined) !== (keyringPath === undefined)) fail();
  if (certSvc === undefined && values["reply-cert-days"] !== undefined) fail();
  const days = values["reply-cert-days"] === undefined ? DEFAULT_REPLY_CERT_DAYS : Number(values["reply-cert-days"]);
  if (!Number.isSafeInteger(days) || days < 1) fail();
  const notAfter = Date.now() + days * DAY_MS;
  if (!Number.isSafeInteger(notAfter)) fail();

  const doc = parse(readFileSync(paths, "utf8")) as { paths?: unknown; local?: unknown };
  const routes = doc?.paths;
  if (
    !Array.isArray(routes) ||
    !routes.every((r) => Array.isArray(r) && r.length > 0 && r.every((n) => typeof n === "string"))
  ) {
    console.error(`policy: ${paths} must contain "paths: [[svc, ...], ...]"`);
    process.exit(2);
  }
  if (!(routes as string[][]).every((r) => r.every(validNode))) fail();

  // A top-level `local:` block is parsed into the folder rules and bound into the root as one more route.
  const allRoutes = [...(routes as string[][])];
  let rules: ReturnType<typeof parseLocalRules> | undefined;
  if (doc.local !== undefined) {
    if (typeof doc.local !== "object" || doc.local === null || Array.isArray(doc.local)) {
      console.error(`policy: ${paths} "local" must be a mapping`);
      process.exit(2);
    }
    try {
      rules = parseLocalRules({ v: 1, ...doc.local });
    } catch (e) {
      console.error(`policy: ${paths}: ${(e as Error).message}`);
      process.exit(2);
    }
    allRoutes.push(rulesRouteNodes(DEFAULT_CLIENT_CHAIN, rulesHash(rules)));
  }

  const privateKey = readKey(keyFile);
  // Checked before anything is written, so a refused certificate leaves no partial output.
  const cert = certSvc === undefined ? undefined : replyCert(keyringPath!, certSvc, notAfter, privateKey);

  // the routes are the ones the paths file allows now
  const { signedRoot, bundles } = buildPolicy(allRoutes, depth, privateKey, Date.now() + DEFAULT_ROOT_DAYS * DAY_MS);
  if (rules !== undefined) writeJson(join(out, "rules.json"), rules);
  writeJson(join(out, "root.json"), signedRoot);
  for (const bundle of Object.values(bundles)) {
    writeJson(join(out, `proofs-${bundle.service}.json`), bundle);
  }
  if (cert !== undefined) writeJson(join(out, "reply-cert.json"), cert);
  console.log(`policy: wrote root ${signedRoot.rootId}, notAfter ${signedRoot.notAfter} (${new Date(signedRoot.notAfter!).toISOString()}), and per-service bundles to ${out}`);
  if (cert !== undefined) {
    console.log(`policy: wrote reply certificate for ${cert.svc}, notAfter ${cert.notAfter} (${new Date(cert.notAfter).toISOString()})`);
  }
}

main();
