// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  buildPolicy, DEFAULT_DEPTH, describeNotAfter, signReplyCert, keyPairMatches, parseLocalRules, parseSignedRoot, renewKeyring, signRenewedRoot, rulesHash, rulesRouteNodes,
  verifyKeyring, verifyReplyCert, verifyRoot,
} from "@paztport/core";
import type { ReplyCert, SignedKeyring, SignedRoot } from "@paztport/core";
import { parse } from "yaml";
import { notAfterInDays, readJson, readKey, readKeyring, writeJson, writeKeyring } from "./files.ts";

const USAGE =
  "Usage: node policy.ts --paths <yaml> --policy-key <file> --keyring <keyring.json> --out <dir> [--depth 8] [--policy-days 7] " +
  "[--reply-cert-svc <name> [--reply-cert-days 7]] [--client-chain <svc,svc,...>]\n" +
  "       node policy.ts --renew --policy-key <file> --keyring <keyring.json> --out <dir> [--policy-days 7] " +
  "[--reply-cert-svc <name> [--reply-cert-days 7]]";

const DEFAULT_REPLY_CERT_DAYS = 7;
/** How long a root and keyring this tool signs stay valid unless `--policy-days` says otherwise: seven days. */
const DEFAULT_POLICY_DAYS = 7;

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
 * The keyring at `keyringPath` re-signed until `notAfter`, after the checks re-signing rests on: it verifies under the policy key it names,
 * in either form and expired or not, and that key is the one in `privateKey`. Re-signing vouches that each listed key is still its
 * service's current key; the tool can check only that this policy key vouched for them before, so that none has been retired since is
 * the policy owner's to ensure. Refuses, writing nothing, when any check fails.
 */
function renewedKeyring(keyringPath: string, notAfter: number, privateKey: string): SignedKeyring {
  let ring: ReturnType<typeof readKeyring>;
  try {
    ring = readKeyring(keyringPath);
  } catch {
    return refuse(`${keyringPath} is missing or not a keyring`);
  }
  // read whole, so the signature is checked in the keyring's own form, over its notAfter when it has one
  if (typeof ring.sig !== "string" || !verifyKeyring(ring as SignedKeyring, ring.policy)) {
    return refuse(`${keyringPath} is not signed by its policy key`);
  }
  if (!keyPairMatches(privateKey, ring.policy)) return refuse(`${keyringPath} is not signed by this policy key (--policy-key)`);
  return renewKeyring(ring as SignedKeyring, notAfter, privateKey);
}

/** A reply certificate for `svc`'s key in `ring`, already checked to be this policy key's keyring; refuses a service the keyring lacks. */
function replyCert(ring: SignedKeyring, keyringPath: string, svc: string, notAfter: number, privateKey: string): ReplyCert {
  const key = Object.hasOwn(ring.services, svc) ? ring.services[svc] : undefined;
  if (typeof key !== "string") return refuse(`${keyringPath} has no key for service ${svc}`);
  const cert = signReplyCert(ring.policy, svc, key, notAfter, privateKey);
  if (!verifyReplyCert(cert, ring.policy)) return refuse(`the certificate for ${svc} does not verify`);
  return cert;
}

/** The routes in the paths file, plus the rules route under `clientChain` when it has a `local:` block (which needs one); exits 2 on a malformed file. */
function readRoutes(paths: string, clientChain: readonly string[] | undefined): { routes: string[][]; rules?: ReturnType<typeof parseLocalRules> } {
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
  if (doc.local === undefined) return { routes: allRoutes };
  if (typeof doc.local !== "object" || doc.local === null || Array.isArray(doc.local)) {
    console.error(`policy: ${paths} "local" must be a mapping`);
    process.exit(2);
  }
  if (clientChain === undefined) {
    console.error(`policy: ${paths} has a "local" block, which is pinned under the client chain: pass --client-chain <svc,svc,...>`);
    process.exit(2);
  }
  let rules: ReturnType<typeof parseLocalRules>;
  try {
    rules = parseLocalRules({ v: 1, ...doc.local });
  } catch (e) {
    console.error(`policy: ${paths}: ${(e as Error).message}`);
    process.exit(2);
  }
  allRoutes.push(rulesRouteNodes(clientChain, rulesHash(rules)));
  return { routes: allRoutes, rules };
}

/** The root in `out`, re-signed until `notAfter` with its `root` and `rootId` kept, after checking it verifies under `ring`'s policy key in either form, expired or not. */
function renewedRoot(out: string, ring: SignedKeyring, notAfter: number, privateKey: string): SignedRoot {
  const rootPath = join(out, "root.json");
  let root: SignedRoot;
  try {
    root = parseSignedRoot(readJson<unknown>(rootPath), "root.json");
  } catch {
    return refuse(`${rootPath} is missing or not a signed root`);
  }
  if (!verifyRoot(root, ring.policy)) return refuse(`${rootPath} is not signed by this policy key (--policy-key)`);
  // renewing vouches that every route in the existing tree is still allowed: a narrowed policy is a rebuild, never a renewal
  return signRenewedRoot(root, notAfter, privateKey);
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
    "policy-days"?: string;
    renew?: boolean;
    "client-chain"?: string;
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
        "policy-days": { type: "string" },
        renew: { type: "boolean" },
        "client-chain": { type: "string" },
      },
      strict: true,
    }).values;
  } catch {
    return fail();
  }
  const { paths, "policy-key": keyFile, out, keyring: keyringPath, "reply-cert-svc": certSvc } = values;
  const renew = values.renew === true;
  if (!keyFile || !out || !keyringPath) fail();
  // renewing keeps the tree, so it takes no paths file and no depth
  if (renew ? paths !== undefined || values.depth !== undefined : !paths) fail();
  const depth = values.depth === undefined ? DEFAULT_DEPTH : Number(values.depth);
  if (!Number.isInteger(depth) || depth < 1) fail();
  if (certSvc === undefined && values["reply-cert-days"] !== undefined) fail();
  const certNotAfter = notAfterInDays(values["reply-cert-days"], DEFAULT_REPLY_CERT_DAYS);
  const policyNotAfter = notAfterInDays(values["policy-days"], DEFAULT_POLICY_DAYS);
  if (certNotAfter === undefined || policyNotAfter === undefined) fail();

  const clientChain = values["client-chain"]?.split(",");
  if (clientChain !== undefined && (renew || clientChain.length === 0 || !clientChain.every(validNode))) fail();
  const built = renew ? undefined : readRoutes(paths!, clientChain);
  const privateKey = readKey(keyFile);
  // Everything is checked before anything is written, so a refusal leaves no partial output.
  const ring = renewedKeyring(keyringPath, policyNotAfter, privateKey);
  const cert = certSvc === undefined ? undefined : replyCert(ring, keyringPath, certSvc, certNotAfter, privateKey);
  let signedRoot: SignedRoot;
  let bundles: ReturnType<typeof buildPolicy>["bundles"] = {};
  if (built === undefined) {
    signedRoot = renewedRoot(out, ring, policyNotAfter, privateKey);
  } else {
    // the routes are the ones the paths file allows now
    ({ signedRoot, bundles } = buildPolicy(built.routes, depth, privateKey, policyNotAfter));
  }

  // the keyring first: of all the writes, it is the one a read-only file would refuse, and renewing it alone harms nothing
  writeKeyring(keyringPath, ring);
  if (built?.rules !== undefined) writeJson(join(out, "rules.json"), built.rules);
  writeJson(join(out, "root.json"), signedRoot);
  for (const bundle of Object.values(bundles)) {
    writeJson(join(out, `proofs-${bundle.service}.json`), bundle);
  }
  if (cert !== undefined) writeJson(join(out, "reply-cert.json"), cert);
  const files = `${join(out, "root.json")} and ${keyringPath}, notAfter ${describeNotAfter(policyNotAfter)}`;
  console.log(renew ? `policy: renewed ${files}; proof bundles in ${out} unchanged` : `policy: wrote ${files}, and per-service bundles to ${out}`);
  if (cert !== undefined) console.log(`policy: wrote ${join(out, "reply-cert.json")} for ${cert.svc}, notAfter ${describeNotAfter(cert.notAfter)}`);
}

main();
