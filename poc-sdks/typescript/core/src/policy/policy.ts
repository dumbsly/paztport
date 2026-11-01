// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { buildTree, parseProof, SALT_BYTES } from "./merkle.ts";
import type { MerkleProof } from "./merkle.ts";
import { randomInt } from "node:crypto";
import { randomBytes } from "../crypto/crypto.ts";
import { readFile } from "../encoding/json.ts";
import { exactly, object, str } from "../internal/fields.ts";
import { signRoot } from "./root.ts";
import { requireValidNode, routeOf } from "./routes.ts";
import type { SignedRoot } from "./root.ts";

export const DEFAULT_DEPTH = 8;

export type ProofBundle = { service: string; rootId: string; proofs: Record<string, MerkleProof> };

/** "v" + 12 lowercase hex of 6 random bytes: a fresh label per build, compared and never derived. */
export function newRootId(): string {
  return "v" + Buffer.from(randomBytes(6)).toString("hex");
}

/** The first `n` of a uniform Fisher-Yates shuffle of all `2 ** depth` slots. */
function randomSlots(n: number, depth: number): number[] {
  const total = 2 ** depth;
  if (n > total) {
    throw new Error(`depth ${depth} holds ${total} leaves, got ${n}`);
  }
  const all = Array.from({ length: total }, (_, i) => i);
  for (let i = total - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [all[i], all[j]] = [all[j]!, all[i]!];
  }
  return all.slice(0, n);
}

/** A fresh tree over `routes` and its root signed until `notAfter`, with each service's proof bundle; the caller must currently allow every route, and throws on a route node requireValidNode refuses, a route with no caller or a bad `notAfter`. */
export function buildPolicy(
  routes: string[][],
  depth: number,
  policyPrivateKey: string,
  notAfter: number,
): { signedRoot: SignedRoot; bundles: Record<string, ProofBundle> } {
  for (const route of routes) for (const node of route) requireValidNode(node);
  const routeStrings = routes.map((r) => routeOf(r));
  const rootId = newRootId();
  const tree = buildTree(
    routeStrings.map((path) => ({ salt: randomBytes(SALT_BYTES), path })),
    depth,
    rootId,
    randomSlots(routeStrings.length, depth),
  );
  const signedRoot = signRoot(tree.root, rootId, policyPrivateKey, notAfter);

  const proofsByService = new Map<string, Record<string, MerkleProof>>();
  for (const route of routes) {
    for (const node of route) {
      if (!proofsByService.has(node)) proofsByService.set(node, {});
    }
  }
  routes.forEach((route, i) => {
    if (route.length < 2) {
      throw new Error(`route has no caller (needs >= 2 nodes): ${JSON.stringify(route)}`);
    }
    const holder = route[route.length - 2]!;
    proofsByService.get(holder)![routeStrings[i]!] = tree.proofFor(routeStrings[i]!);
  });

  const bundles: Record<string, ProofBundle> = {};
  for (const [service, proofs] of proofsByService) {
    bundles[service] = { service, rootId, proofs };
  }
  return { signedRoot, bundles };
}

/** Whether `route` is a route: at least two nodes joined by `/`, each a node requireValidNode allows. */
function isRoute(route: string): boolean {
  const nodes = route.split("/");
  try {
    nodes.forEach(requireValidNode);
  } catch {
    return false;
  }
  return nodes.length >= 2;
}

/**
 * Reads `proofs-<svc>.json` in any member order and spacing: exactly a string `service`, a string `rootId` and a
 * `proofs` object, each of whose names is a route and each of whose values a proof object. MalformedJson for bytes
 * that do not read, an Error naming the member for a bundle the schema refuses.
 */
export function readProofBundleFile(bytes: Uint8Array): ProofBundle {
  const o = object(readFile(bytes));
  exactly(o, ["proofs", "rootId", "service"]);
  const byRoute = object(o, "proofs");
  const proofs: Record<string, MerkleProof> = Object.create(null);
  for (const route of Object.keys(byRoute)) {
    if (!isRoute(route)) throw new Error("member proofs holds a name that is not a route");
    proofs[route] = parseProof(byRoute[route]);
  }
  return { service: str(o, "service"), rootId: str(o, "rootId"), proofs };
}
