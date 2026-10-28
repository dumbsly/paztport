// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { buildTree, SALT_BYTES } from "./merkle.ts";
import type { MerkleProof } from "./merkle.ts";
import { randomInt } from "node:crypto";
import { randomBytes } from "./crypto.ts";
import { signRoot } from "./root.ts";
import { routeOf } from "./routes.ts";
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

export function buildPolicy(
  routes: string[][],
  depth: number,
  policyPrivateKey: string,
): { signedRoot: SignedRoot; bundles: Record<string, ProofBundle> } {
  const routeStrings = routes.map((r) => routeOf(r));
  const rootId = newRootId();
  const tree = buildTree(
    routeStrings.map((path) => ({ salt: randomBytes(SALT_BYTES), path })),
    depth,
    rootId,
    randomSlots(routeStrings.length, depth),
  );
  const signedRoot = signRoot(tree.root, rootId, policyPrivateKey);

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
