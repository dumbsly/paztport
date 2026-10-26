// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { buildTree, SALT_BYTES } from "./merkle.ts";
import type { MerkleProof } from "./merkle.ts";
import { randomBytes, sha256, utf8 } from "./crypto.ts";
import { signRoot } from "./root.ts";
import { routeOf } from "./routes.ts";
import type { SignedRoot } from "./root.ts";

export const DEFAULT_DEPTH = 8;

export type ProofBundle = { service: string; rootId: string; proofs: Record<string, MerkleProof> };

/** "v" + first 12 hex of SHA-256(routes joined by newline, in file order). */
export function deriveRootId(routes: string[]): string {
  return "v" + Buffer.from(sha256(utf8(routes.join("\n")))).toString("hex").slice(0, 12);
}

export function buildPolicy(
  routes: string[][],
  depth: number,
  policyPrivateKey: string,
): { signedRoot: SignedRoot; bundles: Record<string, ProofBundle> } {
  const routeStrings = routes.map((r) => routeOf(r));
  const rootId = deriveRootId(routeStrings);
  const tree = buildTree(
    routeStrings.map((path) => ({ salt: randomBytes(SALT_BYTES), path })),
    depth,
    rootId,
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
