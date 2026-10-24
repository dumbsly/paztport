// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { concat, randomBytes, sha256, utf8 } from "./crypto.ts";

export type MerkleProof = { leafSalt: string; siblings: string[]; dirs: string; rootId: string };

const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

/** SHA-256(0x00 || salt || path). */
export function leafHash(salt: Uint8Array, path: string): Uint8Array {
  return sha256(concat(LEAF, salt, utf8(path)));
}

/** SHA-256(0x01 || left || right). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(NODE, left, right));
}

export function buildTree(
  leaves: { salt: Uint8Array; path: string }[],
  depth: number,
  rootId: string,
): { root: Uint8Array; rootId: string; proofFor(path: string): MerkleProof } {
  const slots = 2 ** depth;
  if (leaves.length > slots) {
    throw new Error(`depth ${depth} holds ${slots} leaves, got ${leaves.length}`);
  }
  const level0: Uint8Array[] = [];
  const indexByPath = new Map<string, number>();
  const saltByPath = new Map<string, string>();
  leaves.forEach((leaf, i) => {
    level0.push(leafHash(leaf.salt, leaf.path));
    indexByPath.set(leaf.path, i);
    saltByPath.set(leaf.path, encode(leaf.salt));
  });
  for (let i = leaves.length; i < slots; i++) {
    level0.push(randomBytes(32)); // opaque padding
  }
  const levels: Uint8Array[][] = [level0];
  let current = level0;
  while (current.length > 1) {
    const parent: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      parent.push(nodeHash(current[i]!, current[i + 1]!));
    }
    levels.push(parent);
    current = parent;
  }
  const root = current[0]!;
  return {
    root: new Uint8Array(root),
    rootId,
    proofFor(path: string): MerkleProof {
      const idx = indexByPath.get(path);
      if (idx === undefined) {
        throw new Error(`no leaf for route ${path}`);
      }
      const siblings: string[] = [];
      let dirs = "";
      let index = idx;
      for (let level = 0; level < levels.length - 1; level++) {
        const working = index % 2 === 0;
        siblings.push(encode(levels[level]![working ? index + 1 : index - 1]!));
        dirs += working ? "L" : "R";
        index = Math.floor(index / 2);
      }
      return { leafSalt: saltByPath.get(path)!, siblings, dirs, rootId };
    },
  };
}

export function verifyProof(proof: MerkleProof, path: string, root: Uint8Array): boolean {
  if (proof.siblings.length !== proof.dirs.length) {
    return false;
  }
  try {
    let working = leafHash(decode(proof.leafSalt), path);
    for (let i = 0; i < proof.siblings.length; i++) {
      const sibling = decode(proof.siblings[i]!);
      working = proof.dirs[i] === "L" ? nodeHash(working, sibling) : nodeHash(sibling, working);
    }
    return Buffer.from(working).equals(Buffer.from(root));
  } catch {
    return false;
  }
}

/** Throws unless value is an object with exactly-typed proof fields. */
export function parseProof(value: unknown): MerkleProof {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("proof must be an object");
  }
  const v = value as Record<string, unknown>;
  if (
    typeof v.leafSalt !== "string" ||
    typeof v.dirs !== "string" ||
    typeof v.rootId !== "string" ||
    !Array.isArray(v.siblings) ||
    !v.siblings.every((s) => typeof s === "string")
  ) {
    throw new Error("malformed proof");
  }
  return { leafSalt: v.leafSalt, siblings: [...(v.siblings as string[])], dirs: v.dirs, rootId: v.rootId };
}

export function encodeProof(p: MerkleProof): string {
  const ordered = { leafSalt: p.leafSalt, siblings: p.siblings, dirs: p.dirs, rootId: p.rootId };
  return encode(utf8(JSON.stringify(ordered)));
}

export function decodeProof(text: string): MerkleProof {
  return parseProof(JSON.parse(Buffer.from(decode(text)).toString("utf8")));
}
