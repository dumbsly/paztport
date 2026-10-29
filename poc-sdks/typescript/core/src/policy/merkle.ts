// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, randomBytes, sha256, utf8 } from "../crypto/crypto.ts";

export type MerkleProof = { leafSalt: string; siblings: string[]; dirs: string; rootId: string };

export const SALT_BYTES = 16;
const HASH_BYTES = 32;
const DIRS = /^[LR]*$/;

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

/** Builds the padded tree; `slots[i]` is leaf i's position (distinct, in range), default `0..n-1`. */
export function buildTree(
  leaves: { salt: Uint8Array; path: string }[],
  depth: number,
  rootId: string,
  slots?: readonly number[],
): { root: Uint8Array; rootId: string; proofFor(path: string): MerkleProof } {
  const total = 2 ** depth;
  if (leaves.length > total) {
    throw new Error(`depth ${depth} holds ${total} leaves, got ${leaves.length}`);
  }
  const placed = slots ?? leaves.map((_, i) => i);
  if (placed.length !== leaves.length) {
    throw new Error(`${leaves.length} leaves need ${leaves.length} slots, got ${placed.length}`);
  }
  const level0: Uint8Array[] = Array.from({ length: total }, () => randomBytes(32)); // opaque padding
  const indexByPath = new Map<string, number>();
  const saltByPath = new Map<string, string>();
  const used = new Set<number>();
  leaves.forEach((leaf, i) => {
    const slot = placed[i]!;
    if (!Number.isInteger(slot) || slot < 0 || slot >= total) {
      throw new Error(`slot ${slot} is outside 0..${total - 1}`);
    }
    if (used.has(slot)) {
      throw new Error(`slot ${slot} is used twice`);
    }
    used.add(slot);
    level0[slot] = leafHash(leaf.salt, leaf.path);
    indexByPath.set(leaf.path, slot);
    saltByPath.set(leaf.path, encode(leaf.salt));
  });
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

/** False unless the proof has a 16-byte salt, 32-byte siblings, L/R dirs, and hashes path up to root. */
export function verifyProof(proof: MerkleProof, path: string, root: Uint8Array): boolean {
  try {
    if (proof.siblings.length !== proof.dirs.length || !DIRS.test(proof.dirs)) {
      return false;
    }
    const salt = decode(proof.leafSalt);
    if (salt.length !== SALT_BYTES) {
      return false;
    }
    let working = leafHash(salt, path);
    for (let i = 0; i < proof.siblings.length; i++) {
      const sibling = decode(proof.siblings[i]!);
      if (sibling.length !== HASH_BYTES) {
        return false;
      }
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
    !v.siblings.every((s) => typeof s === "string") ||
    !DIRS.test(v.dirs)
  ) {
    throw new Error("malformed proof");
  }
  return { leafSalt: v.leafSalt, siblings: [...(v.siblings as string[])], dirs: v.dirs, rootId: v.rootId };
}

/** Whether `value` is a proof for the root named `rootId` that proves `path` against `root`. Never throws. */
export function provesPath(value: unknown, path: string, root: Uint8Array, rootId: string): boolean {
  try {
    const proof = parseProof(value);
    return proof.rootId === rootId && verifyProof(proof, path, root);
  } catch {
    return false;
  }
}

export function encodeProof(p: MerkleProof): string {
  const ordered = { leafSalt: p.leafSalt, siblings: p.siblings, dirs: p.dirs, rootId: p.rootId };
  return encode(utf8(JSON.stringify(ordered)));
}

export function decodeProof(text: string): MerkleProof {
  return parseProof(JSON.parse(Buffer.from(decode(text)).toString("utf8")));
}
