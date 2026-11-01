// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, randomBytes, sha256, utf8 } from "../crypto/crypto.ts";
import { writeToken } from "../encoding/jcs.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { array, exactly, object, str } from "../internal/fields.ts";

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

/**
 * Throws unless value is an object with exactly the proof's members: `siblings` an array of strings each 32 bytes
 * of base64url, `leafSalt` a string of 16 bytes of base64url, `dirs` one L or R per sibling and `rootId` a string.
 * These are the checks of wire.md's proof object that need no root, made in this order, each naming its member.
 */
export function parseProof(value: unknown): MerkleProof {
  const o = object(value as JsonValue);
  exactly(o, ["leafSalt", "siblings", "dirs", "rootId"]);
  const siblings = array(o, "siblings").map((s) => {
    if (typeof s !== "string" || decodedLength(s) !== HASH_BYTES) {
      throw new Error("member siblings holds a value that is not 32 bytes of base64url");
    }
    return s;
  });
  const leafSalt = str(o, "leafSalt");
  if (decodedLength(leafSalt) !== SALT_BYTES) {
    throw new Error("member leafSalt is not 16 bytes of base64url");
  }
  const dirs = str(o, "dirs");
  if (!DIRS.test(dirs) || dirs.length !== siblings.length) {
    throw new Error("member dirs is not one L or R per sibling");
  }
  return { leafSalt, siblings, dirs, rootId: str(o, "rootId") };
}

/** The length of what canonical base64url `text` decodes to, or -1 when it does not decode. */
function decodedLength(text: string): number {
  try {
    return decode(text).length;
  } catch {
    return -1;
  }
}

/**
 * Reads a proof from its token: MalformedJson for bytes that do not read, an Error naming the member for a proof the
 * schema refuses.
 */
export function readProof(token: string): MerkleProof {
  return parseProof(readToken(token));
}

/** Whether `proof` is for the root named `rootId` and proves `path` against `root`. */
export function provesPath(proof: MerkleProof, path: string, root: Uint8Array, rootId: string): boolean {
  return proof.rootId === rootId && verifyProof(proof, path, root);
}

export function encodeProof(p: MerkleProof): string {
  return writeToken({ leafSalt: p.leafSalt, siblings: p.siblings, dirs: p.dirs, rootId: p.rootId });
}
