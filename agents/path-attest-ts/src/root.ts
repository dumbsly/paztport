// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { sign, utf8, verify } from "./crypto.ts";

export type SignedRoot = { rootId: string; root: string; sig: string };

function signingBytes(rootId: string, rootB64: string): Uint8Array {
  return utf8(`${rootId}|${rootB64}`);
}

export function signRoot(root: Uint8Array, rootId: string, policyPrivateKey: string): SignedRoot {
  const rootB64 = encode(root);
  return { rootId, root: rootB64, sig: encode(sign(policyPrivateKey, signingBytes(rootId, rootB64))) };
}

export function verifyRoot(sr: SignedRoot, policyPublicKey: string): boolean {
  try {
    return verify(policyPublicKey, signingBytes(sr.rootId, sr.root), decode(sr.sig));
  } catch {
    return false;
  }
}
