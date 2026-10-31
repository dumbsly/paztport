// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isEd25519PublicKey } from "../crypto/crypto.ts";
import { signReplyCert, verifyReplyCert } from "../session/reply-cert.ts";
import type { ReplyCert } from "../session/reply-cert.ts";
import { signKeyring, verifyKeyring } from "./keyring.ts";
import type { SignedKeyring } from "./keyring.ts";
import { signRenewedRoot, verifyRoot } from "./root.ts";
import type { SignedRoot } from "./root.ts";
import { isNotAfter } from "./validity.ts";

/*
 * The checks a policy owner makes before it signs, in one place so that no tool can sign without them. Each routine signs only what it first
 * confirmed was signed by this same policy key. Every one throws an Error, having signed nothing the caller can
 * use, when a check fails; reading and writing files, and naming them in a message, are the caller's. Every message names the thing refused
 * ("keyring ...", "root ..."), for the caller to put a file name before.
 *
 * What these cannot check is the owner's to ensure: that no listed key has been retired since the keyring was signed, that the keyring given is
 * the current one, and that every route in a renewed tree is still allowed.
 */

const NOT_AFTER = "notAfter must be an integer in [0, 2^53 - 1]";

/** The keyring is verified, expired or not, under the policy key it names. */
function requireSelfSigned(ring: SignedKeyring): void {
  if (typeof ring?.policy !== "string" || !verifyKeyring(ring, ring.policy)) throw new Error("keyring is not signed by its policy key");
}

/** What `sign` throws for a private key it cannot use is the same refusal as a key that is not the policy key's own. */
function signedBy<T>(refusal: string, sign: () => T): T {
  try {
    return sign();
  } catch {
    throw new Error(refusal);
  }
}

/**
 * The keyring signed again until `notAfter`. It must verify, expired or not, under the policy key it names, and that key must
 * be `policyPrivateKey`'s: otherwise the re-signed keyring would not verify under the key it names. Re-signing vouches that each listed key is
 * still its service's current key; a retired key needs a new keyring, not a renewed one.
 */
export function renewKeyring(ring: SignedKeyring, notAfter: number, policyPrivateKey: string): SignedKeyring {
  requireSelfSigned(ring);
  if (!isNotAfter(notAfter)) throw new TypeError(NOT_AFTER);
  const refusal = "keyring is not signed by this policy key";
  const renewed = signedBy(refusal, () => signKeyring(ring.services, ring.policy, policyPrivateKey, notAfter));
  if (!verifyKeyring(renewed, ring.policy)) throw new Error(refusal);
  return renewed;
}

/**
 * The root signed again until `notAfter`, with the same `root` and `rootId` so existing proof bundles stay valid. It must verify, expired or
 * not, under `policyPublicKey`, the base64url key of the policy key that will sign the renewal (a keyring's `policy`, once
 * renewKeyring has accepted it), and `policyPrivateKey` must be that key's private half: otherwise the renewed root would not verify under the
 * key it was checked against. Renewing vouches that every route in the tree is still allowed; a narrowed policy is a new tree, never a renewal.
 */
export function renewRoot(root: SignedRoot, policyPublicKey: string, notAfter: number, policyPrivateKey: string): SignedRoot {
  if (!isEd25519PublicKey(policyPublicKey)) throw new Error("root cannot be checked: the policy key is not an Ed25519 public key");
  const refusal = "root is not signed by this policy key";
  if (!verifyRoot(root, policyPublicKey)) throw new Error(refusal);
  if (!isNotAfter(notAfter)) throw new TypeError(NOT_AFTER);
  const renewed = signedBy(refusal, () => signRenewedRoot(root, notAfter, policyPrivateKey));
  if (!verifyRoot(renewed, policyPublicKey)) throw new Error(refusal);
  return renewed;
}

/**
 * A reply certificate for `svc`'s key in `ring`, valid until `notAfter`. The certificate vouches that the key is `svc`'s in the keyring, so the
 * keyring must verify under the policy key it names, that key must be `policyPrivateKey`'s, and the keyring must hold a key for `svc`.
 */
export function issueReplyCert(ring: SignedKeyring, svc: string, notAfter: number, policyPrivateKey: string): ReplyCert {
  requireSelfSigned(ring);
  const key = Object.hasOwn(ring.services, svc) ? ring.services[svc] : undefined;
  if (typeof key !== "string") throw new Error(`keyring has no key for service ${svc}`);
  if (!isNotAfter(notAfter)) throw new TypeError(NOT_AFTER);
  const refusal = "keyring is not signed by this policy key";
  const cert = signedBy(refusal, () => signReplyCert(ring.policy, svc, key, notAfter, policyPrivateKey));
  if (!verifyReplyCert(cert, ring.policy)) throw new Error(refusal);
  return cert;
}
