// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, sign, utf8, verify } from "../crypto/crypto.ts";
import { writeWire } from "../encoding/jcs.ts";
import { readFile, type JsonValue } from "../encoding/json.ts";
import { exactly, int, object, str } from "../internal/fields.ts";

/** The policy key's statement that `key` is service `svc`'s reply key until `notAfter` (ms since the epoch, inclusive). */
export type ReplyCert = { policy: string; svc: string; key: string; notAfter: number; sig: string };

function validNotAfter(n: unknown): n is number {
  return Number.isSafeInteger(n) && (n as number) >= 0;
}

/** The bytes a certificate signature covers: domain prefix + JCS of key, notAfter, policy and svc; throws on a notAfter outside [0, 2^53 − 1]. */
export function replyCertSigningBytes(policy: string, svc: string, key: string, notAfter: number): Uint8Array {
  if (!validNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return concat(utf8("paztport-reply-cert\n"), writeWire({ key, notAfter, policy, svc }));
}

/** Signs a reply certificate; the caller must have checked `key` is `svc`'s key in its current keyring signed by this policy key. */
export function signReplyCert(policyPublicKey: string, svc: string, key: string, notAfter: number, policyPrivateKey: string): ReplyCert {
  const sig = encode(sign(policyPrivateKey, replyCertSigningBytes(policyPublicKey, svc, key, notAfter)));
  return { policy: policyPublicKey, svc, key, notAfter, sig };
}

/**
 * True when `v` has own string policy, svc, key and sig and a notAfter that is an integer in [0, 2^53 − 1],
 * checked by value (1.0 and 1e3 are 1 and 1000); other fields are ignored.
 */
export function isReplyCert(v: unknown): v is ReplyCert {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  for (const f of ["policy", "svc", "key", "sig"]) {
    if (!Object.hasOwn(o, f) || typeof o[f] !== "string") return false;
  }
  return Object.hasOwn(o, "notAfter") && validNotAfter(o.notAfter);
}

/**
 * Reads `reply-cert.json` in any member order and spacing: MalformedJson for bytes that do not read, an Error naming
 * the member for a certificate other than exactly `key`, `notAfter`, `policy`, `sig` and `svc`. Checks no signature.
 */
export function readReplyCertFile(bytes: Uint8Array): ReplyCert {
  return replyCertOf(readFile(bytes));
}

/**
 * The certificate's schema: exactly `key`, `notAfter`, `policy`, `sig` and `svc`. A session reply's own reader applies
 * it to the certificate it carries.
 */
export function replyCertOf(value: JsonValue): ReplyCert {
  const o = object(value);
  exactly(o, ["key", "notAfter", "policy", "sig", "svc"]);
  const policy = str(o, "policy");
  return { policy, svc: str(o, "svc"), key: str(o, "key"), notAfter: int(o, "notAfter"), sig: str(o, "sig") };
}

/** True only when the certificate is well formed, names `policyKey` and its signature verifies under it; never throws, and ignores time. */
export function verifyReplyCert(cert: ReplyCert, policyKey: string): boolean {
  try {
    return (
      isReplyCert(cert) &&
      typeof policyKey === "string" &&
      cert.policy === policyKey &&
      verify(policyKey, replyCertSigningBytes(cert.policy, cert.svc, cert.key, cert.notAfter), decode(cert.sig))
    );
  } catch {
    return false;
  }
}
