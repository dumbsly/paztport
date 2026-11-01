// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, sign, utf8, verify } from "../crypto/crypto.ts";
import { writeWire } from "../encoding/jcs.ts";
import { readFile, readToken, type JsonValue } from "../encoding/json.ts";
import { exactly, int, object, str, stringMap } from "../internal/fields.ts";
import { requireValidNode } from "./routes.ts";
import { isNotAfter } from "./validity.ts";

/** A keyring signed offline by its policy key: the policy key and the services' public keys; `notAfter` (ms since the epoch, inclusive) is when the owner stops vouching for them. */
export type SignedKeyring = { policy: string; services: Record<string, string>; sig: string; notAfter: number };

/** The bytes a keyring signature covers: domain prefix + JCS of notAfter, the policy key and services; throws on a notAfter outside [0, 2^53 − 1]. */
export function keyringSigningBytes(policy: string, services: Record<string, string>, notAfter: number): Uint8Array {
  if (!isNotAfter(notAfter)) throw new TypeError("notAfter must be an integer in [0, 2^53 - 1]");
  return concat(utf8("paztport-keyring\n"), writeWire({ notAfter, policy, services }));
}

/** Signs a keyring with its policy key, vouching for it until `notAfter` (throws on one outside [0, 2^53 − 1], an absent one included); the caller must have checked that each key is that service's current key. */
export function signKeyring(services: Record<string, string>, policyPublicKey: string, policyPrivateKey: string, notAfter: number): SignedKeyring {
  const sig = encode(sign(policyPrivateKey, keyringSigningBytes(policyPublicKey, services, notAfter)));
  return { policy: policyPublicKey, services, sig, notAfter };
}

/** True only when the keyring names `policyKey` and its signature verifies under it over the keyring's own `notAfter`, which must be in [0, 2^53 − 1]; one that is missing (or inherited) fails. Never throws, and says nothing about time (see isCurrent). */
export function verifyKeyring(k: SignedKeyring, policyKey: string): boolean {
  try {
    if (!Object.hasOwn(k, "notAfter") || !isNotAfter(k.notAfter)) return false;
    return (
      k.policy === policyKey &&
      typeof k.sig === "string" &&
      verify(policyKey, keyringSigningBytes(k.policy, k.services, k.notAfter), decode(k.sig))
    );
  } catch {
    return false;
  }
}

/** The keyring's schema: exactly `notAfter`, `policy`, `services` and `sig`, each service named by a route node. */
function keyringOf(value: JsonValue): SignedKeyring {
  const o = object(value);
  exactly(o, ["notAfter", "policy", "services", "sig"]);
  const services = stringMap(object(o, "services"));
  for (const name of Object.keys(services)) {
    try {
      requireValidNode(name);
    } catch {
      // the name is data, so the refusal does not repeat it
      throw new Error("member services holds a name that is not a route node");
    }
  }
  return { policy: str(o, "policy"), services, sig: str(o, "sig"), notAfter: int(o, "notAfter") };
}

/**
 * Reads `keyring.json` in any member order and spacing: MalformedJson for bytes that do not read, an Error naming
 * the member for a keyring the schema refuses. Checks no signature.
 */
export function readKeyringFile(bytes: Uint8Array): SignedKeyring {
  return keyringOf(readFile(bytes));
}

/** Reads a keyring from the token of the object `keyring.json` holds, by readKeyringFile's schema. */
export function readKeyring(token: string): SignedKeyring {
  return keyringOf(readToken(token));
}
