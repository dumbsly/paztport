// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { newNonce, type SessionRequest } from "./session.ts";
import { parseSignedRoot, type SignedRoot } from "../policy/root.ts";
import { readNotAfter } from "../policy/validity.ts";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown, what: string): string {
  if (typeof v !== "string") {
    throw new Error(`${what} must be a string`);
  }
  return v;
}

/** Copies a string map into an object whose keys (even "__proto__") are ordinary own properties. */
function stringMap(v: Record<string, unknown>, what: string): Record<string, string> {
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, str(x, `${what} entry ${k}`)]));
}

/**
 * Reads a request; throws naming the bad field. The client root is read whole, its own `notAfter` kept. A
 * `clientKeyringNotAfter` or root `notAfter` that is missing or not an integer in [0, 2^53 − 1] (null included) is
 * malformed, and so is a `clientKeyringSig` that is missing, null, not a string or empty.
 */
export function parseSessionRequest(json: unknown): SessionRequest {
  if (!isObject(json)) {
    throw new Error("session request must be an object");
  }
  let clientRoot: SignedRoot | null = null;
  if (json.clientRoot !== null) {
    if (!isObject(json.clientRoot)) {
      throw new Error("clientRoot must be an object or null");
    }
    clientRoot = parseSignedRoot(json.clientRoot, "clientRoot");
  }
  if (!isObject(json.clientKeyring)) {
    throw new Error("clientKeyring must be an object");
  }
  const clientKeyring = stringMap(json.clientKeyring, "clientKeyring");
  const clientKeyringNotAfter = readNotAfter(json, "clientKeyringNotAfter");
  const clientKeyringSig = json.clientKeyringSig;
  if (typeof clientKeyringSig !== "string" || clientKeyringSig === "") {
    throw new Error("clientKeyringSig must be a non-empty string");
  }
  return {
    clientRoot,
    clientPolicyKey: str(json.clientPolicyKey, "clientPolicyKey"),
    clientKeyring,
    clientKeyringSig,
    clientKeyringNotAfter,
    nonce: str(json.nonce, "nonce"),
  };
}

/**
 * A client's session handshake request: its signed root (null for none), policy key, keyring, the policy key's
 * signature over that keyring, the keyring's window as `clientKeyringNotAfter`, and a fresh nonce.
 * `keyringNotAfter` must be the window `keyringSig` was made over, or the server finds the keyring unsigned.
 */
export function sessionRequest(material: {
  signedRoot: SignedRoot | null;
  policyPublicKey: string;
  keyring: Record<string, string>;
  keyringSig: string;
  keyringNotAfter: number;
}): SessionRequest {
  return {
    clientRoot: material.signedRoot,
    clientPolicyKey: material.policyPublicKey,
    clientKeyring: material.keyring,
    clientKeyringSig: material.keyringSig,
    clientKeyringNotAfter: material.keyringNotAfter,
    nonce: newNonce(),
  };
}

/**
 * The request that replaces a session the client cannot use: no client root, so the server opens an
 * unsafe session where reads work and writes are refused UNSAFE_SESSION. Its reply is not trusted either way.
 */
export function replacementRequest(req: SessionRequest): SessionRequest {
  return { ...req, clientRoot: null, nonce: newNonce() };
}
