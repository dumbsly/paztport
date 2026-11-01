// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readToken } from "../encoding/json.ts";
import { exactly, int, object, str, stringMap } from "../internal/fields.ts";
import { requireRouteNodeNames } from "../internal/keyring-names.ts";
import { rootOf, type SignedRoot } from "../policy/root.ts";
import { newNonce, type SessionRequest } from "./session.ts";

/**
 * Reads a request from its token: MalformedJson for bytes that are not exactly the canonical bytes of one value, and
 * an Error naming the member for a request other than exactly its six members: `clientRoot` null or a root with
 * exactly its own members, string `clientPolicyKey` and `nonce`, a `clientKeyring` of strings under route-node
 * names, a non-empty string `clientKeyringSig`, and an integer `clientKeyringNotAfter`. Checks no signature.
 */
export function readSessionRequest(token: string): SessionRequest {
  const o = object(readToken(token));
  exactly(o, ["clientKeyring", "clientKeyringNotAfter", "clientKeyringSig", "clientPolicyKey", "clientRoot", "nonce"]);
  const clientKeyringSig = str(o, "clientKeyringSig");
  if (clientKeyringSig === "") throw new Error("member clientKeyringSig is empty");
  const clientKeyring = stringMap(o, "clientKeyring");
  requireRouteNodeNames(clientKeyring, "clientKeyring");
  return {
    clientRoot: o.clientRoot === null ? null : rootOf(o.clientRoot!),
    clientPolicyKey: str(o, "clientPolicyKey"),
    clientKeyring,
    clientKeyringSig,
    clientKeyringNotAfter: int(o, "clientKeyringNotAfter"),
    nonce: str(o, "nonce"),
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
