// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
import { concat, randomBytes, sha256, sign, utf8, verify } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";
import { verifyRoot, type SignedRoot } from "./root.ts";

export type SessionRequest = {
  clientRoot: SignedRoot | null;
  clientPolicyKey: string;
  clientKeyring: Record<string, string>;
  nonce: string;
};

export type SessionReply = {
  serverRoot: SignedRoot | null;
  serverPolicyKey: string;
  serverKeyring: Record<string, string>;
  nonce: string;
  sess: string;
  status: "attested" | "unsafe";
  disabled: string[];
  sig: string;
};

export function newNonce(): string {
  return encode(randomBytes(16));
}

export function deriveSessionId(
  clientRootSig: string | null,
  serverRootSig: string | null,
  clientNonce: string,
  serverNonce: string,
): string {
  return encode(
    sha256(
      concat(
        new Uint8Array([0x02]),
        decode(clientRootSig ?? ""),
        decode(serverRootSig ?? ""),
        decode(clientNonce),
        decode(serverNonce),
      ),
    ),
  );
}

/** "attested" only when both roots are present and each verifies against its side's policy key. */
export function sessionStatus(
  req: SessionRequest,
  serverRoot: SignedRoot | null,
  serverPolicyKey: string,
): "attested" | "unsafe" {
  if (req.clientRoot === null || serverRoot === null) {
    return "unsafe";
  }
  return verifyRoot(req.clientRoot, req.clientPolicyKey) && verifyRoot(serverRoot, serverPolicyKey) ? "attested" : "unsafe";
}

export function signSessionReply(reply: Omit<SessionReply, "sig">, serverPolicyPrivateKey: string): SessionReply {
  return { ...reply, sig: encode(sign(serverPolicyPrivateKey, utf8(canonicalize(reply)))) };
}

export function verifySessionReply(reply: SessionReply, req: SessionRequest, pinnedServerPolicyKey: string): boolean {
  try {
    if (reply.serverPolicyKey !== pinnedServerPolicyKey) {
      return false;
    }
    const { sig, ...body } = reply;
    if (!verify(pinnedServerPolicyKey, utf8(canonicalize(body)), decode(sig))) {
      return false;
    }
    if (reply.sess !== deriveSessionId(req.clientRoot?.sig ?? null, reply.serverRoot?.sig ?? null, req.nonce, reply.nonce)) {
      return false;
    }
    return reply.serverRoot === null || verifyRoot(reply.serverRoot, pinnedServerPolicyKey);
  } catch {
    return false;
  }
}
