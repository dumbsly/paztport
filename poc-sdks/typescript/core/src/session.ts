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

export type ClientKeys = { clientPolicyKey: string; clientKeyring: Record<string, string> };

function fixed(value: string, length: number, what: string): Uint8Array {
  const bytes = decode(value);
  if (bytes.length !== length) {
    throw new Error(`${what} must be ${length} bytes`);
  }
  return bytes;
}

/** Binds both roots, both nonces and the client's policy key and keyring; throws on bad lengths. */
export function deriveSessionId(
  clientRootSig: string | null,
  serverRootSig: string | null,
  clientNonce: string,
  serverNonce: string,
  clientKeys: ClientKeys,
): string {
  const flags = (clientRootSig !== null ? 1 : 0) | (serverRootSig !== null ? 2 : 0);
  const keysHash = sha256(utf8(canonicalize({ clientPolicyKey: clientKeys.clientPolicyKey, clientKeyring: clientKeys.clientKeyring })));
  return encode(
    sha256(
      concat(
        new Uint8Array([0x02, flags]),
        clientRootSig === null ? new Uint8Array(0) : fixed(clientRootSig, 64, "clientRootSig"),
        serverRootSig === null ? new Uint8Array(0) : fixed(serverRootSig, 64, "serverRootSig"),
        fixed(clientNonce, 16, "clientNonce"),
        fixed(serverNonce, 16, "serverNonce"),
        keysHash,
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

/** The bytes a session reply signature covers: domain prefix + JCS of the reply without "sig". */
function replySigningBytes(body: Omit<SessionReply, "sig">): Uint8Array {
  return utf8("paztport-session-reply\n" + canonicalize(body));
}

/** Signs the reply; any "sig" already on the input is dropped first. */
export function signSessionReply(reply: Omit<SessionReply, "sig">, serverPolicyPrivateKey: string): SessionReply {
  const { sig: _stray, ...body } = reply as Omit<SessionReply, "sig"> & { sig?: unknown };
  return { ...body, sig: encode(sign(serverPolicyPrivateKey, replySigningBytes(body))) };
}

export function verifySessionReply(reply: SessionReply, req: SessionRequest, pinnedServerPolicyKey: string): boolean {
  try {
    if (reply.serverPolicyKey !== pinnedServerPolicyKey) {
      return false;
    }
    const { sig, ...body } = reply;
    if (!verify(pinnedServerPolicyKey, replySigningBytes(body), decode(sig))) {
      return false;
    }
    if (reply.status === "attested" && (reply.serverRoot === null || req.clientRoot === null)) {
      return false;
    }
    const expected = deriveSessionId(req.clientRoot?.sig ?? null, reply.serverRoot?.sig ?? null, req.nonce, reply.nonce, req);
    if (reply.sess !== expected) {
      return false;
    }
    return reply.serverRoot === null || verifyRoot(reply.serverRoot, pinnedServerPolicyKey);
  } catch {
    return false;
  }
}
