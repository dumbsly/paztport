// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { SignedRoot } from "../policy/root.ts";
import type { ReplyCert } from "./reply-cert.ts";
import { deriveSessionId, newNonce, sessionStatus, signSessionReply, type SessionReply, type SessionRequest } from "./session.ts";

/** What a server answers a handshake with: its own policy material and the entry service's private key, which signs the reply. */
export type ReplySource = {
  signedRoot: SignedRoot;
  policyPublicKey: string;
  keyring: Record<string, string>;
  /** The policy key's signature over `keyring` and `keyringNotAfter`. */
  keyringSig: string;
  keyringNotAfter: number;
  /** The policy key's certificate for the entry's key. */
  replyCert: ReplyCert;
  /** The entry service's private key. */
  entryPrivateKey: string;
};

/** Which sessions a server opens attested, and what an unsafe one refuses. */
export type ReplyRules = {
  /** The client policy keys this server opens attested sessions for; empty means every session is unsafe. */
  pinnedClientKeys: readonly string[];
  /** Tools refused in an unsafe session, named in the reply. */
  disabledWhenUnsafe: readonly string[];
};

/**
 * The reply to a handshake, in the entry-key form and signed by the entry's key. "attested" is said only after
 * sessionStatus's checks at `now`: an old-form or expired client root or keyring makes the session unsafe, and so does
 * this server's own root or keyring once it has expired, so a server left running past its material degrades to
 * unattested sessions rather than stopping. The session id binds both nonces; the server's is fresh.
 */
export function buildSessionReply(source: ReplySource, request: SessionRequest, rules: ReplyRules, now: number): SessionReply {
  const status = sessionStatus(request, source.signedRoot, source.keyringNotAfter, source.policyPublicKey, rules.pinnedClientKeys, now);
  const serverNonce = newNonce();
  const sess = deriveSessionId(request.clientRoot?.sig ?? null, source.signedRoot.sig, request.nonce, serverNonce, {
    clientPolicyKey: request.clientPolicyKey,
    clientKeyring: request.clientKeyring,
  });
  return signSessionReply(
    {
      serverRoot: source.signedRoot,
      serverPolicyKey: source.policyPublicKey,
      serverKeyring: source.keyring,
      serverKeyringSig: source.keyringSig,
      serverKeyringNotAfter: source.keyringNotAfter,
      serverReplyCert: source.replyCert,
      nonce: serverNonce,
      sess,
      status,
      disabled: status === "unsafe" ? [...rules.disabledWhenUnsafe] : [],
    },
    source.entryPrivateKey,
  );
}
