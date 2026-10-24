// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only simulator of the plan 1c client harness: never part of the server.

import {
  bindMcpCall,
  bindPrompt,
  buildPolicy,
  commitInfluence,
  decode,
  generateKeyPair,
  META_CALL_ID,
  META_CHAIN,
  META_INFLUENCE,
  META_PROOF,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  signRoot,
  signStampV2,
  verifyResponse,
  verifySessionReply,
  type ContentLabel,
  type InfluenceEntry,
  type ReasonCode,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/path-attest";
import type { CallToolResult } from "../../src/mcp.ts";

export const ALL_TOOLS = [
  "list_issues",
  "issue_read",
  "get_file_contents",
  "search_repositories",
  "create_branch",
  "create_or_update_file",
  "push_files",
  "create_pull_request",
  "add_issue_comment",
];

export type TestClient = {
  request(): SessionRequest;
  acceptReply(reply: SessionReply, pinnedServerKey: string): boolean;
  callParams(
    name: string,
    args: object,
    influence: InfluenceEntry[],
    opts?: { now?: number; callId?: string; rid?: string },
  ): Record<string, unknown>;
  verify(
    result: CallToolResult,
    call: { rid: string; toolCallId: string },
    serverKeyring: Record<string, string>,
    serverRoot: SignedRoot,
  ): { reason: ReasonCode; labels: ContentLabel[] };
};

export function makeClient(opts: { withRoot?: boolean; tools?: string[] } = {}): TestClient {
  const tools = opts.tools ?? ALL_TOOLS;
  const policy = generateKeyPair();
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy(
    tools.map((t) => ["session", "pi", `mcp:github.${t}`]),
    8,
    policy.privateKey,
  );
  const clientRoot: SignedRoot | null = opts.withRoot === false ? null : signedRoot;
  const nonce = newNonce();
  const responseNonces = new NonceCache(NONCE_TTL_MS);
  let req: SessionRequest | undefined;
  let sess: string | undefined;
  let lastNow = Date.now();
  let seq = 0;

  const request = (): SessionRequest => {
    req = {
      clientRoot,
      clientPolicyKey: policy.publicKey,
      clientKeyring: { session: session.publicKey, pi: pi.publicKey },
      nonce,
    };
    return req;
  };

  return {
    request,
    acceptReply(reply, pinnedServerKey) {
      if (req === undefined || !verifySessionReply(reply, req, pinnedServerKey)) {
        return false;
      }
      sess = reply.sess;
      return true;
    },
    callParams(name, args, influence, o = {}) {
      if (sess === undefined) {
        throw new Error("no accepted session");
      }
      const now = o.now ?? Date.now();
      lastNow = now;
      const rid = o.rid ?? `rid-${++seq}`;
      const callId = o.callId ?? `call-${seq}`;
      const s0 = signStampV2(
        { svc: "session", inst: "session-1", rid, ts: now, sess, bind: bindPrompt("test prompt"), infl: "", prev: "" },
        session.privateKey,
      );
      const s1 = signStampV2(
        { svc: "pi", inst: "pi-1", rid, ts: now, sess, bind: bindMcpCall(name, callId, args), infl: commitInfluence(influence), prev: s0.sig },
        pi.privateKey,
      );
      return {
        name,
        arguments: args,
        _meta: {
          [META_CHAIN]: [s0, s1],
          [META_PROOF]: bundles["pi"]!.proofs[`session/pi/mcp:github.${name}`],
          [META_INFLUENCE]: influence,
          [META_CALL_ID]: callId,
        },
      };
    },
    verify(result, call, serverKeyring, serverRoot) {
      if (sess === undefined) {
        throw new Error("no accepted session");
      }
      const r = verifyResponse(result, call, {
        keyring: serverKeyring,
        root: decode(serverRoot.root),
        rootId: serverRoot.rootId,
        allowedOrigins: ["mcp-entry"],
        sess,
        nonces: responseNonces,
        now: lastNow,
      });
      return { reason: r.result.reason, labels: r.labels };
    },
  };
}
