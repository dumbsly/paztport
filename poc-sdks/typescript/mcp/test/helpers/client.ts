// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only simulator of an MCP client harness (session, then pi): never part of the server.

import {
  bindPrompt,
  buildPolicy,
  canonicalize,
  checkSessionReply,
  commitInfluence,
  decode,
  encode,
  generateKeyPair,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  readToken,
  signKeyring,
  signRoot,
  signStampV3,
  utf8,
  writeToken,
  type ContentLabel,
  type InfluenceEntry,
  type MerkleProof,
  type ReasonCode,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import {
  bindMcpCall,
  META_CALL_ID,
  META_CHAIN,
  META_INFLUENCE,
  META_PROOF,
  verifyMcpResponse,
} from "../../src/index.ts";

/**
 * A value's token: the base64url of its JCS text, whether or not the strict writer would write it, so a test can send
 * a value a reader must refuse.
 */
export const tokenOf = (value: unknown): string => encode(utf8(canonicalize(value)));

/** `token` with its value changed: read, edited by `edit` and written back as tokenOf writes it. */
export const retoken = (token: string, edit: (value: any) => unknown): string => tokenOf(edit(readToken(token)));

/** The paztport/session params a client sends for `request`: its token. */
export const sessionParams = (request: unknown): { request: string } => ({ request: tokenOf(request) });

/** The MCP tools/call result shape these tests use. */
export type CallToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  structuredContent?: unknown;
  _meta?: Record<string, unknown>;
};

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
    now?: number,
  ): { reason: ReasonCode; labels: ContentLabel[] };
};

/** The policy key every test client signs with, so a test server can pin it. */
export const CLIENT_POLICY = generateKeyPair();

/** When every test client's root and keyring stop being valid: 2100-01-01. */
export const CLIENT_NOT_AFTER = 4_102_444_800_000;

/** `forgeRoot` signs the client root with a key other than the advertised clientPolicyKey. */
type ClientMaterial = {
  policyPublicKey: string;
  session: { privateKey: string; publicKey: string };
  pi: { privateKey: string; publicKey: string };
  signedRoot: SignedRoot;
  proofFor(tool: string): MerkleProof | undefined;
};

function generatedMaterial(tools: string[], rootNotAfter: number): ClientMaterial & { policyPrivateKey: string } {
  const policy = CLIENT_POLICY;
  const { signedRoot, bundles } = buildPolicy(
    tools.map((t) => ["session", "pi", `mcp:github.${t}`]),
    8,
    policy.privateKey,
    rootNotAfter,
  );
  return {
    policyPublicKey: policy.publicKey,
    policyPrivateKey: policy.privateKey,
    session: generateKeyPair(),
    pi: generateKeyPair(),
    signedRoot,
    proofFor: (tool) => bundles["pi"]!.proofs[`session/pi/mcp:github.${tool}`]!,
  };
}

/**
 * `forgeRoot` signs the client root with a key other than the advertised clientPolicyKey.
 * `tools` limits the client policy to those tools' routes. `rootNotAfter` and `keyringNotAfter` replace
 * CLIENT_NOT_AFTER as the root's and keyring's windows.
 */
export function makeClient(
  opts: { withRoot?: boolean; forgeRoot?: boolean; tools?: string[]; rootNotAfter?: number; keyringNotAfter?: number } = {},
): TestClient {
  const m = generatedMaterial(opts.tools ?? ALL_TOOLS, opts.rootNotAfter ?? CLIENT_NOT_AFTER);
  const { session, pi, signedRoot } = m;
  const policy = { publicKey: m.policyPublicKey };
  const services = { session: session.publicKey, pi: pi.publicKey };
  const ring = signKeyring(services, m.policyPublicKey, m.policyPrivateKey, opts.keyringNotAfter ?? CLIENT_NOT_AFTER);
  const forged = opts.forgeRoot ? signRoot(decode(signedRoot.root), signedRoot.rootId, generateKeyPair().privateKey, CLIENT_NOT_AFTER) : signedRoot;
  const clientRoot: SignedRoot | null = opts.withRoot === false ? null : forged;
  const responseNonces = new NonceCache(NONCE_TTL_MS);
  let req: SessionRequest | undefined;
  let sess: string | undefined;
  let seq = 0;

  const request = (): SessionRequest => {
    req = {
      clientRoot,
      clientPolicyKey: policy.publicKey,
      clientKeyring: ring.services,
      clientKeyringSig: ring.sig,
      clientKeyringNotAfter: ring.notAfter,
      nonce: newNonce(),
    };
    return req;
  };

  return {
    request,
    acceptReply(reply, pinnedServerKey) {
      // the reply as a client receives it: its token, read and checked
      if (req === undefined) {
        return false;
      }
      const check = checkSessionReply(writeToken(reply), req, pinnedServerKey, "mcp-entry", Date.now());
      if (check !== "ATTESTED" && check !== "UNSAFE") {
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
      const rid = o.rid ?? `rid-${++seq}`;
      const callId = o.callId ?? `call-${seq}`;
      const s0 = signStampV3(
        { svc: "session", inst: "session-1", rid, ts: now, sess, rcv: "pi", bind: bindPrompt("test prompt"), infl: "", prev: "" },
        session.privateKey,
      );
      const s1 = signStampV3(
        {
          svc: "pi",
          inst: "pi-1",
          rid,
          ts: now,
          sess,
          rcv: `mcp:github.${name}`,
          bind: bindMcpCall(name, callId, args),
          infl: commitInfluence(influence),
          prev: s0.sig,
        },
        pi.privateKey,
      );
      // a tool outside the client policy has no proof, so the call carries none
      const proof = m.proofFor(name);
      return {
        name,
        arguments: args,
        _meta: {
          [META_CHAIN]: writeToken([s0, s1]),
          ...(proof !== undefined ? { [META_PROOF]: writeToken(proof) } : {}),
          [META_INFLUENCE]: writeToken(influence),
          [META_CALL_ID]: callId,
        },
      };
    },
    verify(result, call, serverKeyring, serverRoot, now = Date.now()) {
      if (sess === undefined) {
        throw new Error("no accepted session");
      }
      const r = verifyMcpResponse(result, { ...call, receiver: "pi" }, {
        keyring: serverKeyring,
        root: decode(serverRoot.root),
        rootId: serverRoot.rootId,
        allowedOrigins: ["mcp-entry"],
        sess,
        nonces: responseNonces,
        now,
        policyNotAfter: serverRoot.notAfter,
      });
      return { reason: r.result.reason, labels: r.labels };
    },
  };
}
