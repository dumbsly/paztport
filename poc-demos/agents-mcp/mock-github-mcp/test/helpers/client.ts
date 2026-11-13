// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only simulator of the pi extension's client harness: never part of the server.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  bindPrompt,
  bindResult,
  buildPolicy,
  decode,
  extensionSettings,
  generateKeyPair,
  INFLUENCE,
  influenceBlock,
  mintOrigin,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  readKeyringFile,
  readProofBundleFile,
  readRootFile,
  responseEntries,
  signKeyring,
  signRoot,
  verifySessionReply,
  writeToken,
  type ExtensionSettings,
  type InfluenceEntry,
  type MerkleProof,
  type ReasonCode,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import { META_PROOF, stampToolCall, verifyMcpResponse } from "@paztport/mcp";
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
  /**
   * Verifies a response as this client, acting on influence: the result's code, and the entries the response adds, as
   * `responseEntries` builds them, with the server `github` as `src`.
   */
  verify(
    result: CallToolResult,
    call: { rid: string; callId: string },
    serverKeyring: Record<string, string>,
    serverRoot: SignedRoot,
    now?: number,
  ): { reason: ReasonCode; entries: InfluenceEntry[] };
};

/** What stampToolCall writes where the client policy has no proof for a tool; the call is sent without it. */
const NO_PROOF: MerkleProof = { leafSalt: "", siblings: [], dirs: "", rootId: "" };

/** The settings of a test client that acts on influence, as the agents demo's does. */
const CLIENT_EXTENSIONS: ExtensionSettings = extensionSettings([INFLUENCE]);

/** The paztport/session params a client sends for `request`: its token. */
export const sessionParams = (request: SessionRequest): { request: string } => ({ request: writeToken(request) });

/** The policy key every generated test client signs with, so a test server can pin it. */
export const CLIENT_POLICY = generateKeyPair();

/** When a generated test client's root and keyring stop being valid: 2100-01-01. */
export const CLIENT_NOT_AFTER = 4_102_444_800_000;

/** `keyringSig` is the policy key's signature over the session and pi keys and `keyringNotAfter`, the keyring's window. */
type ClientMaterial = {
  policyPublicKey: string;
  session: { privateKey: string; publicKey: string };
  pi: { privateKey: string; publicKey: string };
  keyringSig: string;
  keyringNotAfter: number;
  signedRoot: SignedRoot;
  proofFor(tool: string): MerkleProof | undefined;
};

function generatedMaterial(tools: string[]): ClientMaterial {
  const policy = CLIENT_POLICY;
  const { signedRoot, bundles } = buildPolicy(
    tools.map((t) => ["session", "pi", `mcp:github.${t}`]),
    8,
    policy.privateKey,
    CLIENT_NOT_AFTER,
  );
  const session = generateKeyPair();
  const pi = generateKeyPair();
  return {
    policyPublicKey: policy.publicKey,
    session,
    pi,
    keyringSig: signKeyring({ session: session.publicKey, pi: pi.publicKey }, policy.publicKey, policy.privateKey, CLIENT_NOT_AFTER).sig,
    keyringNotAfter: CLIENT_NOT_AFTER,
    signedRoot,
    proofFor: (tool) => bundles["pi"]!.proofs[`session/pi/mcp:github.${tool}`],
  };
}

/** Loads what `setup-demo.ts` wrote into `<out>/client`: session/pi keys, keyring, root and pi's proofs. */
function loadMaterial(dir: string): ClientMaterial {
  const text = (f: string) => readFileSync(join(dir, f), "utf8").trim();
  const bytes = (f: string) => readFileSync(join(dir, f));
  const ring = readKeyringFile(bytes("keyring.json"));
  const bundle = readProofBundleFile(bytes("proofs-pi.json"));
  return {
    policyPublicKey: ring.policy,
    session: { privateKey: text("session.key"), publicKey: ring.services.session },
    pi: { privateKey: text("pi.key"), publicKey: ring.services.pi },
    keyringSig: ring.sig,
    keyringNotAfter: ring.notAfter,
    signedRoot: readRootFile(bytes("root.json")),
    proofFor: (tool) => bundle.proofs[`session/pi/mcp:github.${tool}`],
  };
}

/**
 * `forgeRoot` signs the client root with a key other than the advertised clientPolicyKey.
 * `fromDir` uses the keys, root and proofs produced by `setup-demo.ts` instead of generating fresh ones.
 */
export function makeClient(opts: { withRoot?: boolean; forgeRoot?: boolean; tools?: string[]; fromDir?: string } = {}): TestClient {
  const m = opts.fromDir !== undefined ? loadMaterial(opts.fromDir) : generatedMaterial(opts.tools ?? ALL_TOOLS);
  const { session, pi, signedRoot } = m;
  const policy = { publicKey: m.policyPublicKey };
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
      clientKeyring: { session: session.publicKey, pi: pi.publicKey },
      clientKeyringSig: m.keyringSig,
      clientKeyringNotAfter: m.keyringNotAfter,
      nonce: newNonce(),
    };
    return req;
  };

  return {
    request,
    acceptReply(reply, pinnedServerKey) {
      if (req === undefined || !verifySessionReply(reply, req, pinnedServerKey, "mcp-entry", Date.now())) {
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
      // the origin's block names influence with nothing; the hop's holds the entries and requires influence of the server
      const originBlock = influenceBlock([]);
      const origin = mintOrigin(
        { svc: "session", inst: "session-1", rid, ts: now, sess, rcv: "pi", bind: bindPrompt("test prompt"), block: originBlock },
        session.privateKey,
      );
      // a tool outside the client policy has no proof, so the call carries none: stampToolCall writes a placeholder, dropped
      const proof = m.proofFor(name);
      const meta = stampToolCall(
        { name, args, callId },
        {
          origin, originBlock, svc: "pi", inst: "pi-1", privateKey: pi.privateKey, ts: now,
          block: influenceBlock(influence, [INFLUENCE]), requires: [], proof: proof ?? NO_PROOF, serverId: "github",
        },
      );
      if (proof === undefined) delete meta[META_PROOF];
      return { name, arguments: args, _meta: meta };
    },
    verify(result, call, serverKeyring, serverRoot, now = Date.now()) {
      if (sess === undefined) {
        throw new Error("no accepted session");
      }
      const r = verifyMcpResponse(result, { ...call, receiver: "pi" }, {
        keyrings: [{ keys: serverKeyring, notAfter: serverRoot.notAfter }],
        roots: [{ root: decode(serverRoot.root), rootId: serverRoot.rootId, notAfter: serverRoot.notAfter }],
        allowedOrigins: ["mcp-entry"],
        sess,
        nonces: responseNonces,
        now,
        policyNotAfter: serverRoot.notAfter,
        extensions: CLIENT_EXTENSIONS,
      });
      const stamps = r.ok ? r.handOver!.get(INFLUENCE) : undefined;
      return { reason: r.reason, entries: responseEntries(r.reason, stamps, "server:github", bindResult(result)) };
    },
  };
}
