// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResponse,
  bindResult,
  buildSessionReply,
  checkOwnMaterial,
  decideServerCall,
  decode,
  describeNotAfter,
  describeOwnMaterialProblem,
  earliestNotAfter,
  expiryWarnings,
  keyPairMatches,
  newContentId,
  NonceCache,
  NONCE_TTL_MS,
  provesPath,
  readSessionRequest,
  signStamp,
  verifyReplyCert,
  writeToken,
  type ContentLabel,
  type InfluenceClass,
  type InfluenceEntry,
  type MerkleProof,
  type ReasonCode,
  type ReplyCert,
  type ResponseAttestation,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_ATTESTATION, META_VERDICT } from "./meta.ts";
import { verifyCall } from "./verify-call.ts";

/**
 * What an MCP server attests with: its policy, its signing keys and the route its responses travel. It holds no
 * policy private key: session replies are signed by the entry's key (`hops[0]`), under `keyringSig` and `replyCert`.
 */
export type ServerPolicy = {
  policyPublicKey: string;
  /** Each hop's private key, by service name. */
  signingKeys: Record<string, string>;
  keyring: Record<string, string>;
  /** The policy key's signature over `keyring` and `keyringNotAfter`. */
  keyringSig: string;
  /** The keyring's window, which the keyring's signature covers; replies carry it as `serverKeyringNotAfter`. */
  keyringNotAfter: number;
  /** The policy key's certificate for the entry's key; checkServerPolicy refuses one that is not for `hops[0]`'s keyring key or has expired. */
  replyCert: ReplyCert;
  signedRoot: SignedRoot;
  /** Proof for the route `<entry>/<tools>` of `hops`. */
  routeProof: MerkleProof;
  inst: string;
  /** The services that sign each response, in chain order: the entry that took the call, then the one that ran it. */
  hops: readonly [entry: string, tools: string];
  /** The server id clients name in their receiver, `mcp:<serverId>.<tool>`. */
  serverId: string;
  /** The client policy keys this server opens attested sessions for; empty means every session is unsafe. */
  pinnedClientKeys: readonly string[];
  /** The services whose origin stamp a call chain may start with, the client's origin names; required and non-empty, with no default. */
  clientOrigins: readonly string[];
};

/**
 * The session a server holds for its connection, from the last handshake: one per connection, replaced by the next
 * handshake.
 */
export type Session = {
  /** The session id. */
  sess: string;
  /** Whether calls in it are verified ("attested") or not ("unsafe"), as the handshake reply said. */
  status: "attested" | "unsafe";
  /** The client's handshake request: its root, policy key and keyring, which the session's calls verify against. */
  request: SessionRequest;
  /** The session's own replay cache, which a new handshake replaces. */
  nonces: NonceCache;
  /** Every class this server has attested in a response in this session (sticky). */
  served: Set<InfluenceClass>;
};

/**
 * Tools refused in an unsafe session. A tool left out of this list runs ungated in unsafe sessions,
 * where no influence rule applies; a server's default should list every write tool.
 */
export type SessionRules = { disabledWhenUnsafe: string[] };

/** A call check's verdict; `caller` is the verified call's last signer, "" when the call did not verify. */
export type ServerCallCheck = { reason: ReasonCode; rid: string; callId: string; influence: InfluenceEntry[]; caller: string; session: Session };

/** What the server knows about a tools/call that its tool table, not the protocol, supplies. */
export type ToolCallFacts = {
  /** Whether the tool writes. */
  isWrite: boolean;
  /** Whether the write's destination is public. */
  publicDestination: boolean;
  /** The destination's owner, when the influence rule is owner-aware. */
  destinationOwner?: string;
};

/** The two modes the protocol defines: a refusal is enforced, or only noted on a result that runs anyway. */
export type ToolCallMode = "enforce" | "audit";

/** The result of a call the server refused: it carries the reason and nothing else (no attribution). */
export type RefusedToolResult = {
  content: [{ type: "text"; text: string }];
  isError: true;
  _meta: Record<string, string>;
};

/** What `run` returns: the tool's result, the class of the content it holds (it labels the attested response), and anything the caller wants back. */
export type ToolRun<R, D = undefined> = { result: R; cls: InfluenceClass; detail?: D };

/** What handleToolCall decided and did. `verified` is the call check when the chain verified, else null; a call that ran carries `run`'s `detail`. */
export type ToolCallOutcome<R, D = undefined> =
  | { ran: false; result: RefusedToolResult; verdict: ReasonCode; verified: ServerCallCheck | null }
  | { ran: true; result: R; verdict: ReasonCode; verified: ServerCallCheck | null; detail: D };

/** The result for a refused call: its verdict token, `{reason}`. */
export function refusedToolResult(reason: string): RefusedToolResult {
  return {
    content: [{ type: "text", text: `Paztport refused this call: ${reason}` }],
    isError: true,
    _meta: { [META_VERDICT]: writeToken({ reason }) },
  };
}

/** Thrown for a malformed request; an MCP server answers it with -32602 Invalid params. The message names the bad field. */
export class InvalidParams extends Error {}

/**
 * Reads paztport/session params: exactly a `request`, the request's token, plus an optional `_meta`, which MCP allows
 * on every request and which is ignored. Throws InvalidParams for any other member, a `request` that is missing or not
 * a string, or one that does not read (readSessionRequest). The message names a member the params or the request lack
 * or hold wrongly, never a value the client sent.
 */
export function readSessionParams(params: unknown): SessionRequest {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new InvalidParams("not an object");
  }
  if (!Object.hasOwn(params, "request")) throw new InvalidParams("no member request");
  for (const name of Object.keys(params)) {
    if (name !== "request" && name !== "_meta") throw new InvalidParams("a member the params do not define");
  }
  const request = (params as Record<string, unknown>).request;
  if (typeof request !== "string") throw new InvalidParams("member request is not a string");
  try {
    return readSessionRequest(request);
  } catch (e) {
    throw new InvalidParams((e as Error).message);
  }
}

/**
 * Throws an Error naming the fault unless `policy` can serve at `now`: the keyring is signed by `policyPublicKey`
 * over `keyringNotAfter`, and current; `signingKeys[hops[0]]` is the entry's keyring key; `replyCert` verifies under
 * `policyPublicKey`, is for `hops[0]` and that key, and has not expired; the root is signed by `policyPublicKey` over
 * its `notAfter`, and current; the keyring has its own key for `hops[1]` and `signingKeys[hops[1]]` matches
 * it; `clientOrigins` names at least one origin service, each a non-empty string; and `routeProof` proves
 * `hops[0]/hops[1]` against the root. The keyring and root checks are core's checkOwnMaterial; the rest is this
 * server's. McpServerSession calls it on construction.
 */
export function checkServerPolicy(policy: ServerPolicy, now: number): void {
  const entry = policy.hops[0];
  const tools = policy.hops[1];
  if (!Array.isArray(policy.clientOrigins) || policy.clientOrigins.length === 0 || !policy.clientOrigins.every((o) => typeof o === "string" && o !== "")) {
    throw new Error("server policy refused: clientOrigins must name at least one origin service");
  }
  const own = checkOwnMaterial(policy, now);
  const refuseOwn = (subject: "keyring" | "root"): void => {
    const problem = own.find((p) => p.subject === subject);
    if (problem !== undefined) {
      throw new Error(`server policy refused: ${describeOwnMaterialProblem(problem)}`);
    }
  };
  refuseOwn("keyring");
  if (!Object.hasOwn(policy.keyring, entry)) {
    throw new Error(`server policy refused: the keyring has no key for the entry ${entry}`);
  }
  const entryKey = policy.keyring[entry]!;
  const signingKey = Object.hasOwn(policy.signingKeys, entry) ? policy.signingKeys[entry] : undefined;
  if (typeof signingKey !== "string" || !keyPairMatches(signingKey, entryKey)) {
    throw new Error(`server policy refused: signingKeys[${entry}] is not the entry's keyring key`);
  }
  const cert = policy.replyCert;
  if (!verifyReplyCert(cert, policy.policyPublicKey)) {
    throw new Error("server policy refused: replyCert is not signed by policyPublicKey");
  }
  if (cert.svc !== entry) {
    throw new Error(`server policy refused: replyCert is for ${cert.svc}, not the entry ${entry}`);
  }
  if (cert.key !== entryKey) {
    throw new Error("server policy refused: replyCert names a key other than the entry's keyring key");
  }
  if (now > cert.notAfter) {
    throw new Error(`server policy refused: replyCert expired at ${describeNotAfter(cert.notAfter)}`);
  }
  refuseOwn("root");
  const root = policy.signedRoot;
  if (!Object.hasOwn(policy.keyring, tools)) {
    throw new Error(`server policy refused: the keyring has no key for the tools hop ${tools}`);
  }
  const toolsKey = Object.hasOwn(policy.signingKeys, tools) ? policy.signingKeys[tools] : undefined;
  if (typeof toolsKey !== "string" || !keyPairMatches(toolsKey, policy.keyring[tools]!)) {
    throw new Error(`server policy refused: signingKeys[${tools}] is not the tools hop's keyring key`);
  }
  let rootBytes: Uint8Array;
  try {
    rootBytes = decode(root.root);
  } catch {
    throw new Error("server policy refused: the root is not valid base64url");
  }
  if (!provesPath(policy.routeProof, `${entry}/${tools}`, rootBytes, root.rootId)) {
    throw new Error(`server policy refused: the route proof for ${entry}/${tools} does not prove against the root`);
  }
}

/**
 * Handles a tools/call end to end. In an attested session the call's chain is verified (checkCall); only a verified
 * call is then decided by decideServerCall, over the facts given and the session's served classes. In enforce a
 * verdict other than OK gives an `isError` result carrying the verdict token of `{reason}` and `run` is not called; in
 * audit `run` is called anyway and its result carries the verdict token of `{reason, audit: true}`. `run` gets the
 * verdict and returns the result with the class of its content. Only a verified call's result is attested; an unsafe
 * session's, or one whose chain failed, is returned unattested. A null `server` is a deployment with no Paztport
 * material: no handshake, so every call is in an unsafe session under `rules`. The `off` switch is not a protocol
 * mode; a deployment that has one does not call this.
 */
export async function handleToolCall<R extends Record<string, unknown> & { _meta?: Record<string, unknown> }, D = undefined>(
  server: McpServerSession | null,
  rules: SessionRules,
  params: Record<string, unknown>,
  facts: ToolCallFacts,
  mode: ToolCallMode,
  run: (ctx: { verdict: ReasonCode }) => ToolRun<R, D> | Promise<ToolRun<R, D>>,
): Promise<ToolCallOutcome<R, D>> {
  const name = typeof params.name === "string" ? params.name : "";
  const sess = server?.session();
  const attested = sess?.status === "attested";
  let verdict: ReasonCode = "OK";
  let call: ServerCallCheck | null = null;
  if (server !== null && attested) {
    call = server.checkCall(params);
    verdict = call.reason;
  }
  if (verdict === "OK") {
    verdict = decideServerCall({
      tool: name,
      isWrite: facts.isWrite,
      publicDestination: facts.publicDestination,
      attested,
      served: sess?.served ?? [],
      clientInfluence: call?.influence ?? [],
      disabledWhenUnsafe: rules.disabledWhenUnsafe,
      ...(facts.destinationOwner !== undefined ? { destinationOwner: facts.destinationOwner } : {}),
    });
  }
  const verified = call !== null && call.reason === "OK" ? call : null;
  if (verdict !== "OK" && mode === "enforce") {
    return { result: refusedToolResult(verdict), verdict, ran: false, verified };
  }
  const { result, cls, detail } = await run({ verdict });
  const noted: R =
    verdict !== "OK" ? { ...result, _meta: { ...result._meta, [META_VERDICT]: writeToken({ reason: verdict, audit: true }) } } : result;
  if (server === null || verified === null) {
    return { result: noted, verdict, ran: true, verified, detail: detail as D };
  }
  const args = params.arguments ?? {};
  const attestedResult = server.attest(verified.session, noted, { rid: verified.rid, callId: verified.callId, name, args, caller: verified.caller }, cls);
  return { result: attestedResult, verdict, ran: true, verified, detail: detail as D };
}

/** The server side of one MCP connection: its paztport/session handshake, call checks and response stamps. */
export class McpServerSession {
  private readonly policy: ServerPolicy;
  private readonly rules: SessionRules;
  private readonly now: () => number;
  private current: Session | undefined;

  /**
   * Throws, as checkServerPolicy does at `now()`, for a policy whose replies no client would accept. Then passes each
   * expiryWarnings message to `warn`, by default `console.error` (stderr: a stdio server's stdout carries the protocol).
   */
  constructor(policy: ServerPolicy, rules: SessionRules, now: () => number, warn: (message: string) => void = console.error) {
    checkServerPolicy(policy, now());
    for (const message of expiryWarnings(policy, now())) warn(message);
    this.policy = policy;
    this.rules = rules;
    this.now = now;
  }

  /**
   * Handles a paztport/session handshake, whose params are read by readSessionParams, and answers with the reply's
   * token as `{reply}`. There is one session per connection: a new handshake replaces the current session (its
   * keyring, nonces and served classes), so calls signed for the old session are refused afterwards. Malformed params
   * throw InvalidParams and leave the current session in place. The reply is in the entry-key form, signed by the
   * entry's key. "attested" is said only after sessionStatus's checks, at `now()`: an expired client root or keyring
   * makes the session unsafe, and so does this server's own root or keyring once it has expired, so a server left
   * running past its material degrades to unattested sessions rather than stopping. A request whose client root or
   * keyring has no `notAfter` is malformed. The reply carries the keyring's window as `serverKeyringNotAfter`.
   */
  openSession(params: unknown): { reply: string } {
    const request = readSessionParams(params);
    const reply = buildSessionReply(
      { ...this.policy, entryPrivateKey: this.policy.signingKeys[this.policy.hops[0]]! },
      request,
      { pinnedClientKeys: this.policy.pinnedClientKeys, disabledWhenUnsafe: this.rules.disabledWhenUnsafe },
      this.now(),
    );
    const { sess, status } = reply;
    const token = writeToken(reply);
    this.current = { sess, status, request, nonces: new NonceCache(NONCE_TTL_MS), served: new Set() };
    return { reply: token };
  }

  session(): Session | undefined {
    return this.current;
  }

  /** Verifies a tools/call params object against the current attested session's client policy, until the earlier of the client root's and keyring's windows (POLICY_EXPIRED after it). */
  checkCall(params: Record<string, unknown>): ServerCallCheck {
    const session = this.current;
    if (session === undefined || session.status !== "attested" || session.request.clientRoot === null) {
      throw new Error("checkCall needs an attested session");
    }
    let root: Uint8Array;
    try {
      root = decode(session.request.clientRoot.root);
    } catch {
      return { reason: "CHAIN_MISSING", rid: "", callId: "", influence: [], caller: "", session };
    }
    // the session's one client keyring and root, each held to the session's policy window
    const policyNotAfter = earliestNotAfter(session.request.clientRoot.notAfter, session.request.clientKeyringNotAfter);
    const v = verifyCall(params, { serverId: this.policy.serverId }, {
      keyrings: [{ keys: session.request.clientKeyring, notAfter: policyNotAfter }],
      roots: [{ root, rootId: session.request.clientRoot.rootId, notAfter: policyNotAfter }],
      allowedOrigins: this.policy.clientOrigins,
      sess: session.sess,
      nonces: session.nonces,
      now: this.now(),
      policyNotAfter,
    });
    const reason = v.result.reason === "PATH_NOT_ALLOWED" ? "CLIENT_PATH_NOT_ALLOWED" : v.result.reason;
    const ok = reason === "OK";
    return { reason, rid: v.rid, callId: v.callId, influence: ok ? v.influence : [], caller: ok ? v.result.suspectSvc : "", session };
  }

  /** Handles a tools/call on this session with its rules; see the free function handleToolCall. */
  handleToolCall<R extends Record<string, unknown> & { _meta?: Record<string, unknown> }, D = undefined>(
    params: Record<string, unknown>,
    facts: ToolCallFacts,
    mode: ToolCallMode,
    run: (ctx: { verdict: ReasonCode }) => ToolRun<R, D> | Promise<ToolRun<R, D>>,
  ): Promise<ToolCallOutcome<R, D>> {
    return handleToolCall(this, this.rules, params, facts, mode, run);
  }

  /**
   * Stamps a result for `session`, the session checkCall verified the call against (not necessarily the current
   * one), and carries the attestation's token. The chain runs entry, then tools, then back to `call.caller`,
   * checkCall's caller: the client that made the call.
   */
  attest<R extends Record<string, unknown> & { _meta?: Record<string, unknown> }>(
    session: Session,
    result: R,
    call: { rid: string; callId: string; name: string; args: unknown; caller: string },
    cls: InfluenceClass,
  ): R {
    const [entry, tools] = this.policy.hops;
    const labels: ContentLabel[] = [{ cls, cid: newContentId() }];
    const resultHash = bindResult(result);
    const base = { rid: call.rid, ts: this.now(), inst: this.policy.inst, sess: session.sess, infl: "" };
    const s0 = signStamp(
      { ...base, svc: entry, rcv: tools, bind: bindMcpCall(call.name, call.callId, call.args), prev: "" },
      this.policy.signingKeys[entry]!,
    );
    const s1 = signStamp(
      { ...base, svc: tools, rcv: call.caller, bind: bindResponse(resultHash, call.callId, labels), prev: s0.sig },
      this.policy.signingKeys[tools]!,
    );
    const attestation: ResponseAttestation = { chain: [s0, s1], proof: this.policy.routeProof, labels, resultHash };
    const token = writeToken(attestation);
    session.served.add(cls);
    return { ...result, _meta: { ...result._meta, [META_ATTESTATION]: token } };
  }
}
