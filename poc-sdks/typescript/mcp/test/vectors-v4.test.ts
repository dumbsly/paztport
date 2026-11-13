// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned version 4 vectors for cross-implementation conformance: every case is replayed from the committed JSON
// alone. Cases may be added; a recorded answer changes only with a protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  INFLUENCE, NonceCache, callInSession, callsAfter, canonicalize, checkSessionReply, decode, decideVerifiedCall,
  encode, entryOf, extensionSettings, isAttestedSession, labelOf, newRecordSet, publicWriteRefused, readBlocks,
  readRequestInfluence, recordedCallReason, recordedSession, requirement, responseEntries, sessionStatus,
  readSessionRequest, readSessionReply, isCurrent, isNotAfter, pinnedNotAfter, printFile, signReplyCert,
  keyringSigningBytes, readKeyringFile, readReplyCertFile, readRootFile, replyCertSigningBytes, rootSigningBytes, sign,
  signKeyring, signRoot, signSessionReply, signingBytes, utf8, verifyChainOffline, verifyChain, verifyKeyring,
  verifyRecordedLocalStep, verifyReplyCert, verifyResponse, verifyRoot, verifySessionReply, bindResult,
} from "@paztport/core";
import type {
  ChainVerification, JsonValue, OfflineConfig, OfflineInput, PinnedKeyring, PinnedRoot, SessionReply, VerifierConfig,
  VerifyInput,
} from "@paztport/core";
import { InvalidParams, bindMcpCall, readSessionParams, sessionReplyToken } from "../src/index.ts";
import { buildVectors, vectorsText } from "./vectors-v4-export.ts";

type Sections =
  | "signingBytes" | "signatures" | "keyring" | "root" | "verify" | "offline" | "recordedHandshake" | "recordedCall"
  | "recordedLocalStep" | "responseAttestation" | "sessionParams" | "sessionResult" | "replyCert" | "sessionReply"
  | "sessionRequirement" | "sessionStatus" | "sessionRequest";
const committedText = readFileSync(new URL("../../../spec/vectors/v4.json", import.meta.url), "utf8");
type Keys = Record<string, { pub: string; priv: string }>;
const committed: Record<Sections, any[]> & { keys: Keys; policies: any; blocks: any; influence: any } =
  JSON.parse(committedText);
/** The version 3 file, which the sections whose rule did not change must equal; it goes when v3.json does. */
const v3 = JSON.parse(readFileSync(new URL("../../../spec/vectors/v3.json", import.meta.url), "utf8"));

/** The verify case whose blocks token does not read, the one blocks token that is not its value's JCS bytes. */
const UNREADABLE_BLOCKS_CASE = "a blocks token that does not read";
/** The response attestation case whose token is not the JCS bytes of its readable value. */
const UNSORTED_ATTESTATION_CASE = "an attestation whose members are not in JCS order";

/** What `read` gives, or undefined for a file its reader refuses. */
function readOr<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/** A case whose file does not read: it never verifies, has no signed bytes and is current at no time. */
function refused(c: any): void {
  expect(c.signingBytes).toBeNull();
  expect(c.verifies).toBe(false);
  for (const { at, current } of c.current ?? []) expect(current, String(at)).toBe(false);
}

/** A keyring's keys from its service-to-key-name map, each key from `keys`. */
const keysOf = (v: any, keyring: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(keyring).map(([svc, name]) => [svc, v.keys[name].pub as string]));

/** A policy's root from `policies`, pinned until `notAfter`. */
const rootOf = (v: any, name: string, notAfter: number): PinnedRoot => ({ root: decode(v.policies[name].root), rootId: v.policies[name].rootId, notAfter });

/**
 * A case's pinned keyrings and roots: its `keyrings` in place of `keyring`, and its `roots` when it has them, a
 * member without a `notAfter` taking `absent`; otherwise its one `keyring` and `policy`'s root, each with the window
 * `single`.
 */
function pinsOf(v: any, c: any, single: number, absent: number): { keyrings: PinnedKeyring[]; roots: PinnedRoot[] } {
  const windowOf = (m: any) => (Object.hasOwn(m, "notAfter") ? m.notAfter : absent);
  return {
    keyrings: Object.hasOwn(c, "keyrings")
      ? c.keyrings.map((k: any) => ({ keys: keysOf(v, k.keyring), notAfter: windowOf(k) }))
      : [{ keys: keysOf(v, c.keyring), notAfter: single }],
    roots: Object.hasOwn(c, "roots") ? c.roots.map((r: any) => rootOf(v, r.policy, windowOf(r))) : [rootOf(v, c.policy, single)],
  };
}

/** A case's extension settings: the names it acts on, and its allowed list, null being unset. */
const settingsOf = (c: any) => extensionSettings(c.actsOn, c.allowedExtensions ?? undefined);

/**
 * The config fields both verifiers share, from a case's names, and its input. The proof is always `policy`'s, which
 * with `roots` names only where the proof comes from; the pinned material is `pinsOf`'s.
 */
function shared(v: any, c: any) {
  const policy = v.policies[c.policy];
  const cfg = { allowedOrigins: c.allowedOrigins, sess: c.sess, nonceKey: c.nonceKey, extensions: settingsOf(c) };
  const input = {
    chain: c.chainToken,
    expectedBind: c.expectedBind,
    blocks: c.blocksToken,
    proof: c.proofRoute === null ? null : policy.proofTokens[c.proofRoute],
    receiver: c.receiver,
    receiverInRoute: c.receiverInRoute,
  };
  return { cfg, input };
}

/** A verifier's result as the file records it: the hand-over a plain object, one member per name it acts on. */
function outcome(result: ChainVerification) {
  const handOver = result.handOver === null ? null : JSON.parse(JSON.stringify(Object.fromEntries(result.handOver)));
  return { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst, handOver };
}

/** Runs a live case `uses` times against one nonce cache, use i from `peers[i]`, or each from `peer`; the last result. */
function replayLive(v: any, c: any) {
  const { cfg, input } = shared(v, c);
  // a live member always has a window: one without is never current
  const live: VerifierConfig = {
    ...cfg, ...pinsOf(v, c, c.policyNotAfter, Number.NaN), nonces: new NonceCache(c.nonceTtlMs), now: c.now,
    callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs, policyNotAfter: c.policyNotAfter,
  };
  // a case's policyNotAfter is the pinning factory's, from the members it pins
  expect(pinnedNotAfter(live.keyrings, live.roots), "policyNotAfter").toBe(c.policyNotAfter);
  const peers = Object.hasOwn(c, "peers") ? c.peers : Array.from({ length: c.uses }, () => c.peer);
  expect(peers.length, "a peer per use").toBe(c.uses);
  let result: ChainVerification | undefined;
  for (const peer of peers) {
    const full: VerifyInput = peer === null ? input : { ...input, peer };
    result = verifyChain(full, live);
  }
  return outcome(result!);
}

/** Runs an offline case against the record set's spent nonce keys, `seen`. */
function replayOffline(v: any, c: any) {
  const { cfg, input } = shared(v, c);
  // a null member is absent: no recorded time, or the limit not configured
  const recordedTs = c.recordedTs === null ? undefined : c.recordedTs.run === undefined ? { last: c.recordedTs.last } : { last: c.recordedTs.last, run: new Set<number>(c.recordedTs.run) };
  // offline, a member without a window counts for every record
  const offline: OfflineConfig = {
    ...cfg, ...pinsOf(v, c, Infinity, Infinity), seen: new Set<string>(c.seen), callMaxAgeMs: c.callMaxAgeMs ?? undefined,
    runMaxAgeMs: c.runMaxAgeMs ?? undefined,
  };
  const full: OfflineInput = { ...input, rid: c.rid, recordedTs: recordedTs as never, prompt: c.prompt };
  return outcome(verifyChainOffline(full, offline));
}

/** A recorded handshake case's session, as the library reads it: at each `at`, at all, and the response limit. */
function replayHandshake(v: any, c: any) {
  const s = recordedSession({
    request: c.requestToken, reply: c.replyToken, pin: v.keys[c.pin].pub, serverEntry: c.serverEntry,
  });
  return { attested: s.attested, attestedAt: c.at.map((t: number) => s.attestedAt(t)), responseNotAfter: s.responseNotAfter ?? null };
}

/**
 * A recorded call case: its calls in order, as one record set, each by the offline verifier in the session of the
 * handshake it names (that request's client keyring and root, that reply's session id) and then limited to it.
 */
function replayRecordedCalls(v: any, c: any) {
  const sessions = c.handshakes.map((h: any) =>
    recordedSession({
      request: h.requestToken, reply: h.replyToken, pin: v.keys[h.pin].pub, serverEntry: h.serverEntry,
    }),
  );
  const records = newRecordSet();
  return c.calls.map((call: any) => {
    const h = c.handshakes[call.handshake];
    const request = readSessionRequest(h.requestToken);
    const policy = v.policies[call.policy];
    const result = verifyChainOffline(
      {
        chain: call.chainToken, expectedBind: call.expectedBind, blocks: call.blocksToken,
        proof: call.proofRoute === null ? null : policy.proofTokens[call.proofRoute], receiver: call.receiver,
        receiverInRoute: call.receiverInRoute, rid: call.rid, recordedTs: call.recordedTs, prompt: call.prompt,
      },
      {
        // the session's windows are judged by callInSession, so the members have none
        keyrings: [{ keys: request.clientKeyring, notAfter: Infinity }],
        roots: [{ root: decode(request.clientRoot!.root), rootId: request.clientRoot!.rootId, notAfter: Infinity }],
        allowedOrigins: c.allowedOrigins, sess: readSessionReply(h.replyToken).sess, nonceKey: call.nonceKey,
        seen: records.spent, callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs, extensions: settingsOf(c),
      },
    );
    // a verifier that acts on influence reads the items before the session's limits (recordedCallReason)
    const session = sessions[call.handshake];
    const at = call.recordedTs.last;
    const reason = c.actsOn.includes(INFLUENCE)
      ? recordedCallReason(result, session, at)
      : callInSession(session, result.reason, at);
    return { reason };
  });
}

/** A recorded local step case (MCP profile), against its client's keyring and root and its signed rules. */
function replayLocalStep(v: any, c: any) {
  const {
    proofRoute, chain: _chain, chainToken, blocks: _blocks, blocksToken, decisionToken,
    resolved: _resolved, verdict: _verdict, routeAllowed: _routeAllowed, rulesHash: _rulesHash, ...step
  } = c.step;
  const policy = v.policies[c.client.policy];
  const client = {
    keyring: keysOf(v, c.client.keyring), root: decode(policy.root), rootId: policy.rootId as string,
    rules: c.client.rules, rootNotAfter: c.client.rootNotAfter, keyringNotAfter: c.client.keyringNotAfter,
  };
  const result = verifyRecordedLocalStep(
    {
      ...step, decision: decisionToken, chain: chainToken, blocks: blocksToken,
      proof: proofRoute === null ? null : policy.proofTokens[proofRoute],
    },
    { client, signers: c.signers, run: { prompt: c.run.prompt, ts: new Set<number>(c.run.ts) }, seen: new Set<string>(c.seen) },
  );
  return { reason: result.reason, verdict: result.verdict ?? null };
}

/** A response attestation case (MCP profile): the client's check of the token, once, with its own extensions. */
function replayResponseAttestation(v: any, c: any) {
  const s = c.server;
  const r = verifyResponse(c.attestationToken, c.result, c.call, {
    keyrings: [{ keys: keysOf(v, s.keyring), notAfter: s.policyNotAfter }],
    roots: [rootOf(v, s.policy, s.policyNotAfter)],
    allowedOrigins: s.allowedOrigins, sess: s.sess, nonces: new NonceCache(s.nonceTtlMs), now: c.now,
    policyNotAfter: s.policyNotAfter, extensions: settingsOf(c),
  });
  return { reason: r.reason };
}

/** Whether `read` reads the item, as an entry or a label: a reader that refuses it throws. */
const reads = (read: (item: JsonValue) => unknown, item: JsonValue): boolean => readOr(() => read(item)) !== undefined;

/** A section of the file by its path, `influence.rule` being the member `rule` of the member `influence`. */
const sectionAt = (file: any, path: string): unknown => path.split(".").reduce((o, k) => o?.[k], file);

describe("known-answer vectors, version 4", () => {
  it("the committed file is what the exporter builds", () => expect(buildVectors()).toEqual(committed));
  it("the committed file is byte for byte what the exporter writes", () => expect(committedText).toBe(vectorsText()));

  // A section whose rule did not change is v3.json's, value for value, so no answer moved by accident while the
  // exporter was rewritten. This test goes when v3.json does.
  it.each([
    ["keys", "keys"], ["policies", "policies"], ["keyring", "keyring"], ["root", "root"], ["replyCert", "replyCert"],
    ["sessionStatus", "sessionStatus"], ["sessionRequest", "sessionRequest"], ["sessionParams", "sessionParams"],
    ["fixedInputs", "fixedInputs"], ["deriveSessionId", "deriveSessionId"], ["bindPrompt", "bindPrompt"],
    ["bindMcpCall", "bindMcpCall"], ["bindResult", "bindResult"], ["merkle", "merkle"], ["influence.rule", "rule"],
  ])("theSectionsWhoseRuleDidNotChangeAreV3s %s", (section, inV3) => {
    expect(sectionAt(committed, section)).toBeDefined();
    expect(sectionAt(committed, section)).toEqual(v3[inV3]);
  });

  const blockReads = (committed.blocks.read as any[]).map((c: any): [string, any] => [c.name, c]);
  it.each(blockReads)("blocks read %s", (_n, c: any) => {
    const read = readOr(() => readBlocks(c.token));
    expect(read === undefined ? "REFUSED" : "OK").toBe(c.expected);
    expect(read === undefined ? null : JSON.parse(JSON.stringify(read))).toEqual(c.blocks);
  });
  it("blocks sections", () => {
    expect(committed.blocks.read.length).toBeGreaterThan(0);
    expect(committed.blocks.commit.length).toBeGreaterThan(0);
  });

  it.each(committed.signingBytes.map((c: any): [string, any] => [c.hex, c]))("signing bytes %s", (_h, c: any) => {
    const bytes = signingBytes(c.stamp);
    expect(Buffer.from(bytes).toString("hex")).toBe(c.hex);
    expect(Buffer.from(bytes).toString("utf8")).toBe(c.text);
  });
  const stamps = committed.signingBytes.map((c: any): [string, any] => [c.hex, c]);
  it.each(stamps)("signing bytes %s are the prefix and the JCS of the stamp", (_h, c: any) => {
    const { sig: _sig, ...unsigned } = c.stamp;
    expect(Buffer.from(utf8("paztport-stamp\n" + canonicalize(unsigned))).toString("hex")).toBe(c.hex);
  });
  it.each(committed.signatures.map((c: any, i: number): [number, any] => [i, c]))("signature %i", (_i, c: any) => expect(encode(sign(committed.keys[c.key].priv, signingBytes({ v: 4, ...c.fields })))).toBe(c.sig));
  // A keyring, root or certificate case is replayed from its `file` alone. One that does not read never verifies,
  // has no signed bytes and is current at no time; one that reads is the case's readable value.
  it.each(committed.keyring.map((c: any): [string, any] => [c.name, c]))("keyring %s", (_n, k: any) => {
    const read = readOr(() => readKeyringFile(utf8(k.file)));
    if (read === undefined) return refused(k);
    const { policy, services, notAfter } = read;
    expect({ ...read, services: { ...services } }).toEqual(k.signed);
    expect(encode(keyringSigningBytes(policy, services, notAfter))).toBe(k.signingBytes);
    expect(encode(utf8("paztport-keyring\n" + canonicalize({ notAfter, policy, services })))).toBe(k.signingBytes);
    expect(verifyKeyring(read, committed.keys[k.policyKey].pub)).toBe(k.verifies);
    for (const { at, current } of k.current ?? []) expect(isCurrent(read, at), String(at)).toBe(current);
    // Every keyring that verifies is reproduced byte for byte by signing it.
    if (k.verifies) expect(signKeyring(services, policy, committed.keys[k.policyKey].priv, notAfter).sig).toBe(k.sig);
  });
  it("root section", () => expect(committed.root.length).toBeGreaterThan(0));
  it.each(committed.root.map((c: any): [string, any] => [c.name, c]))("root %s", (_n, r: any) => {
    const read = readOr(() => readRootFile(utf8(r.file)));
    if (read === undefined) return refused(r);
    const { rootId, root, sig, notAfter } = read;
    expect(read).toEqual(r.signed);
    expect(root).toBe(committed.policies[r.policy].root);
    expect(rootId).toBe(committed.policies[r.policy].rootId);
    expect(encode(rootSigningBytes(rootId, root, notAfter))).toBe(r.signingBytes);
    expect(encode(utf8("paztport-root\n" + canonicalize({ notAfter, root, rootId })))).toBe(r.signingBytes);
    expect(verifyRoot(read, committed.keys[r.policyKey].pub)).toBe(r.verifies);
    for (const { at, current } of r.current ?? []) expect(isCurrent(read, at), String(at)).toBe(current);
    // Every root that verifies is reproduced byte for byte by signing it.
    if (r.verifies) expect(signRoot(decode(root), rootId, committed.keys[r.policyKey].priv, notAfter).sig).toBe(sig);
  });

  // Each file is its readable value in the file format, but where the format cannot write the value's notAfter (1.5,
  // 2^53), or the case writes it with a fraction: there the file holds that number's own text.
  it("every file is its value in the file format, but for a notAfter the format cannot write", () => {
    const files: [string, unknown, string][] = [
      ...committed.keyring.map((c: any): [string, unknown, string] => [c.name, c.signed, c.file]),
      ...committed.root.map((c: any): [string, unknown, string] => [c.name, c.signed, c.file]),
      ...committed.replyCert.map((c: any): [string, unknown, string] => [c.name, c.cert, c.file]),
      ...committed.sessionStatus.flatMap((c: any): [string, unknown, string][] => [
        [c.name, c.serverRoot, c.serverRootFile],
        [c.name, c.serverKeyring, c.serverKeyringFile],
      ]),
    ];
    let spliced = 0;
    for (const [name, value, file] of files) {
      const n = (value as { notAfter?: unknown }).notAfter;
      const fraction = name === "notAfter written 1798761600000.0";
      const own = fraction ? `${String(n)}.0` : n !== undefined && !isNotAfter(n) ? String(n) : undefined;
      if (own === undefined) {
        expect(file, name).toBe(printFile(value as JsonValue));
      } else {
        const zero = printFile({ ...(value as object), notAfter: 0 } as JsonValue);
        expect(file, name).toBe(zero.replace('"notAfter": 0', `"notAfter": ${own}`));
        spliced += 1;
      }
    }
    expect(spliced).toBe(6);
  });
  it.each(committed.verify.map((c: any): [string, any] => [c.name, c]))("verify %s", (_n, c: any) => expect(replayLive(committed, c)).toEqual(c.expected));
  it.each(committed.offline.map((c: any): [string, any] => [c.name, c]))("offline %s", (_n, c: any) => expect(replayOffline(committed, c)).toEqual(c.expected));

  // Every code the live order gives (verification.md, Reason codes, those marked live) is some verify case's answer.
  it("everyReasonTheLiveOrderGivesHasACase", () => {
    const reasons = new Set(committed.verify.map((c: any) => c.expected.reason));
    for (const code of [
      "OK", "CHAIN_MISSING", "BAD_ORIGIN", "BAD_SIGNATURE", "BROKEN_LINK", "EXPIRED", "RID_MISMATCH",
      "BINDING_MISMATCH", "REPLAY", "PATH_NOT_ALLOWED", "SESSION_UNKNOWN", "EXTENSION_MISMATCH",
      "EXTENSION_NOT_ALLOWED", "EXTENSION_REQUIRED", "PEER_MISMATCH", "POLICY_EXPIRED",
    ]) {
      expect(reasons.has(code), code).toBe(true);
    }
  });

  // The hand-over is there exactly on OK, with one member per name the verifier acts on.
  it("a hand-over is recorded exactly on OK, one member per name in actsOn", () => {
    for (const c of [...committed.verify, ...committed.offline]) {
      if (c.expected.reason !== "OK") {
        expect(c.expected.handOver, c.name).toBeNull();
      } else {
        expect(Object.keys(c.expected.handOver).sort(), c.name).toEqual([...c.actsOn].sort());
        for (const entries of Object.values(c.expected.handOver) as any[]) {
          expect(entries.length, c.name).toBe(c.chain.length);
        }
      }
    }
  });

  // −2^63 is not a safe integer, and the file spells it exactly, so a reader that takes a ts as a 64-bit long meets it.
  it("a stamp ts of -2^63 is written exactly", () => {
    const c = committed.verify.find((x: any) => x.name === "stamp ts of -2^63");
    expect(c.expected.reason).toBe("CHAIN_MISSING");
    const at = committedText.indexOf('"name": "stamp ts of -2^63"');
    const readable = committedText.slice(at, committedText.indexOf('"chainToken"', at));
    expect(readable).toContain('"ts": -9223372036854775808,\n');
    expect(Buffer.from(decode(c.chainToken)).toString("utf8")).toContain('"ts":-9223372036854775808,');
  });

  // A replay reads only the tokens; each is the base64url of its readable value's JCS bytes, but for the one case
  // whose ts JCS cannot write and the one whose blocks token does not read. A blocks token is null exactly when no
  // token was received, and its readable value is then null too.
  it("every token is the JCS bytes of its value", () => {
    let tokens = 0;
    const blocksToken = (c: any, name: string) => {
      if (name === UNREADABLE_BLOCKS_CASE) {
        expect(c.blocks, name).toBeNull();
        expect(readOr(() => readBlocks(c.blocksToken)), name).toBeUndefined();
      } else if (c.blocksToken === null) {
        expect(c.blocks, name).toBeNull();
      } else {
        expect(c.blocksToken, name).toBe(encode(utf8(canonicalize(c.blocks))));
      }
    };
    for (const section of ["verify", "offline"] as const) {
      for (const c of committed[section]) {
        if (c.name !== "stamp ts of -2^63") expect(c.chainToken, c.name).toBe(encode(utf8(canonicalize(c.chain))));
        blocksToken(c, c.name);
        tokens += 2;
      }
    }
    const recordedCalls = [...committed.recordedCall, ...committed.influence.recordedCall];
    for (const c of recordedCalls) {
      for (const call of c.calls) {
        expect(call.chainToken, c.name).toBe(encode(utf8(canonicalize(call.chain))));
        blocksToken(call, c.name);
        tokens += 2;
      }
    }
    for (const c of committed.recordedLocalStep) {
      const { chain, chainToken, blocks, blocksToken, decisionToken, callId, resolved, verdict, routeAllowed } = c.step;
      const decision = { callId, resolved, verdict, routeAllowed, rulesHash: c.step.rulesHash };
      expect(chainToken, c.name).toBe(encode(utf8(canonicalize(chain))));
      expect(blocksToken, c.name).toBe(encode(utf8(canonicalize(blocks))));
      expect(decisionToken, c.name).toBe(encode(utf8(canonicalize(decision))));
      tokens += 3;
    }
    const handshakes = [
      ...committed.sessionReply,
      ...committed.recordedHandshake,
      ...recordedCalls.flatMap((c: any) => c.handshakes.map((h: any) => ({ ...h, name: c.name }))),
    ];
    for (const c of handshakes) {
      expect(c.requestToken, c.name).toBe(encode(utf8(canonicalize(c.request))));
      expect(c.replyToken, c.name).toBe(encode(utf8(canonicalize(c.reply))));
      tokens += 2;
    }
    for (const c of [...committed.sessionStatus, ...committed.sessionRequest]) {
      expect(c.requestToken, c.name).toBe(encode(utf8(canonicalize(c.request))));
      tokens += 1;
    }
    for (const [name, policy] of Object.entries(committed.policies as Record<string, any>)) {
      expect(Object.keys(policy.proofTokens), name).toEqual(Object.keys(policy.proofs));
      for (const route of Object.keys(policy.proofs)) {
        expect(policy.proofTokens[route], route).toBe(encode(utf8(canonicalize(policy.proofs[route]))));
      }
    }
    expect(tokens).toBeGreaterThan(0);
  });

  // A nonce key is the JCS text of an array of strings, as RFC 8785 writes strings (verification.md, Freshness and
  // replay), so a part holding a noncharacter is written as itself.
  it("every nonce key is the JCS text of an array of strings", () => {
    const keys: string[] = [
      ...committed.verify.map((c: any) => c.nonceKey),
      ...committed.offline.flatMap((c: any) => [c.nonceKey, ...c.seen]),
      ...[...committed.recordedCall, ...committed.influence.recordedCall]
        .flatMap((c: any) => c.calls.map((call: any) => call.nonceKey)),
      ...committed.recordedLocalStep.flatMap((c: any) => c.seen),
    ];
    for (const key of keys) {
      const parts = JSON.parse(key);
      expect(Array.isArray(parts) && parts.every((p: unknown) => typeof p === "string"), key).toBe(true);
      expect(canonicalize(parts), key).toBe(key);
    }
  });

  it.each(["recordedHandshake", "recordedCall"] as const)("%s section", (section) => expect(committed[section].length).toBeGreaterThan(0));
  it.each(committed.recordedHandshake.map((c: any): [string, any] => [c.name, c]))("recorded handshake %s", (_n, c: any) => expect(replayHandshake(committed, c)).toEqual(c.expected));
  it.each(committed.recordedCall.map((c: any): [string, any] => [c.name, c]))("recorded call %s", (_n, c: any) => expect(replayRecordedCalls(committed, c)).toEqual(c.expected));
  it("a recorded call can be outside its session", () => {
    expect(committed.recordedCall.some((c: any) => c.expected.some((e: any) => e.reason === "OUTSIDE_SESSION"))).toBe(true);
  });

  // The MCP profile's sections.
  it.each(["recordedLocalStep", "responseAttestation", "sessionParams", "sessionResult"] as const)("%s section", (section) => {
    expect(committed[section].length).toBeGreaterThan(0);
  });
  const localSteps = committed.recordedLocalStep.map((c: any): [string, any] => [c.name, c]);
  it.each(localSteps)("recorded local step %s", (_n, c: any) => {
    expect(replayLocalStep(committed, c)).toEqual(c.expected);
  });
  it("each offline-only code a local step can give has a case", () => {
    const codes = new Set(committed.recordedLocalStep.map((c: any) => c.expected.reason));
    for (const code of ["INFLUENCE_MISMATCH", "POLICY_EXPIRED", "PROOF_MISMATCH", "RULES_MISMATCH", "VERDICT_MISMATCH"]) {
      expect(codes.has(code), code).toBe(true);
    }
  });
  const attestations = committed.responseAttestation.map((c: any): [string, any] => [c.name, c]);
  it.each(attestations)("response attestation %s", (_n, c: any) => {
    expect(replayResponseAttestation(committed, c)).toEqual(c.expected);
  });
  it("every attestation token is the JCS bytes of its value, but for one whose members are out of JCS order", () => {
    for (const c of committed.responseAttestation) {
      if (c.name === UNSORTED_ATTESTATION_CASE) {
        const text = Buffer.from(decode(c.attestationToken)).toString("utf8");
        expect(text.startsWith('{"chain":'), c.name).toBe(true);
        expect(JSON.parse(text), c.name).toEqual(c.attestation);
        expect(c.attestationToken, c.name).not.toBe(encode(utf8(canonicalize(c.attestation))));
      } else {
        expect(c.attestationToken, c.name).toBe(encode(utf8(canonicalize(c.attestation))));
      }
    }
  });
  it.each(committed.sessionParams.map((c: any): [string, any] => [c.name, c]))("session params %s", (_n, c: any) => {
    let got = "OK";
    try {
      readSessionParams(c.params);
    } catch (e) {
      expect(e).toBeInstanceOf(InvalidParams);
      got = "INVALID_PARAMS";
    }
    expect(got).toBe(c.expected);
  });
  it.each(committed.sessionResult.map((c: any): [string, any] => [c.name, c]))("session result %s", (_n, c: any) => {
    const token = sessionReplyToken(c.result);
    const got = token !== undefined && readOr(() => readSessionReply(token)) !== undefined ? "OK" : "MALFORMED_REPLY";
    expect(got).toBe(c.expected);
  });
  it("a session result that reads carries the first session reply case's reply", () => {
    const first = committed.sessionReply[0];
    for (const c of committed.sessionResult.filter((x: any) => x.expected === "OK")) {
      expect(c.result.reply, c.name).toBe(first.replyToken);
    }
  });
  it("bindMcpCall", () => {
    const c = (committed as any).bindMcpCall;
    expect(bindMcpCall(c.tool, c.callId, c.args)).toBe(c.expected);
  });
  it("bindResult", () => {
    const c = (committed as any).bindResult;
    expect(bindResult(c.result)).toBe(c.expected);
  });

  // Everything that needs the influence extension's rules, under one member.
  it.each(["entries", "labels", "rule", "request", "response", "recordedCall"])("influence.%s section", (section) => {
    expect(committed.influence[section].length).toBeGreaterThan(0);
  });
  const influenceCases = (section: string): [string, any][] =>
    committed.influence[section].map((c: any): [string, any] => [c.name, c]);
  it.each(influenceCases("entries"))("influence entry %s", (_n, c: any) => {
    expect(reads(entryOf, c.item)).toBe(c.reads);
  });
  it.each(influenceCases("labels"))("influence label %s", (_n, c: any) => {
    expect(reads(labelOf, c.item)).toBe(c.reads);
  });
  it.each(influenceCases("rule"))("influence rule %s", (_n, c: any) => {
    expect(publicWriteRefused(c.influence, c.destinationOwner ?? undefined)).toBe(c.refused);
  });
  // The server's decision on a verified call's influence; an item that does not read leaves no reading of whether
  // every stamp names influence.
  it.each(influenceCases("request"))("influence request %s", (_n, c: any) => {
    const owner = c.destinationOwner === null ? {} : { destinationOwner: c.destinationOwner };
    const opts = { isWrite: c.write, publicDestination: c.write, served: c.served, ...owner };
    const decided = decideVerifiedCall(c.stamps, opts);
    const read = readRequestInfluence(c.stamps);
    expect({ reason: decided.verdict, everyStampNames: read.reads ? read.everyStampNames : null }).toEqual(c.expected);
  });
  it.each(influenceCases("response"))("influence response %s", (_n, c: any) => {
    expect(responseEntries(c.reason, c.stamps, c.src, c.resultHash)).toEqual(c.expected.entries);
  });
  it.each(influenceCases("recordedCall"))("influence recorded call %s", (_n, c: any) => {
    expect(c.actsOn).toEqual([INFLUENCE]);
    expect(replayRecordedCalls(committed, c)).toEqual(c.expected);
  });

  // The cases the review of the spec asked version 4 to carry, each a statement that separates two readings.
  it.each([
    ["verify", "a block that only requires example, at a receiver that acts on it"],
    ["influence.request", "a pass-along block (as the hand-over gives it: items null), a write"],
    ["verify", "ext the hash of the empty block"],
    ["verify", "no blocks token where a stamp commits to a block"],
    ["verify", "a block lists constructor"],
    ["verify", "the receiver acts on constructor, no block lists it"],
    ["verify", "an inner operation holding a `|`"],
    ["verify", "a `|` in rid and inst"],
    ["verify", "a `|` in a service name that has no key"],
    ["sessionReply", "unsafe, listing what the client requires"],
    ["sessionRequirement", "an unsafe reply"],
    ["sessionRequirement", "an unsafe reply, with the switch"],
    ["responseAttestation", "the last block requires example, which the client does not act on"],
    ["influence.response", "a response refused at check 9c"],
    ["influence.response", "verified, one label and one item that is not a label"],
    ["influence.recordedCall", "items under influence, at a verifier that acts on it"],
    // and the whole-branch review
    ["influence.request", "an origin block that does not name it, the caller's entries trusted, a write"],
    ["recordedLocalStep", "a write into a public folder, a private entry in the origin's block and the hop's block empty, signed as allowed"],
    ["sessionRequirement", "a Method not found answer (-32601)"],
    ["sessionRequirement", "a Method not found answer (-32601), with the switch"],
    ["responseAttestation", "a first stamp whose rid is not the call's"],
  ])("everyCaseTheReviewAskedForIsThere %s: %s", (section, name) => {
    const cases = sectionAt(committed, section) as any[];
    expect(cases.some((c) => c.name === name)).toBe(true);
  });
  it("everyCaseTheReviewAskedForIsThere: the recorded calls with an item that does not read", () => {
    const name = "items under influence, at a verifier that acts on it";
    const set = committed.influence.recordedCall.find((c: any) => c.name === name);
    const expected = set.expected.map((e: any) => e.reason);
    // in its session, and past its limits: the extension's code either way, never OUTSIDE_SESSION
    expect(expected).toEqual(["OK", "INFLUENCE_MISMATCH", "INFLUENCE_MISMATCH", "OUTSIDE_SESSION"]);
  });

  it.each(committed.replyCert.map((c: any): [string, any] => [c.name, c]))("reply certificate %s", (_n, c: any) => {
    const read = readOr(() => readReplyCertFile(utf8(c.file)));
    if (read === undefined) return refused(c);
    const { policy, svc, key, notAfter, sig } = read;
    expect(read).toEqual(c.cert);
    expect(encode(replyCertSigningBytes(policy, svc, key, notAfter))).toBe(c.signingBytes);
    expect(encode(utf8("paztport-reply-cert\n" + canonicalize({ key, notAfter, policy, svc })))).toBe(c.signingBytes);
    expect(verifyReplyCert(read, committed.keys[c.pin].pub)).toBe(c.verifies);
    // Every certificate that verifies is reproduced byte for byte by issuing it.
    if (c.verifies) expect(signReplyCert(policy, svc, key, notAfter, committed.keys[c.signer].priv).sig).toBe(sig);
  });

  it("session reply section", () => expect(committed.sessionReply.length).toBeGreaterThan(0));

  it.each(committed.sessionReply.map((c: any): [string, any] => [c.name, c]))("session reply %s", (_n, c: any) => {
    const pin = committed.keys[c.pin].pub;
    const request = readSessionRequest(c.requestToken);
    expect(checkSessionReply(c.replyToken, request, pin, c.serverEntry, c.now, c.requires ?? [])).toBe(c.expected);
    // Offline, judged at the same time, the handshake is attested exactly when the live check passes steps 1 to 4:
    // step 5 reads the client's live configuration, which a record does not hold.
    const attested = c.expected === "ATTESTED" || c.expected === "EXTENSION_REQUIRED";
    expect(isAttestedSession(request, c.replyToken, pin, c.serverEntry, c.now)).toBe(attested);
  });

  it("session requirement section", () => expect(committed.sessionRequirement.length).toBeGreaterThan(0));
  const requirements = committed.sessionRequirement.map((c: any): [string, any] => [c.name, c]);
  it.each(requirements)("session requirement %s", (_n, c: any) => {
    expect(callsAfter(c.check, c.listed, requirement(c.requires, c.continueWithout))).toEqual(c.expected);
  });

  it("session status section", () => expect(committed.sessionStatus.length).toBeGreaterThan(0));
  it("session request section", () => expect(committed.sessionRequest.length).toBeGreaterThan(0));

  it.each(committed.sessionRequest.map((c: any): [string, any] => [c.name, c]))("session request %s", (_n, c: any) => {
    let got = "OK";
    try {
      readSessionRequest(c.requestToken);
    } catch {
      got = "MALFORMED";
    }
    expect(got).toBe(c.expected);
  });

  it.each(committed.sessionStatus.map((c: any): [string, any] => [c.name, c]))("session status %s", (_n, c: any) => {
    const ring = readKeyringFile(utf8(c.serverKeyringFile));
    const root = readRootFile(utf8(c.serverRootFile));
    const pinned = c.pinned.map((n: string) => committed.keys[n].pub);
    const request = readSessionRequest(c.requestToken);
    const status = sessionStatus(request, root, ring.notAfter, committed.keys[c.serverPolicyKey].pub, pinned, c.now);
    expect(status).toBe(c.expected);
    // the server's own keyring is the one it signed
    expect(verifyKeyring(ring, committed.keys[c.serverPolicyKey].pub)).toBe(true);
  });

  // A configured entry named like an Object.prototype member must not find a key in a keyring that lacks it. Here
  // the keyring inherits the entry, holding the certificate's key, so only the own-member check stops the reply. It
  // is a proxy rather than Object.create's, since JCS refuses an object whose prototype is not Object.prototype: to
  // JCS and Object.keys it is the signed keyring, while a lookup finds the entry as an inherited member would. The
  // reply's token holds none of that: the keyring a reader reads from it has no such member at all.
  it.each(["constructor", "__proto__", "toString"])("protoEntryHasNoKey %s", (entry) => {
    const good = committed.sessionReply.find((c: any) => c.name === "entry-key form attested");
    const keys = committed.keys;
    const cert = signReplyCert(keys["server-policy"].pub, entry, keys["mcp-entry"].pub, good.reply.serverReplyCert.notAfter, keys["server-policy"].priv);
    expect(verifyReplyCert(cert, keys["server-policy"].pub)).toBe(true);
    const services: Record<string, string> = { ...good.reply.serverKeyring };
    const inherits = new Proxy(services, {
      get: (t, p, r) => (p === entry && !Object.hasOwn(t, p) ? cert.key : Reflect.get(t, p, r)),
    });
    expect(Object.hasOwn(inherits, entry)).toBe(false);
    expect(inherits[entry]).toBe(cert.key);
    expect(Object.getPrototypeOf(inherits)).toBe(Object.prototype);
    const ring = { policy: keys["server-policy"].pub, services: inherits, sig: good.reply.serverKeyringSig, notAfter: good.reply.serverKeyringNotAfter };
    expect(verifyKeyring(ring, keys["server-policy"].pub)).toBe(true);
    const { sig: _sig, ...body } = good.reply;
    const reply = signSessionReply({ ...body, serverKeyring: inherits, serverReplyCert: cert } as Omit<SessionReply, "sig">, keys["mcp-entry"].priv);
    const request = readSessionRequest(good.requestToken);
    expect(verifySessionReply(reply, request, keys["server-policy"].pub, entry, good.now)).toBe(false);
    const token = encode(utf8(canonicalize(reply)));
    expect(checkSessionReply(token, request, keys["server-policy"].pub, entry, good.now)).toBe("BAD_SIGNATURE");
    expect(isAttestedSession(request, token, keys["server-policy"].pub, entry, good.now)).toBe(false);
  });

  it("each keyring case's named services and policy key are its readable keyring's", () => {
    for (const k of committed.keyring) {
      expect(k.signed.sig).toBe(k.sig);
      const named = Object.fromEntries(Object.entries(k.services as Record<string, string>).map(([svc, name]) => [svc, committed.keys[name].pub]));
      expect(k.signed.services).toEqual(named);
      expect(k.signed.policy).toBe(committed.keys[k.policyKey].pub);
    }
  });
});
