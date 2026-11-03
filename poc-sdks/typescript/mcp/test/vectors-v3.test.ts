// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned v3 vectors for cross-implementation conformance: every case is replayed from the committed JSON
// alone. Cases may be added; a recorded answer changes only with a protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  NonceCache, bindResult, callInSession, canonicalize, checkSessionReply, newRecordSet, recordedSession,
  verifyRecordedLocalStep, commitInfluence, decode, encode, isAttestedSession, sessionStatus, readSessionRequest,
  readSessionReply,
  isCurrent, isNotAfter, printFile, signReplyCert, keyringSigningBytes, normalizeInfluence, publicWriteRefused,
  readKeyringFile, readReplyCertFile, readRootFile, replyCertSigningBytes, rootSigningBytes, sign, signKeyring,
  signRoot, signSessionReply, signingBytes, utf8, verifyChainOffline,
  verifyChain, verifyKeyring, verifyReplyCert, verifyResponse, verifyRoot, verifySessionReply,
} from "@paztport/core";
import type { JsonValue, OfflineConfig, OfflineInput, SessionReply, VerifierConfig, VerifyInput } from "@paztport/core";
import { InvalidParams, bindMcpCall, readSessionParams, sessionReplyToken } from "../src/index.ts";
import { buildVectors, vectorsText } from "./vectors-v3-export.ts";

type Sections =
  | "signingBytes" | "signatures" | "influence" | "rule" | "keyring" | "root" | "verify" | "offline" | "recordedHandshake" | "recordedCall" | "recordedLocalStep"
  | "responseAttestation" | "sessionParams" | "sessionResult" | "replyCert" | "sessionReply" | "sessionStatus" | "sessionRequest";
const committedText = readFileSync(new URL("../../../spec/vectors/v3.json", import.meta.url), "utf8");
const committed: Record<Sections, any[]> & { keys: Record<string, { pub: string; priv: string }>; policies: any } = JSON.parse(committedText);

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

/** The config fields both verifiers share, from a case's names: keys from `keys`, the root and proof from `policies`. */
function shared(v: any, c: any) {
  const policy = v.policies[c.policy];
  const keyring = Object.fromEntries(Object.entries(c.keyring as Record<string, string>).map(([svc, name]) => [svc, v.keys[name].pub as string]));
  const cfg = { keyring, root: decode(policy.root), rootId: policy.rootId as string, allowedOrigins: c.allowedOrigins, sess: c.sess, nonceKey: c.nonceKey };
  const input = {
    chain: c.chainToken,
    expectedBind: c.expectedBind,
    influence: c.influenceToken,
    proof: c.proofRoute === null ? null : policy.proofTokens[c.proofRoute],
    receiver: c.receiver,
    receiverInRoute: c.receiverInRoute,
  };
  return { cfg, input };
}

/** Runs a live case `uses` times against one nonce cache; the last result. */
function replayLive(v: any, c: any) {
  const { cfg, input } = shared(v, c);
  const live: VerifierConfig = { ...cfg, nonces: new NonceCache(c.nonceTtlMs), now: c.now, callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs, policyNotAfter: c.policyNotAfter };
  const full: VerifyInput = c.peer === null ? input : { ...input, peer: c.peer };
  let result = verifyChain(full, live);
  for (let i = 1; i < c.uses; i++) result = verifyChain(full, live);
  return { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst };
}

/** Runs an offline case against the record set's spent nonce keys, `seen`. */
function replayOffline(v: any, c: any) {
  const { cfg, input } = shared(v, c);
  // a null member is absent: no recorded time, or the limit not configured
  const recordedTs = c.recordedTs === null ? undefined : c.recordedTs.run === undefined ? { last: c.recordedTs.last } : { last: c.recordedTs.last, run: new Set<number>(c.recordedTs.run) };
  const offline: OfflineConfig = { ...cfg, seen: new Set<string>(c.seen), callMaxAgeMs: c.callMaxAgeMs ?? undefined, runMaxAgeMs: c.runMaxAgeMs ?? undefined };
  const full: OfflineInput = { ...input, rid: c.rid, recordedTs: recordedTs as never, prompt: c.prompt };
  const result = verifyChainOffline(full, offline);
  return { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst };
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
        chain: call.chainToken, expectedBind: call.expectedBind, influence: call.influenceToken,
        proof: call.proofRoute === null ? null : policy.proofTokens[call.proofRoute], receiver: call.receiver,
        receiverInRoute: call.receiverInRoute, rid: call.rid, recordedTs: call.recordedTs, prompt: call.prompt,
      },
      {
        keyring: request.clientKeyring, root: decode(request.clientRoot!.root), rootId: request.clientRoot!.rootId,
        allowedOrigins: c.allowedOrigins, sess: readSessionReply(h.replyToken).sess, nonceKey: call.nonceKey,
        seen: records.spent, callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs,
      },
    );
    const reason = callInSession(sessions[call.handshake], result.reason, call.recordedTs.last);
    return { reason };
  });
}

/** A recorded local step case (MCP profile), against its client's keyring and root and its signed rules. */
function replayLocalStep(v: any, c: any) {
  const {
    proofRoute, chain: _chain, chainToken, influence: _influence, influenceToken, decisionToken,
    resolved: _resolved, verdict: _verdict, routeAllowed: _routeAllowed, rulesHash: _rulesHash, ...step
  } = c.step;
  const policy = v.policies[c.client.policy];
  const keyring = Object.fromEntries(Object.entries(c.client.keyring as Record<string, string>).map(([svc, name]) => [svc, v.keys[name].pub as string]));
  const client = {
    keyring, root: decode(policy.root), rootId: policy.rootId as string, rules: c.client.rules,
    rootNotAfter: c.client.rootNotAfter, keyringNotAfter: c.client.keyringNotAfter,
  };
  const result = verifyRecordedLocalStep(
    {
      ...step, decision: decisionToken, chain: chainToken, influence: influenceToken,
      proof: proofRoute === null ? null : policy.proofTokens[proofRoute],
    },
    { client, signers: c.signers, run: { prompt: c.run.prompt, ts: new Set<number>(c.run.ts) }, seen: new Set<string>(c.seen) },
  );
  return { reason: result.reason, verdict: result.verdict ?? null };
}

/** A response attestation case (MCP profile): the client's check of the token, once, against the server's names. */
function replayResponseAttestation(v: any, c: any) {
  const s = c.server;
  const policy = v.policies[s.policy];
  const named = Object.entries(s.keyring as Record<string, string>);
  const keyring = Object.fromEntries(named.map(([svc, name]) => [svc, v.keys[name].pub as string]));
  const r = verifyResponse(c.attestationToken, c.result, c.call, {
    keyring, root: decode(policy.root), rootId: policy.rootId as string, allowedOrigins: s.allowedOrigins, sess: s.sess,
    nonces: new NonceCache(s.nonceTtlMs), now: c.now, policyNotAfter: s.policyNotAfter,
  });
  return { reason: r.result.reason };
}

describe("known-answer vectors", () => {
  it("the committed file is what the exporter builds", () => expect(buildVectors()).toEqual(committed));
  it("the committed file is byte for byte what the exporter writes", () => expect(committedText).toBe(vectorsText()));
  it.each(committed.signingBytes.map((c: any): [string, any] => [c.hex, c]))("signing bytes %s", (_h, c: any) => expect(Buffer.from(signingBytes(c.stamp)).toString("hex")).toBe(c.hex));
  it.each(committed.signingBytes.map((c: any): [string, any] => [c.hex, c]))("signing bytes %s are the fields joined by |", (_h, c: any) => {
    const s = c.stamp;
    expect(Buffer.from(utf8([3, s.svc, s.inst, s.rid, s.ts, s.sess, s.rcv, s.bind, s.infl, s.prev].join("|"))).toString("hex")).toBe(c.hex);
  });
  it.each(committed.signatures.map((c: any, i: number): [number, any] => [i, c]))("signature %i", (_i, c: any) => expect(encode(sign(committed.keys[c.key].priv, signingBytes({ v: 3, ...c.fields })))).toBe(c.sig));
  it.each(committed.influence.map((c: any): [string, any] => [c.name, c]))("influence %s", (_n, c: any) => {
    expect(normalizeInfluence(c.entries)).toEqual(c.normalized);
    expect(commitInfluence(c.entries)).toBe(c.commitment);
  });
  it.each(committed.rule.map((c: any): [string, any] => [c.name, c]))("rule %s", (_n, c: any) => expect(publicWriteRefused(c.influence, c.destinationOwner ?? undefined)).toBe(c.refused));
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
  // whose ts JCS cannot write.
  it("every token is the JCS bytes of its value", () => {
    let tokens = 0;
    for (const section of ["verify", "offline"] as const) {
      for (const c of committed[section]) {
        if (c.name !== "stamp ts of -2^63") expect(c.chainToken, c.name).toBe(encode(utf8(canonicalize(c.chain))));
        expect(c.influenceToken, c.name).toBe(encode(utf8(canonicalize(c.influence))));
        tokens += 2;
      }
    }
    for (const c of committed.recordedCall) {
      for (const call of c.calls) {
        expect(call.chainToken, c.name).toBe(encode(utf8(canonicalize(call.chain))));
        expect(call.influenceToken, c.name).toBe(encode(utf8(canonicalize(call.influence))));
        tokens += 2;
      }
    }
    for (const c of committed.recordedLocalStep) {
      expect(c.step.chainToken, c.name).toBe(encode(utf8(canonicalize(c.step.chain))));
      expect(c.step.influenceToken, c.name).toBe(encode(utf8(canonicalize(c.step.influence))));
      const { callId, resolved, verdict, routeAllowed, rulesHash } = c.step;
      const decision = { callId, resolved, verdict, routeAllowed, rulesHash };
      expect(c.step.decisionToken, c.name).toBe(encode(utf8(canonicalize(decision))));
      tokens += 3;
    }
    const handshakes = [
      ...committed.sessionReply,
      ...committed.recordedHandshake,
      ...committed.recordedCall.flatMap((c: any) => c.handshakes.map((h: any) => ({ ...h, name: c.name }))),
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

  const attested = committed.responseAttestation.map((c: any): [string, any] => [c.name, c]);
  it.each(attested)("response attestation %s", (_n, c: any) => {
    expect(replayResponseAttestation(committed, c)).toEqual(c.expected);
  });
  it("every attestation token is the JCS bytes of its value, but for the one in wire member order", () => {
    for (const c of committed.responseAttestation) {
      if (c.name === "an attestation in wire member order") {
        const text = Buffer.from(decode(c.attestationToken)).toString("utf8");
        expect(text.startsWith('{"chain":'), c.name).toBe(true);
        expect(text.indexOf('"proof":'), c.name).toBeLessThan(text.indexOf('"labels":'));
        expect(c.attestationToken, c.name).not.toBe(encode(utf8(canonicalize(c.attestation))));
      } else {
        expect(c.attestationToken, c.name).toBe(encode(utf8(canonicalize(c.attestation))));
      }
    }
  });

  // paztport/session's params as the server reads them, and its result as the client reads it (MCP profile).
  it.each(["sessionParams", "sessionResult"] as const)("%s section", (section) => expect(committed[section].length).toBeGreaterThan(0));
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

  it.each(["recordedHandshake", "recordedCall", "recordedLocalStep"] as const)("%s section", (section) => expect(committed[section].length).toBeGreaterThan(0));
  it.each(committed.recordedHandshake.map((c: any): [string, any] => [c.name, c]))("recorded handshake %s", (_n, c: any) => expect(replayHandshake(committed, c)).toEqual(c.expected));
  it.each(committed.recordedCall.map((c: any): [string, any] => [c.name, c]))("recorded call %s", (_n, c: any) => expect(replayRecordedCalls(committed, c)).toEqual(c.expected));
  it.each(committed.recordedLocalStep.map((c: any): [string, any] => [c.name, c]))("recorded local step %s", (_n, c: any) => expect(replayLocalStep(committed, c)).toEqual(c.expected));
  it("each offline-only code a local step can give has a case", () => {
    const codes = new Set(committed.recordedLocalStep.map((c: any) => c.expected.reason));
    for (const code of ["POLICY_EXPIRED", "PROOF_MISMATCH", "RULES_MISMATCH", "VERDICT_MISMATCH"]) expect(codes.has(code), code).toBe(true);
    expect(committed.recordedCall.some((c: any) => c.expected.some((e: any) => e.reason === "OUTSIDE_SESSION"))).toBe(true);
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
    expect(checkSessionReply(c.replyToken, request, pin, c.serverEntry, c.now)).toBe(c.expected);
    // Offline, judged at the same time, the handshake is attested exactly when the live check says so.
    expect(isAttestedSession(request, c.replyToken, pin, c.serverEntry, c.now)).toBe(c.expected === "ATTESTED");
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

  it("bindMcpCall", () => {
    const c = (committed as any).bindMcpCall;
    expect(bindMcpCall(c.tool, c.callId, c.args)).toBe(c.expected);
  });

  it("bindResult", () => {
    const c = (committed as any).bindResult;
    expect(bindResult(c.result)).toBe(c.expected);
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
