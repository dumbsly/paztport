// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  bindPrompt,
  decode,
  encode,
  NonceCache,
  sha256,
  utf8,
  verifyCall,
  verifyResponse,
  verifyRoot,
  verifySessionReply,
  type ReasonCode,
  type SessionReply,
  type SessionRequest,
} from "@paztport/path-attest";

/**
 * Offline re-check of a run's evidence file (the `evidenceLog` of the pi extension). It needs no keys
 * of ours: the pinned server key is in the file, and everything else is checked against it.
 *
 * Results beyond the library's reason codes:
 * - BAD_SESSION: the session record does not verify against its pin, or was not attested.
 * - NO_SESSION: a call or response whose server has no verified session before it.
 * - PROMPT_MISMATCH: the call chain's first stamp does not bind the run's recorded prompt.
 * - UNREADABLE: a line, record or file that cannot be read.
 * - NO_CALL: a response with no verified call before it (same server, rid and call id).
 * - DUPLICATE_RESPONSE: a second response record for a call that already has one.
 * - REFUSED: the server refused a call that itself verified. A refusal carries no signature or
 *   attestation by design, so verify cannot check it: it checks only that the response has the
 *   server's refusal shape (isError, and a `_meta` holding only the verdict) and answers a verified
 *   call. It is reported, not counted as a failure. A refusal-looking response that carries an
 *   attestation, or any other `_meta`, is verified as an ordinary response.
 * - NO_RESPONSE: a call with no response record (for example a run that was stopped). Reported, not
 *   counted as a failure.
 * - UNBOUND: a run record that no verified call refers to, so its prompt is not tied to anything in
 *   this file. Reported, not counted as a failure.
 *
 * Replay is checked over the whole file, not over a 15 second window: the library's nonce cache forgets
 * keys older than its TTL relative to the record being checked, which suits a live server but would let
 * a copy of a call pass once any later record is more than 15 seconds on. Offline there is nothing to
 * forget, so the whole file shares one cache, and a call whose (server, rid, call id) was already seen is REPLAY (a deliberate deviation from the live server).
 *
 * Calls are checked with serverId = the record's server id. The mock server checks calls with the
 * serverId "github", which is the record's server id in every shipped configuration. Freshness windows
 * are the library defaults.
 */
export type VerifyItem = {
  line: number;
  type: string;
  callId?: string;
  result: "OK" | ReasonCode | "BAD_SESSION" | "NO_SESSION" | "PROMPT_MISMATCH" | "UNREADABLE" | "REFUSED" | "NO_RESPONSE" | "NO_CALL" | "DUPLICATE_RESPONSE" | "UNBOUND";
};
/**
 * `pins` are fingerprints of the server policy keys the file's verified sessions were pinned to.
 * `nothingToCheck` marks a readable file with no session, call or response record: only the unsigned run
 * record, which Paztport writes before any session. It is not a failure, and not a pass either.
 */
export type VerifyReport = {
  file: string;
  ok: boolean;
  items: VerifyItem[];
  pins: string[];
  nothingToCheck?: true;
  /** Why a file failed when the reason is about the file as a whole (folder mode: a run that needed signed evidence). */
  problem?: string;
};

const META_VERDICT = "paztport/verdict";
/** Results that are reported but do not make a file fail. */
export const NOT_FAILURES: readonly string[] = ["OK", "REFUSED", "NO_RESPONSE", "UNBOUND"];

type Rec = Record<string, unknown>;

const isObject = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string";

/** What a verified session gives the checks that follow it. */
type Session = {
  clientKeyring: Record<string, string>;
  clientRoot: Uint8Array;
  clientRootId: string;
  serverKeyring: Record<string, string>;
  serverRoot: Uint8Array;
  serverRootId: string;
  sess: string;
};

/** First 16 characters of the base64url SHA-256 of the pin text. */
export function pinFingerprint(pin: string): string {
  return encode(sha256(utf8(pin))).slice(0, 16);
}

function verifySession(r: Rec): Session | undefined {
  try {
    const request = r.request as SessionRequest;
    const reply = r.reply as SessionReply;
    if (r.status !== "attested" || !isString(r.pin) || !isObject(request) || !isObject(reply)) {
      return undefined;
    }
    if (reply.status !== "attested" || request.clientRoot === null || reply.serverRoot === null) {
      return undefined;
    }
    if (!verifySessionReply(reply, request, r.pin)) {
      return undefined;
    }
    // The reply binds the client root's signature but not its contents; the root itself must verify
    // against the client policy key, which the session id does bind.
    if (!verifyRoot(request.clientRoot, request.clientPolicyKey)) {
      return undefined;
    }
    return {
      clientKeyring: request.clientKeyring,
      clientRoot: decode(request.clientRoot.root),
      clientRootId: request.clientRoot.rootId,
      serverKeyring: reply.serverKeyring,
      serverRoot: decode(reply.serverRoot.root),
      serverRootId: reply.serverRoot.rootId,
      sess: reply.sess,
    };
  } catch {
    return undefined;
  }
}

/** The first stamp's binding of a call's chain, if it has one. */
function firstBind(params: Rec): string | undefined {
  const meta = params._meta;
  const chain = isObject(meta) ? meta["paztport/chain"] : undefined;
  const first: unknown = Array.isArray(chain) ? chain[0] : undefined;
  return isObject(first) && isString(first.bind) ? first.bind : undefined;
}

/**
 * The mock server's refusal: isError true and a `_meta` that holds only a non-audit paztport/verdict.
 * Such a response is unsigned by design; it counts as a refusal only when it answers a verified call.
 */
function hasRefusalShape(result: Rec): boolean {
  const meta = result._meta;
  if (result.isError !== true || !isObject(meta)) {
    return false;
  }
  const keys = Object.keys(meta);
  if (keys.length !== 1 || keys[0] !== META_VERDICT) {
    return false;
  }
  const verdict = meta[META_VERDICT];
  return isObject(verdict) && verdict.audit !== true;
}

function unreadable(file: string, line: number, type: string): VerifyReport {
  return { file, ok: false, items: [{ line, type, result: "UNREADABLE" }], pins: [] };
}

function verifyFile(path: string, label: string): VerifyReport {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return unreadable(label, 0, "file");
  }
  const items: VerifyItem[] = [];
  const lines: { line: number; rec: Rec }[] = [];
  text.split("\n").forEach((raw, i) => {
    if (raw.trim() === "") {
      return;
    }
    try {
      const rec: unknown = JSON.parse(raw);
      if (isObject(rec) && rec.v === 1 && isString(rec.type) && ["run", "session", "call", "response"].includes(rec.type)) {
        lines.push({ line: i + 1, rec });
        return;
      }
    } catch {
      // reported below
    }
    items.push({ line: i + 1, type: "line", result: "UNREADABLE" });
  });
  if (lines.length === 0 && items.length === 0) {
    return unreadable(label, 0, "file"); // an empty file verifies nothing
  }

  // Runs may be written after the session and before or between calls; collect them first. A second
  // run record for a rid must repeat the first prompt, otherwise the rid's prompt is in dispute.
  const prompts = new Map<string, string>();
  const disputed = new Set<string>();
  for (const { rec } of lines) {
    if (rec.type === "run" && isString(rec.rid) && isString(rec.prompt)) {
      const seen = prompts.get(rec.rid);
      if (seen === undefined) {
        prompts.set(rec.rid, rec.prompt);
      } else if (seen !== rec.prompt) {
        disputed.add(rec.rid);
      }
    }
  }

  type CallEntry = { line: number; callId: string; ok: boolean; session: Session; responded: boolean };
  // One cache for the whole file: a repeated session record must not reset replay protection.
  const nonces = new NonceCache(Number.POSITIVE_INFINITY);
  const sessions = new Map<string, Session | undefined>(); // the latest session record per server id
  const pins = new Set<string>();
  const calls = new Map<string, CallEntry>();
  const key = (server: string, rid: string, callId: string) => JSON.stringify([server, rid, callId]);
  const responses: { line: number; rec: Rec }[] = [];
  const runItems: { item: VerifyItem; rid: string }[] = [];
  const boundRids = new Set<string>();
  const firstRun = new Set<string>();

  for (const { line, rec } of lines) {
    const type = rec.type as string;
    const callId = isString(rec.callId) ? rec.callId : undefined;
    const add = (result: VerifyItem["result"]): VerifyItem => {
      const item: VerifyItem = { line, type, ...(callId !== undefined ? { callId } : {}), result };
      items.push(item);
      return item;
    };
    const server = isString(rec.server) ? rec.server : "";

    if (type === "run") {
      if (!isString(rec.rid) || !isString(rec.prompt)) {
        add("UNREADABLE");
      } else if (disputed.has(rec.rid) && (firstRun.has(rec.rid) || prompts.get(rec.rid) !== rec.prompt)) {
        add("PROMPT_MISMATCH");
      } else {
        firstRun.add(rec.rid);
        runItems.push({ item: add("OK"), rid: rec.rid });
      }
    } else if (type === "session") {
      const s = verifySession(rec);
      sessions.set(server, s);
      if (s !== undefined) {
        pins.add(pinFingerprint(rec.pin as string));
      }
      add(s !== undefined ? "OK" : "BAD_SESSION");
    } else if (type === "call") {
      const params = rec.params;
      const session = sessions.get(server);
      if (!isString(rec.callId) || !isString(rec.rid) || !isObject(params) || typeof rec.now !== "number") {
        add("UNREADABLE");
      } else if (session === undefined) {
        add("NO_SESSION");
      } else if (calls.has(key(server, rec.rid, rec.callId))) {
        add("REPLAY"); // the same call again, whatever session record precedes it
      } else {
        const v = verifyCall(params, { serverId: server }, {
          keyring: session.clientKeyring,
          root: session.clientRoot,
          rootId: session.clientRootId,
          allowedOrigins: ["session"],
          sess: session.sess,
          nonces,
          now: rec.now,
        });
        let result: VerifyItem["result"];
        if (v.result.reason !== "OK") {
          result = v.result.reason;
        } else if (v.rid !== rec.rid || v.callId !== rec.callId) {
          result = "RID_MISMATCH";
        } else {
          const prompt = disputed.has(v.rid) ? undefined : prompts.get(v.rid);
          result = prompt !== undefined && firstBind(params) === bindPrompt(prompt) ? "OK" : "PROMPT_MISMATCH";
        }
        add(result);
        const k = key(server, rec.rid, rec.callId);
        calls.set(k, { line, callId: rec.callId, ok: result === "OK", session, responded: false });
        if (result === "OK") {
          boundRids.add(rec.rid);
        }
      }
    } else {
      responses.push({ line, rec });
    }
  }

  // Responses are matched to calls only once every call has been checked: a response counts only
  // when it answers a verified call that comes before it in the file.
  for (const { line, rec } of responses) {
    const callId = isString(rec.callId) ? rec.callId : undefined;
    const add = (result: VerifyItem["result"]) => items.push({ line, type: "response", ...(callId !== undefined ? { callId } : {}), result });
    if (!isString(rec.server) || !isString(rec.callId) || !isString(rec.rid) || !isObject(rec.result) || typeof rec.now !== "number") {
      add("UNREADABLE");
      continue;
    }
    const call = calls.get(key(rec.server, rec.rid, rec.callId));
    const answered = call?.responded === true;
    if (call !== undefined) {
      call.responded = true; // a response was seen for it, so it is not also reported as unanswered
    }
    if (call === undefined || !call.ok || call.line > line) {
      add("NO_CALL");
    } else if (answered) {
      add("DUPLICATE_RESPONSE");
    } else {
      if (hasRefusalShape(rec.result)) {
        add("REFUSED");
      } else {
        const v = verifyResponse(rec.result, { rid: rec.rid, toolCallId: rec.callId }, {
          keyring: call.session.serverKeyring,
          root: call.session.serverRoot,
          rootId: call.session.serverRootId,
          allowedOrigins: ["mcp-entry"],
          sess: call.session.sess,
          nonces,
          now: rec.now,
        });
        add(v.result.reason);
      }
    }
  }

  for (const call of calls.values()) {
    if (!call.responded) {
      items.push({ line: call.line, type: "response", callId: call.callId, result: "NO_RESPONSE" });
    }
  }
  for (const { item, rid } of runItems) {
    if (!boundRids.has(rid)) {
      item.result = "UNBOUND";
    }
  }
  items.sort((a, b) => a.line - b.line); // stable: a call's NO_RESPONSE follows its own item
  const ok = items.every((i) => NOT_FAILURES.includes(i.result));
  const nothingToCheck = ok && lines.every(({ rec }) => rec.type === "run");
  return { file: label, ok, items, pins: [...pins], ...(nothingToCheck ? { nothingToCheck: true as const } : {}) };
}

/** Never throws. A missing file, a malformed line or an unknown record gives an UNREADABLE item. */
export function verifyEvidence(file: string): VerifyReport {
  return verifyFile(file, file);
}

/** Modes in which Paztport signs, so a run in them can be expected to leave signed evidence. */
const SIGNED_MODES: readonly string[] = ["on", "clean-on"];

/** What a results folder's results.json says to expect of each run's evidence, by run folder name. */
type Expectation = "none" | "maybe" | "signed";
const STRICTNESS: Record<Expectation, number> = { none: 0, maybe: 1, signed: 2 };
/**
 * Reads results.json. A missing file is no problem (the folder is verified as any folder is). One that exists
 * but can't be used is reported as a failure, and the runs are then checked without it.
 */
function expectations(dir: string): { expected?: Map<string, Expectation>; problem?: string } {
  let text: string;
  try {
    text = readFileSync(join(dir, "results.json"), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return {};
    return { problem: `results.json can't be read (${(e as Error).message}); runs were checked without it` };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { problem: `results.json can't be read (${(e as Error).message}); runs were checked without it` };
  }
  if (!isObject(raw) || !Array.isArray(raw.runs)) return { problem: "results.json can't be read (it has no list of runs); runs were checked without it" };
  if (raw.formatVersion !== 1) return { problem: `results.json can't be read (formatVersion ${String(raw.formatVersion)}; this verify reads version 1); runs were checked without it` };
  const out = new Map<string, Expectation>();
  for (const r of raw.runs) {
    const m = isObject(r) && isString(r.dir) ? /^runs\/([^/]+)$/.exec(r.dir) : null;
    if (!m || m[1] === "." || m[1] === "..") continue;
    const status = isObject(r.verify) ? r.verify.status : undefined;
    const expect: Expectation = !SIGNED_MODES.includes(String((r as Rec).mode)) ? "none" : status === "not-recorded" ? "maybe" : "signed";
    // a run listed twice is held to the stricter of its entries
    const before = out.get(m[1]!);
    if (before === undefined || STRICTNESS[expect] > STRICTNESS[before]) out.set(m[1]!, expect);
  }
  return { expected: out };
}

/** The run's outcome log shows calls made in a signed session (records carry `sess`). */
function outcomeShowsSignedCalls(runDir: string): boolean {
  let text: string;
  try {
    text = readFileSync(join(runDir, "outcome.jsonl"), "utf8");
  } catch {
    return false;
  }
  return text.split("\n").some((raw) => {
    try {
      const rec: unknown = JSON.parse(raw);
      return isObject(rec) && isString(rec.sess);
    } catch {
      return false;
    }
  });
}

const SIGNED_CALLS_NO_EVIDENCE = "the outcome log shows signed calls, but evidence.jsonl has no signed records";

const nothingToCheck = (file: string): VerifyReport => ({ file, ok: true, items: [], pins: [], nothingToCheck: true });
const needsSigned = (file: string, problem: string): VerifyReport => ({ file, ok: false, items: [{ line: 0, type: "file", result: "UNREADABLE" }], pins: [], problem });

/**
 * Every `runs/<name>/evidence.jsonl` under a results folder, in name order, each reported on its own.
 * Folder names are shown relative to the results folder.
 *
 * When the folder has a results.json, each run it lists is judged by what its mode and stored check lead
 * one to expect: a run without Paztport, or with Paztport on but recorded as having ended before anything
 * was recorded, may have no signed evidence (NOTHING TO CHECK); any other run with Paztport on must, so a
 * missing, empty or run-record-only file fails. Evidence files results.json doesn't list are verified as
 * they are. Without results.json, only the files that exist are verified.
 *
 * Whatever results.json says (it can be edited, duplicated or deleted), a run whose outcome log shows signed
 * calls (records with `sess`) and has no signed evidence fails. A results.json that exists but can't be used
 * (unparseable, no runs list, another formatVersion) is itself reported as a failure, and the runs are then
 * checked without it. A single evidence file can't show any of this: on its own it can't tell an off run
 * from an on-run cut down to its run record.
 */
export function verifyResultsDir(dir: string): VerifyReport[] {
  let names: string[];
  try {
    names = readdirSync(join(dir, "runs"), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [unreadable("runs", 0, "directory")];
  }
  const { expected, problem } = expectations(dir);
  const reports: VerifyReport[] = [];
  if (problem !== undefined) reports.push({ file: "results.json", ok: false, items: [{ line: 0, type: "file", result: "UNREADABLE" }], pins: [], problem });
  const all = [...new Set([...names, ...(expected?.keys() ?? [])])].sort();
  for (const name of all) {
    const rel = `runs/${name}/evidence.jsonl`;
    const expect = expected?.get(name);
    let size: number | undefined;
    try {
      const st = statSync(join(dir, rel));
      if (st.isDirectory()) {
        reports.push(unreadable(rel, 0, "file")); // a directory where the evidence file should be
        continue;
      }
      size = st.size;
    } catch {
      size = undefined; // missing
    }
    const report = size === undefined || size === 0 ? undefined : verifyFile(join(dir, rel), rel);
    if (report !== undefined && report.nothingToCheck !== true) {
      reports.push(report);
      continue;
    }
    // no signed evidence: the outcome log decides first, whatever results.json says (it can be edited or deleted)
    if (outcomeShowsSignedCalls(join(dir, "runs", name))) {
      reports.push(needsSigned(rel, SIGNED_CALLS_NO_EVIDENCE));
    } else if (expect === "signed") {
      const what = report !== undefined ? "has no signed records" : size === 0 ? "is empty" : "is missing";
      reports.push(needsSigned(rel, `evidence.jsonl ${what}, but this run had Paztport on and results.json records its evidence as checked`));
    } else if (expect !== undefined || report !== undefined) {
      reports.push(report ?? nothingToCheck(rel));
    } else if (size === 0) {
      reports.push(verifyFile(join(dir, rel), rel)); // as before: an empty file verifies nothing
    }
    // else: not listed and no file, as before nothing to report
  }
  return reports;
}
