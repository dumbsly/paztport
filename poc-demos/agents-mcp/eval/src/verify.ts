// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  callInSession,
  decode,
  encode,
  newRecordSet,
  readSessionReply,
  readSessionRequest,
  recordedSession,
  sha256,
  utf8,
  type ReasonCode,
  type RecordedSession,
} from "@paztport/core";
import { hasRefusalShape, verifyMcpResponse, verifyRecordedCall } from "@paztport/mcp";
import { ORIGIN_SVC, verifyClient, verifyLocal, type Client, type LocalResult, type NamedClient, type RunInfo } from "./verify-local.ts";

/**
 * Offline re-check of a run's evidence file (the `evidenceLog` of the pi extension). It needs no keys
 * of ours: the pinned server key is in the file, and everything else is checked against it.
 *
 * Every signature, link, binding, proof, influence, replay, session and local-step check is the library's: calls
 * are recorded chains (verifyRecordedCall), responses are checked as the client checked them (verifyMcpResponse
 * at the recorded time, ending at the call's caller), sessions are recorded handshakes (recordedSession), judged
 * again at each call's recorded time (callInSession), and local steps are the library's recorded local steps
 * (verifyRecordedLocalStep, through verify-local.ts). What is here is reading the evidence format, matching
 * records to each other, the client record, and the report. Every Paztport object a record holds is its token, read
 * by the library's reader, so one that does not read gets that reader's refusal.
 * Of the library's codes, these are given only offline:
 * - TIME_MISMATCH: a call or local step whose stamp time is not the record's `now`, or a local step whose origin
 *   time is not its run's.
 * - PROMPT_MISMATCH: a call or local step whose origin does not bind its run's recorded prompt (or its run has no
 *   record, or two that disagree); also a second run record for a rid with another prompt.
 * - OUTSIDE_SESSION: a call that verifies, in a verified session, but recorded after its session's reply
 *   certificate, or a root or keyring of its handshake (either side's), expired.
 * - PROOF_MISMATCH: a local record whose route proof does not prove `session/pi/local:<tool>` against the client
 *   root, or whose signed `routeAllowed` does not match whether it has a proof.
 * - RULES_MISMATCH: a local record whose signed rules hash is not the client record's.
 * - VERDICT_MISMATCH: a local record whose verdict does not follow from the signed rules applied to what it records.
 *
 * Results that are this verifier's own, about the evidence file rather than the protocol:
 * - BAD_SESSION: the session record does not verify against its pin, or was not attested.
 * - NO_SESSION: a call whose server has no verified session before it (a response to it is NO_CALL).
 * - UNREADABLE: a line, record or file that cannot be read.
 * - NO_CALL: a response with no verified call before it (same server, rid and call id).
 * - DUPLICATE_RESPONSE: a second response record for a call that already has one.
 * - REFUSED: the server refused a call that itself verified. A refusal carries no signature or
 *   attestation by design, so verify cannot check it: it checks only that the response has the
 *   server's refusal shape (isError, and a `_meta` holding only a verdict token that reads and is not an audit
 *   note) and answers a verified call. It is reported, not counted as a failure. A refusal-looking response that
 *   carries an attestation, any other `_meta`, or a verdict that does not read is verified as an ordinary response.
 *   A local step that verified but was refused is REFUSED too.
 * - NO_RESPONSE: a call with no response record (for example a run that was stopped). Reported, not
 *   counted as a failure.
 * - UNBOUND: a run record that no verified call or local step refers to, so its prompt is not tied to
 *   anything in this file. Reported, not counted as a failure.
 * - BAD_CLIENT: a client record that does not verify (see verify-local.ts).
 * - NO_CLIENT: a local record with no verified client record before it.
 *
 * Local steps: `client` and `local` records are checked by verify-local.ts, whose comment lists the checks. A
 * verified local step is OK when it was allowed and REFUSED when it was refused; local refusals are signed and
 * checked, unlike the server's. Verify does not look at the disk.
 *
 * Replay is checked over the whole file, not over a 15 second window: the file is one record set (newRecordSet),
 * whose calls and local steps share one set of spent nonce keys, and whose responses share one nonce cache that
 * never forgets; a repeated session record resets neither.
 *
 * Calls are checked with serverId = the record's server id. The mock server checks calls with the serverId
 * "github", which is the record's server id in every shipped configuration. Calls have no freshness window offline:
 * each is checked against the time recorded with it. Responses keep the library's window, at the time the client
 * recorded verifying them.
 *
 * Lifetimes are judged at each record's own time, as the client signed it, never at the time verify runs: a call at
 * its last stamp's `ts` (the record's `now`, which must equal it, else TIME_MISMATCH), a local step likewise, and a
 * response at the time the client recorded checking it, which the library's freshness window ties to the server's
 * signed stamps. The client signs those times itself, so a client that lies about them can make its own records
 * count longer than they should; what it cannot do is move a window, which the policy key signed. A response past
 * the server's root or keyring window is POLICY_EXPIRED. A record whose root or keyring has no window does not
 * verify: a client record so is BAD_CLIENT, and a session record so opened no attested session, so no call in it is
 * judged.
 */
export type VerifyItem = {
  line: number;
  type: string;
  callId?: string;
  result:
    | "OK"
    | ReasonCode
    | "BAD_SESSION"
    | "NO_SESSION"
    | "UNREADABLE"
    | "REFUSED"
    | "NO_RESPONSE"
    | "NO_CALL"
    | "DUPLICATE_RESPONSE"
    | "UNBOUND"
    | LocalResult;
};
/**
 * `pins` are fingerprints of the server policy keys the file's verified sessions were pinned to.
 * `nothingToCheck` marks a readable file with no session, call, response or local record: only the unsigned run
 * record, which Paztport writes before any session, and the client record it writes at session start, when that
 * verifies (it is the session's configuration, not a step of the run). It is not a failure, and not a pass either.
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

/** Results that are reported but do not make a file fail. */
export const NOT_FAILURES: readonly string[] = ["OK", "REFUSED", "NO_RESPONSE", "UNBOUND"];

type Rec = Record<string, unknown>;

const isObject = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string";

/** What `read` gives, or undefined when it throws: a reader's answer for a token that may not read. */
export function readOr<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/** The mock server's entry service, from this verifier's own configuration: its responses start there, and its reply certificate names it. */
const SERVER_ENTRY = "mcp-entry";

/** What a verified session gives the checks that follow it: the recorded handshake as the library reads it, and the material its records are checked against. */
type Session = {
  recorded: RecordedSession;
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
    if (r.status !== "attested" || !isString(r.pin) || !isString(r.request) || !isString(r.reply)) {
      return undefined;
    }
    // The record carries no signed time, so the library judges the session itself at the earliest of its limits, and
    // each call again at its own recorded time.
    const recorded = recordedSession({
      request: r.request, reply: r.reply, pin: r.pin, serverEntry: SERVER_ENTRY,
    });
    if (!recorded.attested) {
      return undefined;
    }
    const request = readSessionRequest(r.request);
    const reply = readSessionReply(r.reply);
    return {
      recorded,
      clientKeyring: request.clientKeyring,
      clientRoot: decode(request.clientRoot!.root),
      clientRootId: request.clientRoot!.rootId,
      serverKeyring: reply.serverKeyring,
      serverRoot: decode(reply.serverRoot!.root),
      serverRootId: reply.serverRoot!.rootId,
      sess: reply.sess,
    };
  } catch {
    return undefined;
  }
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
      if (isObject(rec) && rec.v === 1 && isString(rec.type) && ["run", "session", "call", "response", "client", "local"].includes(rec.type)) {
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
  // Every client root, policy key, keyring and keyring window a session record names, for the client records to agree with.
  const named: NamedClient[] = [];
  const runTimes = new Map<string, Set<number>>();
  for (const { rec } of lines) {
    if (rec.type === "run" && isString(rec.rid) && isString(rec.prompt)) {
      if (typeof rec.ts === "number") runTimes.set(rec.rid, (runTimes.get(rec.rid) ?? new Set<number>()).add(rec.ts));
      const seen = prompts.get(rec.rid);
      if (seen === undefined) {
        prompts.set(rec.rid, rec.prompt);
      } else if (seen !== rec.prompt) {
        disputed.add(rec.rid);
      }
    }
    // a request that does not read names nothing
    const request = rec.type === "session" && isString(rec.request) ? readOr(() => readSessionRequest(rec.request as string)) : undefined;
    if (request !== undefined && request.clientRoot !== null) {
      named.push({
        root: request.clientRoot,
        policyKey: request.clientPolicyKey,
        keyring: request.clientKeyring,
        keyringNotAfter: request.clientKeyringNotAfter,
      });
    }
  }
  const runOf = (rid: string): RunInfo | undefined => {
    const prompt = disputed.has(rid) ? undefined : prompts.get(rid);
    return prompt === undefined ? undefined : { prompt, ts: runTimes.get(rid) ?? new Set<number>() };
  };

  /** `caller` is the verified call's last signer, the client its response must end at; "" when it did not verify. */
  type CallEntry = { line: number; callId: string; ok: boolean; caller: string; session: Session; responded: boolean };
  // The whole file is one record set: a repeated session record must not reset replay protection.
  const records = newRecordSet();
  const sessions = new Map<string, Session | undefined>(); // the latest session record per server id
  const pins = new Set<string>();
  const calls = new Map<string, CallEntry>();
  const key = (server: string, rid: string, callId: string) => JSON.stringify([server, rid, callId]);
  const responses: { line: number; rec: Rec }[] = [];
  const runItems: { item: VerifyItem; rid: string }[] = [];
  const boundRids = new Set<string>();
  const firstRun = new Set<string>();
  let client: Client | undefined; // the latest client record

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
    } else if (type === "client") {
      client = verifyClient(rec, named);
      add(client !== undefined ? "OK" : "BAD_CLIENT");
    } else if (type === "local") {
      const result = verifyLocal(rec, client, runOf, records.spent);
      add(result);
      if (result === "OK" || result === "REFUSED") {
        boundRids.add(rec.rid as string);
      }
    } else if (type === "call") {
      const params = rec.params;
      const session = sessions.get(server);
      if (!isString(rec.callId) || !isString(rec.rid) || !isObject(params) || typeof rec.now !== "number") {
        add("UNREADABLE");
      } else if (session === undefined) {
        add("NO_SESSION");
      } else {
        const run = runOf(rec.rid);
        const v = verifyRecordedCall(
          params,
          { serverId: server, rid: rec.rid, callId: rec.callId, stampedAt: rec.now, ...(run !== undefined ? { prompt: run.prompt } : {}) },
          { keyring: session.clientKeyring, root: session.clientRoot, rootId: session.clientRootId, allowedOrigins: [ORIGIN_SVC], sess: session.sess, seen: records.spent },
        );
        // `now` is the time of the call's last stamp, which the client signed (a call whose stamp time differs is
        // TIME_MISMATCH): a call recorded past one of its session's limits is OUTSIDE_SESSION. The session is attested.
        const result = callInSession(session.recorded, v.result.reason, rec.now)!;
        add(result);
        // the first record of a call is the one its response answers
        const k = key(server, rec.rid, rec.callId);
        if (!calls.has(k)) {
          calls.set(k, { line, callId: rec.callId, ok: result === "OK", caller: result === "OK" ? v.result.suspectSvc : "", session, responded: false });
        }
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
        const v = verifyMcpResponse(rec.result, { rid: rec.rid, toolCallId: rec.callId, receiver: call.caller }, {
          keyring: call.session.serverKeyring,
          root: call.session.serverRoot,
          rootId: call.session.serverRootId,
          allowedOrigins: [SERVER_ENTRY],
          sess: call.session.sess,
          nonces: records.responseNonces,
          now: rec.now,
          policyNotAfter: call.session.recorded.responseNotAfter,
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
  const nothingToCheck = ok && lines.every(({ rec }) => rec.type === "run" || rec.type === "client");
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

/**
 * Whether the run's outcome log shows calls made in a signed session (records carry a string `sess`), as
 * strictly as the eval reads the log: a missing log shows none, but one that exists and can't be read, has a
 * line that is not a JSON object, or has a `sess` that is not a string, can't show that there were none,
 * so it comes back as a problem.
 */
function outcomeShowsSignedCalls(runDir: string): boolean | { problem: string } {
  let text: string;
  try {
    text = readFileSync(join(runDir, "outcome.jsonl"), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    return { problem: `the outcome log can't be read; ${(e as Error).message}` };
  }
  let signed = false;
  const lines = text.split("\n");
  for (const [i, raw] of lines.entries()) {
    if (raw.trim() === "") continue;
    let rec: unknown;
    try {
      rec = JSON.parse(raw);
    } catch {
      return { problem: `the outcome log can't be read; line ${i + 1} is not valid JSON` };
    }
    if (!isObject(rec)) return { problem: `the outcome log can't be read; line ${i + 1} is not an outcome record` };
    if ("sess" in rec && !isString(rec.sess)) return { problem: `the outcome log can't be read; line ${i + 1} has a sess that is not a string` };
    if (isString(rec.sess)) signed = true;
  }
  return signed;
}

const SIGNED_CALLS_NO_EVIDENCE = "the outcome log shows signed calls, but evidence.jsonl has no signed records";

/**
 * Whether the run's events log shows local tool calls made during a run (`local` lines with a rid), which
 * Paztport signs. A missing log shows none; one that exists but can't be read, or has a line that is not a JSON
 * object, can't show that there were none, so it comes back as a problem.
 */
function eventsShowLocalSteps(runDir: string): boolean | { problem: string } {
  let text: string;
  try {
    text = readFileSync(join(runDir, "events.jsonl"), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    return { problem: `the events log can't be read; ${(e as Error).message}` };
  }
  let local = false;
  for (const [i, raw] of text.split("\n").entries()) {
    if (raw.trim() === "") continue;
    let rec: unknown;
    try {
      rec = JSON.parse(raw);
    } catch {
      return { problem: `the events log can't be read; line ${i + 1} is not valid JSON` };
    }
    if (!isObject(rec)) return { problem: `the events log can't be read; line ${i + 1} is not an event` };
    if (rec.type === "local" && isString(rec.rid)) local = true;
  }
  return local;
}

const LOCAL_STEPS_NO_EVIDENCE = "the events log shows local tool calls during a run, but evidence.jsonl has no signed records";

/**
 * Why a run must have signed evidence, from its own logs and whatever any record of its mode says: its outcome
 * log shows signed calls (records with `sess`), or its events log shows local tool calls made during a run
 * (`local` lines with a rid), or a log that exists can't be read and so can't show that there were none.
 * Undefined when neither log shows anything Paztport would have signed.
 */
export function signedEvidenceNeeded(runDir: string): string | undefined {
  const signed = outcomeShowsSignedCalls(runDir);
  if (typeof signed === "object") return `${signed.problem}, so it can't show that this run made no signed calls`;
  if (signed) return SIGNED_CALLS_NO_EVIDENCE;
  const local = eventsShowLocalSteps(runDir);
  if (typeof local === "object") return `${local.problem}, so it can't show that this run made no local tool calls`;
  if (local) return LOCAL_STEPS_NO_EVIDENCE;
  return undefined;
}

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
 * calls (records with `sess`) and has no signed evidence fails, and so does one whose outcome log exists but
 * can't be read (a bad line, a line that is not a record, a `sess` that is not a string). The same holds for
 * the events log: a run with no signed evidence whose events log shows local tool calls made during a run
 * (`local` lines with a rid), or exists but can't be read, fails. A results.json that exists but can't be used
 * (unparseable, no runs list, another formatVersion) is itself reported as a failure, and the runs are then
 * checked without it. A single evidence file can't show any of this: on its own it can't tell an on-run
 * cut down to its run record from a run that ended before a session.
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
    // no signed evidence: the outcome log, then the events log, decide first, whatever results.json says (it can
    // be edited or deleted)
    const need = signedEvidenceNeeded(join(dir, "runs", name));
    if (need !== undefined) {
      reports.push(needsSigned(rel, need));
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
