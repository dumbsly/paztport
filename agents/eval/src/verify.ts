// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  bindPrompt,
  decode,
  NONCE_TTL_MS,
  NonceCache,
  verifyCall,
  verifyResponse,
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
 * - REFUSED: the server refused the call. A refusal carries no attestation by design, so it is
 *   reported, not counted as a failure.
 * - NO_RESPONSE: a call with no response record (for example a run that was stopped). Reported, not
 *   counted as a failure.
 *
 * Calls are checked with serverId = the record's server id. The mock server checks calls with the
 * serverId "github", which is the record's server id in every shipped configuration. Freshness windows
 * are the library defaults.
 */
export type VerifyItem = {
  line: number;
  type: string;
  callId?: string;
  result: "OK" | ReasonCode | "BAD_SESSION" | "NO_SESSION" | "PROMPT_MISMATCH" | "UNREADABLE" | "REFUSED" | "NO_RESPONSE";
};
export type VerifyReport = { file: string; ok: boolean; items: VerifyItem[] };

const META_VERDICT = "paztport/verdict";
/** Results that are reported but do not make a file fail. */
const NOT_FAILURES: readonly string[] = ["OK", "REFUSED", "NO_RESPONSE"];

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

/** A response result with a paztport/verdict that is not an audit-mode note: a refusal. */
function isRefusal(result: unknown): boolean {
  const meta = isObject(result) ? result._meta : undefined;
  if (!isObject(meta) || !Object.hasOwn(meta, META_VERDICT)) {
    return false;
  }
  const verdict = meta[META_VERDICT];
  return !(isObject(verdict) && verdict.audit === true);
}

function unreadable(file: string, line: number, type: string): VerifyReport {
  return { file, ok: false, items: [{ line, type, result: "UNREADABLE" }] };
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

  // Runs may be written after the session and before or between calls; collect them first.
  const prompts = new Map<string, string>();
  for (const { rec } of lines) {
    if (rec.type === "run" && isString(rec.rid) && isString(rec.prompt) && !prompts.has(rec.rid)) {
      prompts.set(rec.rid, rec.prompt);
    }
  }

  const nonces = new NonceCache(NONCE_TTL_MS);
  const sessions = new Map<string, Session | undefined>(); // the latest session record per server id
  const calls = new Map<string, { line: number; rid: string }>();
  const responded = new Set<string>();

  for (const { line, rec } of lines) {
    const type = rec.type as string;
    const callId = isString(rec.callId) ? rec.callId : undefined;
    const add = (result: VerifyItem["result"]) => items.push({ line, type, ...(callId !== undefined ? { callId } : {}), result });
    const server = isString(rec.server) ? rec.server : "";

    if (type === "run") {
      add(isString(rec.rid) && isString(rec.prompt) ? "OK" : "UNREADABLE");
    } else if (type === "session") {
      const s = verifySession(rec);
      sessions.set(server, s);
      add(s !== undefined ? "OK" : "BAD_SESSION");
    } else if (type === "call") {
      const params = rec.params;
      const session = sessions.get(server);
      if (!isString(rec.callId) || !isString(rec.rid) || !isObject(params) || typeof rec.now !== "number") {
        add("UNREADABLE");
      } else if (session === undefined) {
        add("NO_SESSION");
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
        if (v.result.reason !== "OK") {
          add(v.result.reason);
        } else if (v.rid !== rec.rid || v.callId !== rec.callId) {
          add("RID_MISMATCH");
        } else {
          const prompt = prompts.get(v.rid);
          add(prompt !== undefined && firstBind(params) === bindPrompt(prompt) ? "OK" : "PROMPT_MISMATCH");
        }
        calls.set(`${server}|${rec.callId}`, { line, rid: rec.rid });
      }
    } else {
      const session = sessions.get(server);
      if (!isString(rec.callId) || !isString(rec.rid) || !isObject(rec.result) || typeof rec.now !== "number") {
        add("UNREADABLE");
        continue;
      }
      responded.add(`${server}|${rec.callId}`);
      if (isRefusal(rec.result)) {
        add("REFUSED");
      } else if (session === undefined) {
        add("NO_SESSION");
      } else {
        const v = verifyResponse(rec.result, { rid: rec.rid, toolCallId: rec.callId }, {
          keyring: session.serverKeyring,
          root: session.serverRoot,
          rootId: session.serverRootId,
          allowedOrigins: ["mcp-entry"],
          sess: session.sess,
          nonces,
          now: rec.now,
        });
        const call = calls.get(`${server}|${rec.callId}`);
        add(v.result.reason === "OK" && call !== undefined && call.rid !== rec.rid ? "RID_MISMATCH" : v.result.reason);
      }
    }
  }

  for (const [key, call] of calls) {
    if (!responded.has(key)) {
      items.push({ line: call.line, type: "response", callId: key.slice(key.indexOf("|") + 1), result: "NO_RESPONSE" });
    }
  }
  items.sort((a, b) => a.line - b.line); // stable: a call's NO_RESPONSE follows its own item
  return { file: label, ok: items.every((i) => NOT_FAILURES.includes(i.result)), items };
}

/** Never throws. A missing file, a malformed line or an unknown record gives an UNREADABLE item. */
export function verifyEvidence(file: string): VerifyReport {
  return verifyFile(file, file);
}

/**
 * Every `runs/<name>/evidence.jsonl` under a results folder, in name order, each reported on its own.
 * Folder names are shown relative to the results folder.
 */
export function verifyResultsDir(dir: string): VerifyReport[] {
  let names: string[];
  try {
    names = readdirSync(join(dir, "runs"), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch {
    return [unreadable("runs", 0, "directory")];
  }
  const reports: VerifyReport[] = [];
  for (const name of names) {
    const rel = `runs/${name}/evidence.jsonl`;
    try {
      readdirSync(join(dir, rel)); // exists as a directory: not a readable evidence file
      reports.push(unreadable(rel, 0, "file"));
      continue;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") {
        continue; // a run without evidence (nothing was attested) has nothing to verify
      }
    }
    reports.push(verifyFile(join(dir, rel), rel));
  }
  return reports;
}
