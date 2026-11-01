// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode } from "../encoding/b64url.ts";
import { verify } from "../crypto/crypto.ts";
import { EVENT_ID_TTL_MS, EVENT_WINDOW_MS, eventSigningBytes, type EventEnvelope } from "./envelope.ts";

/** A rejection event as the responder reads it; `suspectSvc` and `suspectInst` are "" when the result names no one. */
export type ResponderEvent = { reason: string; suspectSvc: string; suspectInst: string; rid: string; audit: boolean; ts: number; eventId: string };

/** Why a body was refused. */
export type EventRefusal =
  | "MALFORMED_ENVELOPE"
  | "SIGNER_NOT_ALLOWED"
  | "UNKNOWN_SIGNER"
  | "BAD_SIGNATURE"
  | "MALFORMED_EVENT"
  | "NO_EVENT_ID"
  | "OUTSIDE_WINDOW"
  | "REPEATED_EVENT_ID";

/** Either the verified event or a refusal; `signer` is set only for UNKNOWN_SIGNER and BAD_SIGNATURE, where it has passed the allow-list, since any other signer is attacker-chosen text. */
export type EventOutcome = { event: ResponderEvent } | { refusal: EventRefusal; signer?: string };

const MEMBERS: ReadonlySet<string> = new Set(["reason", "suspectSvc", "suspectInst", "rid", "audit", "ts", "eventId"]);
const STRINGS = ["reason", "suspectSvc", "suspectInst", "rid"] as const;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** A JSON number as written, kept because a double has already rounded away what the text said. */
class NumberText {
  readonly source: string;
  constructor(source: string) {
    this.source = source;
  }
}

/** RFC 8259's number grammar, split into its parts. */
const NUMBER = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;

/** The integer a JSON number's text has as its value, if it is an integer within ±(2^53 − 1), else null: `1.0` and `1e3` are 1 and 1000, `1.5` and `9007199254740991.4` are not integers. */
function safeIntegerByValue(source: string): number | null {
  const m = NUMBER.exec(source);
  if (m === null) return null;
  const digits = (m[2]! + (m[3] ?? "")).replace(/^0+/, "");
  if (digits === "") return 0;
  let scale = Number(m[4] ?? "0") - (m[3] ?? "").length;
  let significant = digits;
  while (significant.endsWith("0")) {
    significant = significant.slice(0, -1);
    scale++;
  }
  if (scale < 0 || significant.length + scale > 16) return null;
  const magnitude = BigInt(significant) * 10n ** BigInt(scale);
  if (magnitude > MAX_SAFE) return null;
  return Number(m[1] === "-" ? -magnitude : magnitude);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The envelope in `body`, or null unless it is exactly one JSON object with string `signer`, `payload` and `sig` and no other member. */
function readEnvelope(body: string): EventEnvelope | null {
  let node: unknown;
  try {
    node = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isRecord(node) || Object.keys(node).length !== 3) return null;
  const { signer, payload, sig } = node;
  if (!Object.hasOwn(node, "signer") || !Object.hasOwn(node, "payload") || !Object.hasOwn(node, "sig")) return null;
  if (typeof signer !== "string" || typeof payload !== "string" || typeof sig !== "string") return null;
  return { signer, payload, sig };
}

/** The event in the payload's bytes: strict UTF-8 holding exactly one JSON object with the event's members, each of its type and no other, `ts` an integer by value; `eventId` may be absent or null and is then "" for the caller to refuse as a missing id. Null otherwise. */
function readEvent(bytes: Uint8Array): ResponderEvent | null {
  let node: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    // Every number is kept as its text: a double has already rounded `9007199254740991.4` to an integer. A
    // runtime that gives no text cannot judge by value, so it refuses (the throw is caught below).
    node = JSON.parse(text, (_key, value, context?: { source?: string }) => {
      if (typeof value !== "number") return value;
      if (context?.source === undefined) throw new Error("no source text for a number");
      return new NumberText(context.source);
    });
  } catch {
    return null;
  }
  if (!isRecord(node)) return null;
  for (const name of Object.keys(node)) {
    if (!MEMBERS.has(name)) return null;
  }
  for (const name of STRINGS) {
    if (!Object.hasOwn(node, name) || typeof node[name] !== "string") return null;
  }
  const { audit, ts, eventId } = node;
  if (!Object.hasOwn(node, "audit") || typeof audit !== "boolean") return null;
  if (!Object.hasOwn(node, "ts") || !(ts instanceof NumberText)) return null;
  const tsValue = safeIntegerByValue(ts.source);
  if (tsValue === null) return null;
  const absent = !Object.hasOwn(node, "eventId") || eventId === null;
  if (!absent && typeof eventId !== "string") return null;
  return {
    reason: node.reason as string,
    suspectSvc: node.suspectSvc as string,
    suspectInst: node.suspectInst as string,
    rid: node.rid as string,
    audit,
    ts: tsValue,
    eventId: absent ? "" : (eventId as string),
  };
}

/** Decides whether an event body may reach whatever acts on it: a signed envelope from an allowed signer, fresh, and not seen before; every failure is a typed refusal that changes nothing, and nothing here throws on hostile input. */
export function createEventVerifier(opts: {
  keyring: Readonly<Record<string, string>>;
  allowedSigners: readonly string[];
  now: () => number;
}): { accept(body: string): EventOutcome } {
  const allowed = new Set(opts.allowedSigners);
  const seen = new Map<string, number>();
  return {
    accept(body: string): EventOutcome {
      const envelope = readEnvelope(body);
      if (envelope === null) return { refusal: "MALFORMED_ENVELOPE" };
      if (!allowed.has(envelope.signer)) return { refusal: "SIGNER_NOT_ALLOWED" };
      const key = Object.hasOwn(opts.keyring, envelope.signer) ? opts.keyring[envelope.signer] : undefined;
      if (typeof key !== "string") return { refusal: "UNKNOWN_SIGNER", signer: envelope.signer };
      let signature: Uint8Array;
      try {
        signature = decode(envelope.sig);
      } catch {
        return { refusal: "BAD_SIGNATURE", signer: envelope.signer };
      }
      // A payload that has no UTF-8 form has no signed bytes, so no signature covers it.
      let signed: boolean;
      try {
        signed = verify(key, eventSigningBytes(envelope.payload), signature);
      } catch {
        signed = false;
      }
      if (!signed) {
        return { refusal: "BAD_SIGNATURE", signer: envelope.signer };
      }
      let bytes: Uint8Array;
      try {
        bytes = decode(envelope.payload);
      } catch {
        return { refusal: "MALFORMED_EVENT" };
      }
      const event = readEvent(bytes);
      if (event === null) return { refusal: "MALFORMED_EVENT" };
      if (event.eventId === "") return { refusal: "NO_EVENT_ID" };
      const now = opts.now();
      if (Math.abs(now - event.ts) > EVENT_WINDOW_MS) return { refusal: "OUTSIDE_WINDOW" };
      for (const [id, receivedAt] of seen) {
        if (now - receivedAt > EVENT_ID_TTL_MS) seen.delete(id);
      }
      if (seen.has(event.eventId)) return { refusal: "REPEATED_EVENT_ID" };
      seen.set(event.eventId, now);
      return { event };
    },
  };
}
