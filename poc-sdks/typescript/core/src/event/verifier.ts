// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode } from "../encoding/b64url.ts";
import { readWireBytes } from "../encoding/json.ts";
import { JSON_LIMITS } from "../encoding/json-rules.ts";
import { utf8, verify } from "../crypto/crypto.ts";
import { bool, exactly, int, object, str } from "../internal/fields.ts";
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

/** The event's members but `eventId`, which is checked apart; any member but these seven is malformed. */
const EVENT = ["reason", "suspectSvc", "suspectInst", "rid", "audit", "ts"] as const;

/** The envelope in `body`, or null unless the body's UTF-8 is exactly the JCS bytes of an object with string `signer`, `payload` and `sig` and no other member. A body holding a lone surrogate has no UTF-8 form, and is null. */
function readEnvelope(body: string): EventEnvelope | null {
  // A string longer than the wire limit has more UTF-8 bytes than that, so it is refused before it is encoded.
  if (typeof body !== "string" || body.length > JSON_LIMITS.wireBytes) return null;
  try {
    const o = object(readWireBytes(utf8(body)));
    exactly(o, ["signer", "payload", "sig"]);
    return { signer: str(o, "signer"), payload: str(o, "payload"), sig: str(o, "sig") };
  } catch {
    return null;
  }
}

/** The event in the payload's bytes: exactly the JCS bytes of an object with the event's members, each of its type and no other; `eventId` may be absent or null and is then "" for the caller to refuse as a missing id. Null otherwise. */
function readEvent(bytes: Uint8Array): ResponderEvent | null {
  try {
    const o = object(readWireBytes(bytes));
    exactly(o, EVENT, ["eventId"]);
    const absent = !Object.hasOwn(o, "eventId") || o.eventId === null;
    return {
      reason: str(o, "reason"),
      suspectSvc: str(o, "suspectSvc"),
      suspectInst: str(o, "suspectInst"),
      rid: str(o, "rid"),
      audit: bool(o, "audit"),
      ts: int(o, "ts"),
      eventId: absent ? "" : str(o, "eventId"),
    };
  } catch {
    return null;
  }
}

/**
 * Each keyring's own string entries, copied so the caller's objects no longer reach the verifier. A TypeError
 * unless `keyrings` is a non-empty array whose every member is a map, naming the first member that is not.
 */
function copyKeyrings(keyrings: unknown): ReadonlyMap<string, string>[] {
  if (!Array.isArray(keyrings) || keyrings.length === 0) throw new TypeError("keyrings must be a non-empty array");
  const copies: ReadonlyMap<string, string>[] = [];
  for (let i = 0; i < keyrings.length; i++) {
    const ring: unknown = keyrings[i];
    if (typeof ring !== "object" || ring === null || Array.isArray(ring)) throw new TypeError(`keyrings[${i}] must be an object`);
    copies.push(new Map(Object.entries(ring).filter((e): e is [string, string] => typeof e[1] === "string")));
  }
  return copies;
}

/** Decides whether an event body may reach whatever acts on it: a signed envelope from an allowed signer, fresh, and not seen before; every failure is a typed refusal that changes nothing, and nothing here throws on hostile input. */
export function createEventVerifier(opts: {
  /**
   * One or more keyrings, service name to public key, copied at construction (a TypeError unless a non-empty array
   * of objects); a signer's key is looked up by own name in each.
   */
  keyrings: readonly Readonly<Record<string, string>>[];
  allowedSigners: readonly string[];
  now: () => number;
}): { accept(body: string): EventOutcome } {
  const keyrings = copyKeyrings(opts.keyrings);
  const allowed = new Set(opts.allowedSigners);
  const seen = new Map<string, number>();
  return {
    accept(body: string): EventOutcome {
      const envelope = readEnvelope(body);
      if (envelope === null) return { refusal: "MALFORMED_ENVELOPE" };
      if (!allowed.has(envelope.signer)) return { refusal: "SIGNER_NOT_ALLOWED" };
      const keys = new Set<string>();
      for (const ring of keyrings) {
        const key = ring.get(envelope.signer);
        if (key !== undefined) keys.add(key);
      }
      if (keys.size === 0) return { refusal: "UNKNOWN_SIGNER", signer: envelope.signer };
      let signature: Uint8Array;
      try {
        signature = decode(envelope.sig);
      } catch {
        return { refusal: "BAD_SIGNATURE", signer: envelope.signer };
      }
      const signed = eventSigningBytes(envelope.payload);
      if (![...keys].some((key) => verify(key, signed, signature))) {
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
