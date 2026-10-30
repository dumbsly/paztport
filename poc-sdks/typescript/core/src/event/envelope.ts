// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { sign, utf8 } from "../crypto/crypto.ts";

/** Domain separator prepended to the payload before signing, so an event signature is never read as a stamp's. */
export const EVENT_DOMAIN = "paztport-event\n";

/** How far an event's `ts` may be from now, either way (ms). */
export const EVENT_WINDOW_MS = 30000;

/** How long a responder remembers an accepted event id (ms): twice the window, so a captured event cannot be replayed while its `ts` is still acceptable. */
export const EVENT_ID_TTL_MS = 2 * EVENT_WINDOW_MS;

/** The signed wrapper around an event on its way to the responder; the signature covers `payload` as sent. */
export type EventEnvelope = { signer: string; payload: string; sig: string };

/** The exact bytes that are signed: the domain prefix followed by the payload string, so the receiver never canonicalises JSON. */
export function eventSigningBytes(payload: string): Uint8Array {
  return utf8(EVENT_DOMAIN + payload);
}

/** Wraps the event's JSON text, exactly as given, in an envelope signed as `signer`. */
export function signEvent(signer: string, eventJson: string, privateKey: string): EventEnvelope {
  const payload = encode(utf8(eventJson));
  return { signer, payload, sig: encode(sign(privateKey, eventSigningBytes(payload))) };
}
