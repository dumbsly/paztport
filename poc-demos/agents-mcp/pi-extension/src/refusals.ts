// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The texts the model is shown when Paztport refuses a call. They become the tool result.

import type { LocalVerdict } from "@paztport/core";

/** For an action outside the session's folders, programs or tools. Scope is not evidence of injection, so it does not ask the model to stop. */
export const SCOPE_TEXT = "Paztport refused this action: it is outside what this session is allowed to do, so it was not carried out.";

/** For a `bash` command the gate could not check. It helps legitimate work and tells an attacker nothing useful. */
export const UNCHECKABLE_TEXT = "Paztport couldn't check this command, so it wasn't run. Use simple commands with plain paths.";

/**
 * For POLICY_EXPIRED, from the server or the local gate: the signed policy the call is checked against is past its
 * notAfter. Not the unsafe text, as expiry is no sign of an injection; it asks the model to stop because nothing will
 * pass until the user renews the policy, and naming expiry helps no attacker, who cannot renew it.
 */
export const POLICY_EXPIRED_TEXT =
  "Paztport refused this action: the signed policy it is checked against has expired, so it was not carried out. " +
  "Retrying will not work until the user renews the policy. End your turn now and tell the user that the " +
  "Paztport policy has expired and must be renewed.";

const UNSAFE_TEXT =
  "Paztport stopped this action. The system flagged it as unsafe, and it was not carried out. Actions like it stay " +
  "blocked for the rest of this session, so retrying it or trying another way will not work. A stop like this is the " +
  "system doing what the user wants. It is not a fault on your part. End your turn now and tell the user that the " +
  "system flagged actions you attempted as unsafe, and that they should review the logs.";

/**
 * The text the model gets for a refusal. An influence or session refusal says only that the action was
 * unsafe and stays blocked for the session, never why, and asks the model to stop and tell the user. An expired
 * policy has its own text (POLICY_EXPIRED_TEXT). The wording only nudges; the call is refused whatever the model
 * does next. Other codes are technical, not sticky, and keep the plain message with the code.
 */
export function refusalText(reason: string): string {
  if (reason === "INFLUENCE_DENIED" || reason === "UNSAFE_SESSION") {
    return UNSAFE_TEXT;
  }
  if (reason === "POLICY_EXPIRED") {
    return POLICY_EXPIRED_TEXT;
  }
  return `Paztport refused this call: ${reason}`;
}

/** The text the model gets for a local gate refusal: the unsafe text for influence, otherwise scope or uncheckable. */
export function localRefusalText(v: Exclude<LocalVerdict, "OK">): string {
  switch (v) {
    case "INFLUENCE_DENIED":
      return UNSAFE_TEXT;
    case "UNCHECKABLE":
      return UNCHECKABLE_TEXT;
    case "SCOPE_DENIED":
    case "PATH_NOT_ALLOWED":
      return SCOPE_TEXT;
  }
}

const REFUSAL_TEXTS = new Set([UNSAFE_TEXT, SCOPE_TEXT, UNCHECKABLE_TEXT, POLICY_EXPIRED_TEXT]);

/** Whether a tool result's content is exactly one of the local refusal texts (the whole text, nothing more). */
export function isRefusalText(content: unknown): boolean {
  const part: unknown = Array.isArray(content) && content.length === 1 ? content[0] : undefined;
  return isObject(part) && part.type === "text" && typeof part.text === "string" && REFUSAL_TEXTS.has(part.text);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
