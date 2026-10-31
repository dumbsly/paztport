// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { sha256, utf8 } from "../crypto/crypto.ts";
import { canonicalize } from "../encoding/jcs.ts";

/** Prompt binding: SHA-256(utf8("prompt\n" + text)), base64url. */
export function bindPrompt(text: string): string {
  return encode(sha256(utf8("prompt\n" + text)));
}

/**
 * Local tool step binding: SHA-256(utf8("tool\n" + toolName + "\n" + JCS({ input, resolved }))), base64url.
 * stampLocalStep passes the signed decision as the third argument (it is named `resolved` in the hashed
 * object): { callId, resolved, verdict, routeAllowed, rulesHash }, so the call id, what the gate resolved and
 * what it decided are all covered by the stamp.
 */
export function bindLocalTool(toolName: string, input: unknown, resolved: unknown): string {
  if (toolName.includes("\n")) {
    throw new Error("toolName must not contain newlines");
  }
  return encode(sha256(utf8(`tool\n${toolName}\n${canonicalize({ input: input ?? {}, resolved: resolved ?? {} })}`)));
}

/** Result binding: SHA-256(utf8("result\n" + JCS(result without its "_meta" key))), base64url. */
export function bindResult(result: Record<string, unknown>): string {
  const { _meta: _ignored, ...rest } = result;
  return encode(sha256(utf8("result\n" + canonicalize(rest))));
}
