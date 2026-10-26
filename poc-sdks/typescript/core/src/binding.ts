// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "./b64url.ts";
import { concat, sha256, utf8 } from "./crypto.ts";
import { canonicalize } from "./jcs.ts";

const NL = new Uint8Array([0x0a]);

/** v1 request binding: SHA-256(method LF path LF body), base64url. */
export function bindHttp(method: string, path: string, body: Uint8Array): string {
  return encode(sha256(concat(utf8(method), NL, utf8(path), NL, body)));
}

/** v2 prompt binding: SHA-256(utf8("prompt\n" + text)), base64url. */
export function bindPrompt(text: string): string {
  return encode(sha256(utf8("prompt\n" + text)));
}

/** v2 MCP tools/call binding over tool name, call id and canonical arguments. */
export function bindMcpCall(toolName: string, toolCallId: string, args: unknown): string {
  if (toolName.includes("\n") || toolCallId.includes("\n")) {
    throw new Error("toolName and toolCallId must not contain newlines");
  }
  return encode(sha256(utf8(`tools/call\n${toolName}\n${toolCallId}\n${canonicalize(args ?? {})}`)));
}

/**
 * Local tool step binding: SHA-256(utf8("tool\n" + toolName + "\n" + JCS({ input, resolved }))), base64url.
 * The pi extension passes its signed decision as the third argument (it is named `resolved` in the hashed
 * object): { callId, resolved, verdict, routeAllowed, rulesHash }, so the call id, what the gate resolved and
 * what it decided are all covered by the stamp.
 */
export function bindLocalTool(toolName: string, input: unknown, resolved: unknown): string {
  if (toolName.includes("\n")) {
    throw new Error("toolName must not contain newlines");
  }
  return encode(sha256(utf8(`tool\n${toolName}\n${canonicalize({ input: input ?? {}, resolved: resolved ?? {} })}`)));
}

/** v2 result binding: SHA-256(utf8("result\n" + JCS(result without its "_meta" key))), base64url. */
export function bindResult(result: Record<string, unknown>): string {
  const { _meta: _ignored, ...rest } = result;
  return encode(sha256(utf8("result\n" + canonicalize(rest))));
}
