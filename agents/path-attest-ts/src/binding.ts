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

/** v2 prompt binding: SHA-256(utf8(text)), base64url. */
export function bindPrompt(text: string): string {
  return encode(sha256(utf8(text)));
}

/** v2 MCP tools/call binding over tool name, call id and canonical arguments. */
export function bindMcpCall(toolName: string, toolCallId: string, args: unknown): string {
  return encode(sha256(utf8(`tools/call\n${toolName}\n${toolCallId}\n${canonicalize(args ?? {})}`)));
}

/** v2 result binding: canonical JSON of the result without its "_meta" key. */
export function bindResult(result: Record<string, unknown>): string {
  const { _meta: _ignored, ...rest } = result;
  return encode(sha256(utf8(canonicalize(rest))));
}
