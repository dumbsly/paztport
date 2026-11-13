// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The server's gate on a tools/call that no extension decides (spec sessions.md, The server decision, step 4): in an
 * unsafe session, or with no handshake yet, the tools in `disabledWhenUnsafe` are refused and every other tool runs
 * ungated; in an attested session the call is allowed here. A call that verified is decided first by the extensions
 * the server acts on (steps 2 and 3).
 */
export function decideServerCall(opts: {
  tool: string;
  /** True only for a session opened as attested. */
  attested: boolean;
  disabledWhenUnsafe: readonly string[];
}): "OK" | "UNSAFE_SESSION" {
  return !opts.attested && opts.disabledWhenUnsafe.includes(opts.tool) ? "UNSAFE_SESSION" : "OK";
}
