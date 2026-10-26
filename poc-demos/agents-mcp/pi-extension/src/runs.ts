// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { bindPrompt, encode, mintOrigin, randomBytes, type StampV2 } from "@paztport/core";

type Run = { rid: string; ts: number; bind: string };

/** The current user-prompt run and its per-server-session origin stamps. */
export class RunState {
  private run: Run | undefined;
  private origins = new Map<string, StampV2>();

  /** Begins a new run: fresh rid, prompt binding and timestamp. Old origins are dropped. */
  start(prompt: string, now: number): void {
    this.run = { rid: encode(randomBytes(16)), ts: now, bind: bindPrompt(prompt) };
    this.origins.clear();
  }

  current(): { rid: string; ts: number; bind: string } | undefined {
    return this.run === undefined ? undefined : { ...this.run };
  }

  /** The "session" origin stamp for this run and server session, minted once per (rid, sess). */
  origin(serverSess: string, sessionKey: string, inst: string): StampV2 {
    const run = this.run;
    if (run === undefined) {
      throw new Error("no active run");
    }
    const key = JSON.stringify([run.rid, serverSess]);
    const cached = this.origins.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const stamp = mintOrigin({ rid: run.rid, ts: run.ts, bind: run.bind, sess: serverSess, inst }, sessionKey);
    this.origins.set(key, stamp);
    return stamp;
  }
}
