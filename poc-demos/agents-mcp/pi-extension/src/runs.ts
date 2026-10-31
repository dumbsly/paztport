// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { bindPrompt, encode, mintOrigin, randomBytes, type StampV3 } from "@paztport/core";
import { ORIGIN_SVC, PI_SVC } from "./keys.ts";

type Run = { rid: string; ts: number; bind: string };

/** The current user-prompt run and its per-server-session origin stamps. */
export class RunState {
  private run: Run | undefined;
  private origins = new Map<string, StampV3>();

  /** Begins a new run: fresh rid, prompt binding and timestamp. Old origins are dropped. */
  start(prompt: string, now: number): void {
    this.run = { rid: encode(randomBytes(16)), ts: now, bind: bindPrompt(prompt) };
    this.origins.clear();
  }

  /** Ends the current run, so that no call is signed until the next one starts. */
  clear(): void {
    this.run = undefined;
    this.origins.clear();
  }

  current(): { rid: string; ts: number; bind: string } | undefined {
    return this.run === undefined ? undefined : { ...this.run };
  }

  /** The run's origin stamp for this run and server session, naming pi as its receiver, minted once per (rid, sess). */
  origin(serverSess: string, sessionKey: string, inst: string): StampV3 {
    const run = this.run;
    if (run === undefined) {
      throw new Error("no active run");
    }
    const key = JSON.stringify([run.rid, serverSess]);
    const cached = this.origins.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const stamp = mintOrigin({ svc: ORIGIN_SVC, rid: run.rid, ts: run.ts, bind: run.bind, sess: serverSess, inst, rcv: PI_SVC }, sessionKey);
    this.origins.set(key, stamp);
    return stamp;
  }
}
