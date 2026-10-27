// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { signStampV3, type StampV3 } from "./stamp.ts";

/** The service that signs a run's origin stamp, the first in every client chain. */
export const ORIGIN_SVC = "session";

/**
 * A run's origin stamp for one server session: bound to the user prompt (`bind`), dated by the run's
 * start, naming the hop it hands to (`rcv`), with no influence and no previous stamp. Throws if a field
 * holds the stamp delimiter.
 */
export function mintOrigin(
  fields: { rid: string; ts: number; bind: string; sess: string; inst: string; rcv: string },
  sessionKey: string,
): StampV3 {
  return signStampV3(
    { svc: ORIGIN_SVC, inst: fields.inst, rid: fields.rid, ts: fields.ts, sess: fields.sess, rcv: fields.rcv, bind: fields.bind, infl: "", prev: "" },
    sessionKey,
  );
}
