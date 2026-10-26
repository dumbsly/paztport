// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { signStampV2, type StampV2 } from "./stamp.ts";

/** The service that signs a run's origin stamp, the first in every client chain. */
export const ORIGIN_SVC = "session";

/**
 * A run's origin stamp for one server session: bound to the user prompt (`bind`), dated by the run's
 * start, with no influence and no previous stamp. Throws if a field holds the stamp delimiter.
 */
export function mintOrigin(
  fields: { rid: string; ts: number; bind: string; sess: string; inst: string },
  sessionKey: string,
): StampV2 {
  return signStampV2(
    { svc: ORIGIN_SVC, inst: fields.inst, rid: fields.rid, ts: fields.ts, sess: fields.sess, bind: fields.bind, infl: "", prev: "" },
    sessionKey,
  );
}
