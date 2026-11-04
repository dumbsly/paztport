// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { requireStampableNames } from "./names.ts";
import { signStamp, type Stamp } from "./stamp.ts";

/**
 * A run's origin stamp for one server session, signed as the service `svc` (the client's origin name, which its policy
 * routes and its receivers' allowed origins must carry too): bound to the user prompt (`bind`), dated by the run's
 * start, naming the hop it hands to (`rcv`), with no influence and no previous stamp. Throws if a field
 * holds the stamp delimiter, or if `svc` or `rcv` is not a route node (see `requireStampableNames`), since such a stamp
 * could never verify.
 */
export function mintOrigin(
  fields: { svc: string; rid: string; ts: number; bind: string; sess: string; inst: string; rcv: string },
  sessionKey: string,
): Stamp {
  requireStampableNames(fields.svc, fields.rcv);
  return signStamp(
    { svc: fields.svc, inst: fields.inst, rid: fields.rid, ts: fields.ts, sess: fields.sess, rcv: fields.rcv, bind: fields.bind, infl: "", prev: "" },
    sessionKey,
  );
}
