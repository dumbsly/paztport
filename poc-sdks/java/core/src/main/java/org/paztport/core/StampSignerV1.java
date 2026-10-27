// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PrivateKey;

/** Creates a signed {@link StampV1} from a service's private key. */
public final class StampSignerV1 {

    private StampSignerV1() {
    }

    public static StampV1 sign(
            String svc, String inst, String rid, long ts, String bind, String prev, PrivateKey key) {
        StampV1 unsigned = new StampV1(svc, inst, rid, ts, bind, prev, "");
        String sig = Base64Url.encode(Crypto.sign(key, unsigned.signingBytes()));
        return new StampV1(svc, inst, rid, ts, bind, prev, sig);
    }
}
