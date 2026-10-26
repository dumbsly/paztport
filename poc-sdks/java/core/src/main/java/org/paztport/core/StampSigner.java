// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.security.PrivateKey;

/** Creates a signed {@link Stamp} from a service's private key. */
public final class StampSigner {

    private StampSigner() {
    }

    public static Stamp sign(
            String svc, String inst, String rid, long ts, String bind, String prev, PrivateKey key) {
        Stamp unsigned = new Stamp(svc, inst, rid, ts, bind, prev, "");
        String sig = Base64Url.encode(Crypto.sign(key, unsigned.signingBytes()));
        return new Stamp(svc, inst, rid, ts, bind, prev, sig);
    }
}
