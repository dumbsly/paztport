// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

/**
 * A legacy v2 stamp, kept so a record written before receivers existed can still be read offline. There is no
 * signer: implementations MUST NOT produce v2, so the only way to hold one is to have parsed it.
 */
public record StampV2(String svc, String inst, String rid, long ts, String sess, String bind, String infl,
        String prev, String sig) implements RecordedStamp {

    @Override
    public byte[] signingBytes() {
        return StampV3.join("2", svc, inst, rid, Long.toString(ts), sess, bind, infl, prev);
    }

    @Override
    public String rcvOrNull() {
        return null;
    }
}
