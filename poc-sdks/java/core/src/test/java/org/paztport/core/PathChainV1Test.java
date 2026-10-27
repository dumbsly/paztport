// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PathChainV1Test {

    private static StampV1 stamp(String svc, String prev, String sig) {
        return new StampV1(svc, "host", "rid-1", 1761249600123L, "bind", prev, sig);
    }

    @Test
    void prevSigIsEmptyForAnEmptyChain() {
        assertEquals("", new PathChainV1(List.of()).prevSig());
    }

    @Test
    void prevSigIsTheLastStampsSignature() {
        PathChainV1 chain = new PathChainV1(List.of(stamp("gateway", "", "sigA")));
        assertEquals("sigA", chain.prevSig());
    }

    @Test
    void appendingLinksPrevToPreviousSignature() {
        PathChainV1 origin = new PathChainV1(List.of(stamp("gateway", "", "sigA")));
        StampV1 next = stamp("orders", origin.prevSig(), "sigB");
        PathChainV1 chain = origin.withAppended(next);

        assertEquals(2, chain.stamps().size());
        assertEquals("sigA", chain.stamps().get(1).prev());
    }

    @Test
    void encodeThenDecodeRoundTrips() {
        PathChainV1 original = new PathChainV1(List.of(stamp("gateway", "", "sigA"), stamp("orders", "sigA", "sigB")));
        String header = original.encode();
        PathChainV1 decoded = PathChainV1.decode(header);

        assertEquals(original.stamps(), decoded.stamps());
    }

    @Test
    void encodedHeaderIsBase64Url() {
        String header = new PathChainV1(List.of(stamp("gateway", "", "sigA"))).encode();
        // round-trips through the url-safe decoder without error
        assertTrue(Base64Url.decode(header).length > 0);
    }

    @Test
    void decodeFailsClosedOnGarbage() {
        assertThrows(IllegalArgumentException.class, () -> PathChainV1.decode("!!!not-base64!!!"));
    }

    @Test
    void decodeFailsClosedOnValidBase64ThatIsNotStampJson() {
        String notJson = Base64Url.encode("hello".getBytes());
        assertThrows(IllegalArgumentException.class, () -> PathChainV1.decode(notJson));
    }
}
