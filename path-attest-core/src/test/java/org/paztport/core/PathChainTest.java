// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PathChainTest {

    private static Stamp stamp(String svc, String prev, String sig) {
        return new Stamp(svc, "host", "rid-1", 1761249600123L, "bind", prev, sig);
    }

    @Test
    void prevSigIsEmptyForAnEmptyChain() {
        assertEquals("", new PathChain(List.of()).prevSig());
    }

    @Test
    void prevSigIsTheLastStampsSignature() {
        PathChain chain = new PathChain(List.of(stamp("gateway", "", "sigA")));
        assertEquals("sigA", chain.prevSig());
    }

    @Test
    void appendingLinksPrevToPreviousSignature() {
        PathChain origin = new PathChain(List.of(stamp("gateway", "", "sigA")));
        Stamp next = stamp("orders", origin.prevSig(), "sigB");
        PathChain chain = origin.withAppended(next);

        assertEquals(2, chain.stamps().size());
        assertEquals("sigA", chain.stamps().get(1).prev());
    }

    @Test
    void encodeThenDecodeRoundTrips() {
        PathChain original = new PathChain(List.of(stamp("gateway", "", "sigA"), stamp("orders", "sigA", "sigB")));
        String header = original.encode();
        PathChain decoded = PathChain.decode(header);

        assertEquals(original.stamps(), decoded.stamps());
    }

    @Test
    void encodedHeaderIsBase64Url() {
        String header = new PathChain(List.of(stamp("gateway", "", "sigA"))).encode();
        // round-trips through the url-safe decoder without error
        assertTrue(Base64Url.decode(header).length > 0);
    }

    @Test
    void decodeFailsClosedOnGarbage() {
        assertThrows(IllegalArgumentException.class, () -> PathChain.decode("!!!not-base64!!!"));
    }

    @Test
    void decodeFailsClosedOnValidBase64ThatIsNotStampJson() {
        String notJson = Base64Url.encode("hello".getBytes());
        assertThrows(IllegalArgumentException.class, () -> PathChain.decode(notJson));
    }
}
