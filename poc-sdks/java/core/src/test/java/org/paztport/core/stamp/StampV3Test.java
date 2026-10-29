// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class StampV3Test {

    private static final KeyPair KEY = Crypto.generateEd25519KeyPair();

    @Test
    void signRefusesDelimiter() {
        assertThrows(IllegalArgumentException.class,
                () -> StampV3.sign("pi", "i", "r", 1, "", "a|b", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> StampV3.sign("p|i", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate()));
    }

    @Test
    void signRefusesLoneSurrogate() {
        assertThrows(IllegalArgumentException.class,
                () -> StampV3.sign("pi", "\ud800", "r", 1, "", "x", "b", "", "", KEY.getPrivate()));
    }

    @Test
    void signatureVerifiesOverSigningBytes() {
        StampV3 s = StampV3.sign("pi", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate());
        assertTrue(Crypto.verify(KEY.getPublic(), s.signingBytes(), Base64Url.decode(s.sig())));
    }

    @Test
    void toJsonWritesVersionThenWireOrder() {
        StampV3 s = StampV3.sign("pi", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate());
        List<String> names = new ArrayList<>();
        s.toJson().fieldNames().forEachRemaining(names::add);
        assertEquals(List.of("v", "svc", "inst", "rid", "ts", "sess", "rcv", "bind", "infl", "prev", "sig"), names);
        assertEquals(3, s.toJson().get("v").asInt());
    }

    @Test
    void roundTrip() {
        StampV3 s = StampV3.sign("pi", "i", "r", 1767225600000L, "sess", "x", "b", "n", "p", KEY.getPrivate());
        ParsedChain p = Chains.parse(JsonNodeFactory.instance.arrayNode().add(s.toJson()), false);
        assertTrue(p.ok());
        assertEquals(s, p.stamps().get(0));
    }

    @Test
    void signRefusesTsOutsideSafeRange() {
        assertThrows(IllegalArgumentException.class,
                () -> StampV3.sign("pi", "i", "r", 9007199254740992L, "", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> StampV3.sign("pi", "i", "r", -9007199254740992L, "", "x", "b", "", "", KEY.getPrivate()));
        StampV3.sign("pi", "i", "r", 9007199254740991L, "", "x", "b", "", "", KEY.getPrivate());
    }
}
