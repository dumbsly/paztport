// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class StampTest {

    private static final KeyPair KEY = Crypto.generateEd25519KeyPair();

    @Test
    void signRefusesDelimiter() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", 1, "", "a|b", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("p|i", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate()));
    }

    @Test
    void signRefusesLoneSurrogate() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "\ud800", "r", 1, "", "x", "b", "", "", KEY.getPrivate()));
    }

    @Test
    void signatureVerifiesOverSigningBytes() {
        Stamp s = Stamp.sign("pi", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate());
        assertTrue(Crypto.verify(KEY.getPublic(), s.signingBytes(), Base64Url.decode(s.sig())));
    }

    @Test
    void toJsonIsJcs() {
        Stamp s = Stamp.sign("pi", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate());
        assertEquals("{\"bind\":\"b\",\"infl\":\"\",\"inst\":\"i\",\"prev\":\"\",\"rcv\":\"x\",\"rid\":\"r\","
                + "\"sess\":\"\",\"sig\":\"" + s.sig() + "\",\"svc\":\"pi\",\"ts\":1,\"v\":3}", s.toJson());
    }

    @Test
    void roundTrip() {
        Stamp s = Stamp.sign("pi", "i", "r", 1767225600000L, "sess", "x", "b", "n", "p", KEY.getPrivate());
        ParsedChain p = Chains.parse("[" + s.toJson() + "]");
        assertTrue(p.ok());
        assertEquals(s, p.stamps().get(0));
    }

    @Test
    void signRefusesANoncharacter() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "\uFFFE", "r", 1, "", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", 1, "\uFDD0", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", 1, "", "x", "b", "", "\uD83F\uDFFF", KEY.getPrivate()));
    }

    @Test
    void signRefusesANegativeTs() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", -1, "", "x", "b", "", "", KEY.getPrivate()));
    }

    @Test
    void signRefusesTsOutsideSafeRange() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", 9007199254740992L, "", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", Long.MIN_VALUE, "", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", Long.MAX_VALUE, "", "x", "b", "", "", KEY.getPrivate()));
        Stamp.sign("pi", "i", "r", 9007199254740991L, "", "x", "b", "", "", KEY.getPrivate());
        Stamp.sign("pi", "i", "r", 0, "", "x", "b", "", "", KEY.getPrivate());
    }
}
