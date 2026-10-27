// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;

class KeyringFileTest {

    private static final KeyPair POLICY = Crypto.generateEd25519KeyPair();
    private static final KeyPair OTHER = Crypto.generateEd25519KeyPair();

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private static KeyringFile signed() {
        return KeyringFile.sign(Map.of("pi", pub(Crypto.generateEd25519KeyPair())), pub(POLICY), POLICY.getPrivate());
    }

    @Test
    void verifiesUnderItsOwnPolicyKey() {
        assertTrue(signed().verifies(pub(POLICY)));
    }

    @Test
    void failsUnderAnotherKey() {
        assertFalse(signed().verifies(pub(OTHER)));
    }

    @Test
    void failsWithOneServiceKeyChanged() {
        KeyringFile f = signed();
        KeyringFile tampered = new KeyringFile(Map.of("pi", pub(OTHER)), f.policy(), f.sig());
        assertFalse(tampered.verifies(pub(POLICY)));
    }

    @Test
    void unsignedNeverVerifies() {
        assertFalse(new KeyringFile(Map.of("pi", pub(OTHER)), pub(POLICY), null).verifies(pub(POLICY)));
    }

    @Test
    void garbageSigDoesNotThrow() {
        assertFalse(new KeyringFile(Map.of(), pub(POLICY), "!!").verifies(pub(POLICY)));
    }

    @Test
    void jsonWithAndWithoutSigDeserialises() throws Exception {
        ObjectMapper m = new ObjectMapper();
        KeyringFile f = signed();
        assertEquals(f, m.readValue(m.writeValueAsBytes(f), KeyringFile.class));
        KeyringFile bare = m.readValue("{\"services\":{},\"policy\":\"p\"}", KeyringFile.class);
        assertNull(bare.sig());
        assertFalse(m.writeValueAsString(bare).contains("sig"));
    }
}
