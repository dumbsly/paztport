// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class KeyringTest {

    @Test
    void fromFileDecodesPublicKeysThatVerifyRealSignatures() {
        KeyPair gateway = Crypto.generateEd25519KeyPair();
        KeyPair orders = Crypto.generateEd25519KeyPair();
        KeyPair policy = Crypto.generateEd25519KeyPair();

        KeyringFile file = new KeyringFile(
                Map.of(
                        "gateway", Base64Url.encode(Crypto.encodePublicKey(gateway.getPublic())),
                        "orders", Base64Url.encode(Crypto.encodePublicKey(orders.getPublic()))),
                Base64Url.encode(Crypto.encodePublicKey(policy.getPublic())), null);

        Keyring keyring = Keyring.fromFile(file);

        byte[] msg = "hop".getBytes(StandardCharsets.UTF_8);
        assertTrue(Crypto.verify(keyring.keyFor("gateway"), msg, Crypto.sign(gateway.getPrivate(), msg)));
        assertTrue(Crypto.verify(keyring.keyFor("orders"), msg, Crypto.sign(orders.getPrivate(), msg)));
        assertNull(keyring.keyFor("unknown"), "unknown service has no key");
    }
}
