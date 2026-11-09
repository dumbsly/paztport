// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.spring.PaztportProperties;

class ResponseVerifierCacheTest {

    private static final long NOT_AFTER = 4_102_444_800_000L;
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The starter's own cache for responses remembers a key for the call window's nonce lifetime. */
    @Test
    void theResponseVerifiersOwnCacheRemembersForTheCallWindowsTtl(@TempDir Path dir) throws Exception {
        KeyPair gateway = Crypto.generateEd25519KeyPair();
        KeyPair policy = Crypto.generateEd25519KeyPair();
        String pin = Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()));
        Files.writeString(dir.resolve("policy.pub"), pin + "\n");
        JSON.writeValue(dir.resolve("keyring.json").toFile(), KeyringFile.sign(
                Map.of("gateway", Base64Url.encode(Crypto.encodePublicKey(gateway.getPublic()))), pin, NOT_AFTER,
                policy.getPrivate()));
        JSON.writeValue(dir.resolve("root.json").toFile(), PolicyBuilder.build(
                List.of(List.of("gateway", "orders")), 4, NOT_AFTER, policy.getPrivate()).signedRoot());

        PaztportProperties props = new PaztportProperties();
        props.setServiceName("payment");
        props.setKeyringPath(dir.resolve("keyring.json").toString());
        props.setRootPath(dir.resolve("root.json").toString());
        props.setPolicyKeyPath(dir.resolve("policy.pub").toString());
        props.setOrigins(List.of("gateway"));
        props.setMaxAgeMs(20_000);

        ResponseVerifier responses = new TrustConfiguration().paztportResponseVerifier(props);

        assertThat(responses.material().nonces().ttlMs()).isEqualTo(VerifierConfig.nonceTtlFor(20_000));
    }
}
