// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.MerkleLeaf;
import org.paztport.core.MerkleTree;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;
import org.paztport.core.Verifier;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class PathAttestAutoConfigurationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PathAttestAutoConfiguration.class));

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    private Path writeWorld(Path dir) throws Exception {
        Files.writeString(dir.resolve("gateway.key"), Base64Url.encode(Crypto.encodePrivateKey(gateway.getPrivate())));
        JSON.writeValue(dir.resolve("keyring.json").toFile(), new KeyringFile(
                Map.of("gateway", Base64Url.encode(Crypto.encodePublicKey(gateway.getPublic()))),
                Base64Url.encode(Crypto.encodePublicKey(policy.getPublic()))));
        MerkleTree tree = MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "gateway/orders")), 8, "v1");
        JSON.writeValue(dir.resolve("root.json").toFile(), SignedRoot.sign(tree.root(), "v1", policy.getPrivate()));
        JSON.writeValue(dir.resolve("proofs-gateway.json").toFile(),
                new ProofBundle("gateway", "v1", Map.of("gateway/orders", tree.proofFor("gateway/orders"))));
        return dir;
    }

    @Test
    void callerGetsStamperAndRestClientCustomizerButNoVerifier(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(
                        "path-attest.service-name=gateway",
                        "path-attest.origin=true",
                        "path-attest.key-path=" + dir.resolve("gateway.key"),
                        "path-attest.proofs-path=" + dir.resolve("proofs-gateway.json"))
                .run(context -> {
                    assertThat(context).hasSingleBean(OutboundStamper.class);
                    assertThat(context).hasSingleBean(org.springframework.boot.web.client.RestClientCustomizer.class);
                    assertThat(context).hasSingleBean(org.springframework.boot.web.servlet.FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(Verifier.class);
                });
    }

    @Test
    void verifierServiceGetsVerifierAndFilterButNoStamper(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(
                        "path-attest.service-name=payment",
                        "path-attest.verify=true",
                        "path-attest.keyring-path=" + dir.resolve("keyring.json"),
                        "path-attest.root-path=" + dir.resolve("root.json"))
                .run(context -> {
                    assertThat(context).hasSingleBean(Verifier.class);
                    assertThat(context).hasSingleBean(org.springframework.boot.web.servlet.FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(OutboundStamper.class);
                });
    }
}
