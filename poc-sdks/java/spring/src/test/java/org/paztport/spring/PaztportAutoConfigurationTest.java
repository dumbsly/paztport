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
import org.paztport.core.OutboundStamperV1;
import org.paztport.core.ProofBundle;
import org.paztport.core.SignedRoot;
import org.paztport.core.VerifierV1;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class PaztportAutoConfigurationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PaztportAutoConfiguration.class));

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
                        "paztport.service-name=gateway",
                        "paztport.origin=true",
                        "paztport.key-path=" + dir.resolve("gateway.key"),
                        "paztport.proofs-path=" + dir.resolve("proofs-gateway.json"))
                .run(context -> {
                    assertThat(context).hasSingleBean(OutboundStamperV1.class);
                    assertThat(context).hasSingleBean(org.springframework.boot.web.client.RestClientCustomizer.class);
                    assertThat(context).hasSingleBean(org.springframework.boot.web.servlet.FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(VerifierV1.class);
                });
    }

    @Test
    void verifierServiceGetsVerifierAndFilterButNoStamper(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(
                        "paztport.service-name=payment",
                        "paztport.verify=true",
                        "paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"))
                .run(context -> {
                    assertThat(context).hasSingleBean(VerifierV1.class);
                    assertThat(context).hasSingleBean(org.springframework.boot.web.servlet.FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(OutboundStamperV1.class);
                });
    }

    private static final String[] VERIFIER_PROPS = {
        "paztport.service-name=payment", "paztport.verify=true"};

    @Test
    void responderUrlWithoutAnEventKeyFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(
                        "paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"),
                        "paztport.responder-url=http://responder:8080")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void responderUrlWithAnEventKeyGetsTheResponderPublisher(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(
                        "paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"),
                        "paztport.responder-url=http://responder:8080",
                        "paztport.event-key-path=" + dir.resolve("gateway.key"))
                .run(context -> assertThat(context.getBean(EventPublisher.class))
                        .isInstanceOf(ResponderEventPublisher.class));
    }

    @Test
    void noResponderUrlNeedsNoEventKey(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(
                        "paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"))
                .run(context -> assertThat(context.getBean(EventPublisher.class))
                        .isInstanceOf(LoggingEventPublisher.class));
    }
}
