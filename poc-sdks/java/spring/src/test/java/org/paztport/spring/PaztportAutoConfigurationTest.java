// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierV3;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

class PaztportAutoConfigurationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PaztportAutoConfiguration.class));

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /** A world shaped like keygen and policy-tool output: a signed keyring, its pin, a root and a bundle. */
    private Path writeWorld(Path dir) throws Exception {
        Files.writeString(dir.resolve("gateway.key"), Base64Url.encode(Crypto.encodePrivateKey(gateway.getPrivate())));
        Files.writeString(dir.resolve("policy.pub"), pub(policy) + "\n");
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("gateway", pub(gateway)), pub(policy), policy.getPrivate()));
        PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("gateway", "orders")), 4, policy.getPrivate());
        JSON.writeValue(dir.resolve("root.json").toFile(), built.signedRoot());
        JSON.writeValue(dir.resolve("proofs-gateway.json").toFile(), built.bundles().get("gateway"));
        return dir;
    }

    private static String[] trust(Path dir) {
        return new String[] {
            "paztport.keyring-path=" + dir.resolve("keyring.json"),
            "paztport.root-path=" + dir.resolve("root.json"),
            "paztport.policy-key-path=" + dir.resolve("policy.pub")};
    }

    private static final String[] VERIFIER_PROPS = {
        "paztport.service-name=payment", "paztport.verify=true"};

    @Test
    void callerGetsStamperAndRestClientCustomizerButNoVerifier(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(
                        "paztport.service-name=gateway",
                        "paztport.origin=true",
                        "paztport.key-path=" + dir.resolve("gateway.key"),
                        "paztport.proofs-path=" + dir.resolve("proofs-gateway.json"))
                .run(context -> {
                    assertThat(context).hasSingleBean(StamperV3.class);
                    assertThat(context).hasSingleBean(RestClientCustomizer.class);
                    assertThat(context).hasSingleBean(FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(VerifierV3.class);
                });
    }

    @Test
    void verifierServiceGetsVerifierAndFilterButNoStamper(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> {
                    assertThat(context).hasSingleBean(VerifierV3.class);
                    assertThat(context).hasSingleBean(FilterRegistrationBean.class);
                    assertThat(context).doesNotHaveBean(StamperV3.class);
                });
    }

    @Test
    void theVerifierNeedsAllThreeTrustPaths(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        String[] all = trust(dir);
        runner.withPropertyValues(all).run(context -> assertThat(context).hasSingleBean(VerifierV3.class));
        for (int left = 0; left < all.length; left++) {
            List<String> some = new ArrayList<>(List.of(all));
            some.remove(left);
            runner.withPropertyValues(some.toArray(String[]::new))
                    .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(VerifierV3.class));
        }
    }

    @Test
    void verifyingWithoutTheTrustPathsFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues("paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void anUnsignedKeyringFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                new KeyringFile(Map.of("gateway", pub(gateway)), pub(policy), null));
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void aKeyringSignedUnderAnotherKeyFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        KeyPair other = Crypto.generateEd25519KeyPair();
        JSON.writeValue(dir.resolve("keyring.json").toFile(),
                KeyringFile.sign(Map.of("gateway", pub(gateway)), pub(other), other.getPrivate()));
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void runMaxAgeIsUnsetUnlessConfigured() {
        runner.run(context -> assertThat(context.getBean(PaztportProperties.class).getRunMaxAgeMs()).isNull());
        runner.withPropertyValues("paztport.run-max-age-ms=60000")
                .run(context -> assertThat(context.getBean(PaztportProperties.class).getRunMaxAgeMs())
                        .isEqualTo(60_000L));
    }

    @Test
    void responderUrlWithoutAnEventKeyFailsAtStartup(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .withPropertyValues("paztport.responder-url=http://responder:8080")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void responderUrlWithAnEventKeyGetsTheResponderPublisher(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .withPropertyValues(
                        "paztport.responder-url=http://responder:8080",
                        "paztport.event-key-path=" + dir.resolve("gateway.key"))
                .run(context -> assertThat(context.getBean(EventPublisher.class))
                        .isInstanceOf(ResponderEventPublisher.class));
    }

    @Test
    void noResponderUrlNeedsNoEventKey(@TempDir Path dir) throws Exception {
        writeWorld(dir);
        runner.withPropertyValues(VERIFIER_PROPS)
                .withPropertyValues(trust(dir))
                .run(context -> assertThat(context.getBean(EventPublisher.class))
                        .isInstanceOf(LoggingEventPublisher.class));
    }
}
