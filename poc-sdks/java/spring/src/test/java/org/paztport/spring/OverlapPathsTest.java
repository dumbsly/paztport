// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;
import org.paztport.spring.internal.OwnMaterial;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ContextConsumer;
import org.springframework.core.env.SystemEnvironmentPropertySource;

/**
 * The verifier pins {@code paztport.overlap.*} beside this service's own keyring and root, so that a renewed root or a
 * rotated key can be rolled out: every verifier pins the new one beside the old, then each holder switches, then every
 * verifier unpins the old. What this service itself presents (its own material) is not touched.
 */
class OverlapPathsTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String[] VERIFIER_PROPS = {"paztport.service-name=payment", "paztport.verify=true"};

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PaztportAutoConfiguration.class));

    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair rotated = Crypto.generateEd25519KeyPair();

    /** This service's own root, which proves gateway to orders. */
    private final PolicyBuilder.Result own = root(List.of(List.of("gateway", "orders")));

    /** A renewal that also allows gateway to payment, so its proofs are for a root the service does not hold. */
    private final PolicyBuilder.Result renewed = root(List.of(List.of("gateway", "orders"),
            List.of("gateway", "payment")));

    private PolicyBuilder.Result root(List<List<String>> routes) {
        return PolicyBuilder.build(routes, 4, NOT_AFTER, policy.getPrivate());
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    private void keyring(Path file, KeyPair key, long notAfter, KeyPair signer) throws IOException {
        JSON.writeValue(file.toFile(), KeyringFile.sign(Map.of("gateway", pub(key)), pub(policy), notAfter,
                signer.getPrivate()));
    }

    /** The service's own files: a keyring holding {@code gateway}, the root {@link #own}, and the pin. */
    private void writeOwn(Path dir) throws IOException {
        Files.writeString(dir.resolve("policy.pub"), pub(policy) + "\n");
        keyring(dir.resolve("keyring.json"), gateway, NOT_AFTER, policy);
        JSON.writeValue(dir.resolve("root.json").toFile(), own.signedRoot());
    }

    private static String[] trust(Path dir, String... more) {
        return java.util.stream.Stream.concat(java.util.stream.Stream.of(
                "paztport.keyring-path=" + dir.resolve("keyring.json"),
                "paztport.root-path=" + dir.resolve("root.json"),
                "paztport.policy-key-path=" + dir.resolve("policy.pub")),
                java.util.stream.Stream.of(more)).toArray(String[]::new);
    }

    /** What the verifier says to a first hop from gateway to orders, signed by {@code key}, proven by {@code root}. */
    private ReasonCode verdict(Verifier verifier, KeyPair key, PolicyBuilder.Result root, String rid) {
        Stamper.Stamped sent = new Stamper("gateway", "gw-1", key.getPrivate(), true, () -> rid,
                System::currentTimeMillis).next(null, "orders", "b", List.of(), root.bundles().get("gateway"));
        return verifier.verify(new VerifyInput(Chains.toJson(sent.chain()), "b", "[]", sent.proof().toJson(),
                "orders", true, rid + "|gateway|req", null)).reason();
    }

    private void runWith(Path dir, ContextConsumer<AssertableApplicationContext> then, String... more) {
        runner.withPropertyValues(VERIFIER_PROPS).withPropertyValues(trust(dir, more)).run(then);
    }

    @Test
    void aRequestProvenUnderAnOverlapRootIsAccepted(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        JSON.writeValue(dir.resolve("renewed.json").toFile(), renewed.signedRoot());

        runWith(dir, context -> assertThat(verdict(context.getBean(Verifier.class), gateway, renewed, "r-1"))
                .isEqualTo(ReasonCode.PATH_NOT_ALLOWED));
        runWith(dir, context -> {
            Verifier verifier = context.getBean(Verifier.class);
            assertThat(verdict(verifier, gateway, renewed, "r-2")).isEqualTo(ReasonCode.OK);
            assertThat(verdict(verifier, gateway, own, "r-3")).as("the service's own root still counts")
                    .isEqualTo(ReasonCode.OK);
        }, "paztport.overlap.root-paths=" + dir.resolve("renewed.json"));
    }

    @Test
    void aStampUnderAKeyOnlyInAnOverlapKeyringIsAccepted(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        keyring(dir.resolve("rotated.json"), rotated, NOT_AFTER, policy);

        runWith(dir, context -> assertThat(verdict(context.getBean(Verifier.class), rotated, own, "k-1"))
                .isEqualTo(ReasonCode.BAD_SIGNATURE));
        runWith(dir, context -> {
            Verifier verifier = context.getBean(Verifier.class);
            assertThat(verdict(verifier, rotated, own, "k-2")).isEqualTo(ReasonCode.OK);
            assertThat(verdict(verifier, gateway, own, "k-3")).as("the service's own keyring still counts")
                    .isEqualTo(ReasonCode.OK);
        }, "paztport.overlap.keyring-paths=" + dir.resolve("rotated.json"));
    }

    @Test
    void anOverlapFileThatDoesNotVerifyUnderThePinFailsStartup(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        KeyPair other = Crypto.generateEd25519KeyPair();
        keyring(dir.resolve("good.json"), rotated, NOT_AFTER, policy);
        keyring(dir.resolve("forged.json"), rotated, NOT_AFTER, other);
        JSON.writeValue(dir.resolve("forged-root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("gateway", "orders")), 4, NOT_AFTER, other.getPrivate())
                        .signedRoot());

        runWith(dir, context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause()
                    .hasMessageContaining("paztport.overlap.keyring-paths[1]")
                    .hasMessageContaining("does not verify under paztport.policy-key-path")
                    .hasMessageNotContaining(pub(rotated)).hasMessageNotContaining(pub(policy));
        }, "paztport.overlap.keyring-paths=" + dir.resolve("good.json") + "," + dir.resolve("forged.json"));
        runWith(dir, context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause()
                    .hasMessageContaining("paztport.overlap.root-paths[0]")
                    .hasMessageContaining("does not verify under paztport.policy-key-path");
        }, "paztport.overlap.root-paths=" + dir.resolve("forged-root.json"));
    }

    @Test
    void anExpiredOverlapFileFailsStartup(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        long past = System.currentTimeMillis() - 1;
        keyring(dir.resolve("old.json"), rotated, past, policy);
        JSON.writeValue(dir.resolve("old-root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("gateway", "orders")), 4, past, policy.getPrivate())
                        .signedRoot());

        runWith(dir, context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause()
                    .hasMessageContaining("paztport.overlap.keyring-paths[0]").hasMessageContaining("expired")
                    .hasMessageContaining(dir.resolve("old.json").toString());
        }, "paztport.overlap.keyring-paths=" + dir.resolve("old.json"));
        runWith(dir, context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause()
                    .hasMessageContaining("paztport.overlap.root-paths[0]").hasMessageContaining("expired");
        }, "paztport.overlap.root-paths=" + dir.resolve("old-root.json"));
    }

    @Test
    void withoutOverlapPathsTheVerifierPinsOnlyItsOwnMaterial(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        List<String> infos = infoLines(() -> runWith(dir, context -> {
            Verifier verifier = context.getBean(Verifier.class);
            assertThat(verdict(verifier, gateway, own, "o-1")).isEqualTo(ReasonCode.OK);
            assertThat(verdict(verifier, rotated, own, "o-2")).isEqualTo(ReasonCode.BAD_SIGNATURE);
            assertThat(verdict(verifier, gateway, renewed, "o-3")).isEqualTo(ReasonCode.PATH_NOT_ALLOWED);
        }));
        assertThat(infos).noneMatch(line -> line.contains("overlap"));
    }

    @Test
    void startupLogsTheOverlapCountsAndNothingElse(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        JSON.writeValue(dir.resolve("renewed.json").toFile(), renewed.signedRoot());
        List<String> infos = infoLines(() -> runWith(dir,
                context -> assertThat(context).hasNotFailed(),
                "paztport.overlap.root-paths=" + dir.resolve("renewed.json")));
        assertThat(infos).containsExactly("pinning 1 overlap root and 0 overlap keyrings beside this service's own");
    }

    @Test
    void overlapPathsWithoutTheVerifiersOwnPathsFailStartup(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        JSON.writeValue(dir.resolve("renewed.json").toFile(), renewed.signedRoot());
        runner.withPropertyValues("paztport.service-name=payment",
                        "paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"),
                        "paztport.overlap.root-paths=" + dir.resolve("renewed.json"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("paztport.overlap")
                            .hasMessageContaining("paztport.policy-key-path");
                });
    }

    @Test
    void aPartnerEntryWithOverlapPathsButNotTheVerifiersOwnFailsStartup(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        JSON.writeValue(dir.resolve("renewed.json").toFile(), renewed.signedRoot());
        runner.withPropertyValues("paztport.service-name=payment", "paztport.partner.enabled=true",
                        "paztport.keyring-path=" + dir.resolve("keyring.json"),
                        "paztport.root-path=" + dir.resolve("root.json"),
                        "paztport.overlap.root-paths=" + dir.resolve("renewed.json"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("paztport.overlap");
                });
    }

    @Test
    void anOverlapFileNearItsEndIsWarnedAboutNamingItsPlace(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        long soon = System.currentTimeMillis() + OwnMaterial.WARN_WITHIN_MS - 60_000;
        keyring(dir.resolve("far.json"), rotated, NOT_AFTER, policy);
        keyring(dir.resolve("soon.json"), rotated, soon, policy);
        JSON.writeValue(dir.resolve("soon-root.json").toFile(),
                PolicyBuilder.build(List.of(List.of("gateway", "orders"), List.of("gateway", "payment")), 4, soon,
                        policy.getPrivate()).signedRoot());

        List<String> warnings = warningsDuring(() -> runWith(dir, context -> assertThat(context).hasNotFailed(),
                "paztport.overlap.keyring-paths=" + dir.resolve("far.json") + "," + dir.resolve("soon.json"),
                "paztport.overlap.root-paths=" + dir.resolve("soon-root.json")));

        assertThat(warnings).hasSize(2);
        assertThat(warnings.get(0)).contains("paztport.overlap.keyring-paths[1]").contains(dir.resolve("soon.json")
                .toString()).contains("notAfter " + soon).contains("unpin it or replace it");
        assertThat(warnings.get(1)).contains("paztport.overlap.root-paths[0]").contains("notAfter " + soon);
    }

    @Test
    void anOverlapFileWithPlentyLeftIsNotWarnedAbout(@TempDir Path dir) throws Exception {
        writeOwn(dir);
        keyring(dir.resolve("far.json"), rotated, NOT_AFTER, policy);
        assertThat(warningsDuring(() -> runWith(dir, context -> assertThat(context).hasNotFailed(),
                "paztport.overlap.keyring-paths=" + dir.resolve("far.json")))).isEmpty();
    }

    /** The warning lines the starter's material check logs while {@code run} runs. */
    private static List<String> warningsDuring(Runnable run) {
        Logger log = (Logger) LoggerFactory.getLogger(OwnMaterial.class);
        ListAppender<ILoggingEvent> lines = new ListAppender<>();
        lines.start();
        log.addAppender(lines);
        log.setLevel(Level.WARN);
        try {
            run.run();
        } finally {
            log.detachAppender(lines);
            log.setLevel(null);
        }
        return lines.list.stream().filter(e -> e.getLevel() == Level.WARN).map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    @Test
    void aCommaSeparatedEnvironmentValueBindsToTheLists() {
        SystemEnvironmentPropertySource env = new SystemEnvironmentPropertySource("systemEnvironment", Map.of(
                "PAZTPORT_OVERLAP_ROOT_PATHS", "/config/policy/old.json,/config/policy/new.json",
                "PAZTPORT_OVERLAP_KEYRING_PATHS", "/config/keys/rotated.json"));
        PaztportProperties props = new Binder(ConfigurationPropertySources.from(env))
                .bind("paztport", PaztportProperties.class).get();
        assertThat(props.getOverlap().getRootPaths())
                .containsExactly("/config/policy/old.json", "/config/policy/new.json");
        assertThat(props.getOverlap().getKeyringPaths()).containsExactly("/config/keys/rotated.json");
        assertThat(new PaztportProperties().getOverlap().getRootPaths()).isEmpty();
    }

    /** The INFO lines the trust configuration logs while {@code run} runs. */
    private static List<String> infoLines(Runnable run) {
        Logger log = (Logger) LoggerFactory.getLogger("org.paztport.spring.trust.TrustConfiguration");
        ListAppender<ILoggingEvent> lines = new ListAppender<>();
        lines.start();
        log.addAppender(lines);
        log.setLevel(Level.INFO);
        try {
            run.run();
        } finally {
            log.detachAppender(lines);
            log.setLevel(null);
        }
        return lines.list.stream().filter(e -> e.getLevel() == Level.INFO).map(ILoggingEvent::getFormattedMessage)
                .toList();
    }
}
