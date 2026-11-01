// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.ModeHolder;
import org.paztport.http.VerificationMode;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.Durations;
import org.paztport.spring.internal.OwnMaterial;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Builds what this service signs and verifies with from its {@code paztport.*} files and settings: its stamper and
 * route proofs, the pinned verifier, and the verification mode with its admin endpoint.
 * {@link PaztportAutoConfiguration} imports it; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class TrustConfiguration {

    @Bean
    @ConditionalOnProperty("paztport.key-path")
    Stamper stamper(PaztportProperties props) {
        return new Stamper(
                props.getServiceName(),
                instance(props),
                KeyFiles.loadPrivateKey(Path.of(props.getKeyPath())),
                props.isOrigin(),
                () -> UUID.randomUUID().toString(),
                System::currentTimeMillis);
    }

    @Bean
    @ConditionalOnProperty("paztport.proofs-path")
    ProofBundle proofBundle(PaztportProperties props) {
        return OwnMaterial.loadProofs(Path.of(props.getProofsPath()));
    }

    @Bean
    @ConditionalOnProperty({"paztport.keyring-path", "paztport.root-path", "paztport.policy-key-path"})
    Verifier verifier(PaztportProperties props) {
        long runMaxAgeMs = props.getRunMaxAgeMs() != null ? props.getRunMaxAgeMs() : props.getMaxAgeMs();
        KeyringFile keyring = OwnMaterial.loadKeyring(Path.of(props.getKeyringPath()));
        SignedRoot root = OwnMaterial.loadRoot(Path.of(props.getRootPath()));
        String pin = KeyFiles.loadPolicyPin(Path.of(props.getPolicyKeyPath()));
        OwnMaterial.require(keyring, Path.of(props.getKeyringPath()), root, Path.of(props.getRootPath()), pin,
                System.currentTimeMillis());
        VerifierConfig cfg = VerifierConfig.pinned(
                keyring,
                root,
                pin,
                Set.copyOf(props.getOrigins()),
                "",
                new InMemoryNonceCache(VerifierConfig.nonceTtlFor(props.getMaxAgeMs())),
                System::currentTimeMillis,
                props.getMaxAgeMs(),
                runMaxAgeMs);
        return new Verifier(cfg);
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    ModeHolder modeHolder(PaztportProperties props) {
        return new ModeHolder(VerificationMode.fromProperty(props.getMode()));
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    AdminModeController adminModeController(ModeHolder modeHolder, PaztportProperties props) {
        return new AdminModeController(modeHolder, props.getAdminToken());
    }

    private static String instance(PaztportProperties props) {
        if (props.getInstance() != null && !props.getInstance().isBlank()) {
            return props.getInstance();
        }
        String host = System.getenv("HOSTNAME");
        if (host != null && !host.isBlank()) {
            return host;
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return props.getServiceName();
        }
    }
}
