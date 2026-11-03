// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger LOG = LoggerFactory.getLogger(TrustConfiguration.class);

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
        // One reading of the clock judges every file at startup and pins them, so none can pass one check and
        // expire before the next. The pinned members, judged at that reading, then go to a config on the live clock.
        long startup = System.currentTimeMillis();
        Path keyringFile = Path.of(props.getKeyringPath());
        Path rootFile = Path.of(props.getRootPath());
        OwnMaterial.require(keyring, keyringFile, root, rootFile, pin, startup);
        // This service's own keyring and root first, then the overlap files in the order given.
        List<Path> keyringFiles = paths(props.getOverlap().getKeyringPaths());
        List<Path> rootFiles = paths(props.getOverlap().getRootPaths());
        List<KeyringFile> keyrings = new ArrayList<>(List.of(keyring));
        List<SignedRoot> roots = new ArrayList<>(List.of(root));
        for (int i = 0; i < keyringFiles.size(); i++) {
            keyrings.add(OwnMaterial.loadOverlapKeyring(keyringFiles.get(i), i));
        }
        for (int i = 0; i < rootFiles.size(); i++) {
            roots.add(OwnMaterial.loadOverlapRoot(rootFiles.get(i), i));
        }
        OwnMaterial.requireOverlap(keyrings.subList(1, keyrings.size()), keyringFiles,
                roots.subList(1, roots.size()), rootFiles, keyring, keyringFile, root, rootFile, pin, startup);
        if (!keyringFiles.isEmpty() || !rootFiles.isEmpty()) {
            LOG.info("pinning {} overlap {} and {} overlap {} beside this service's own", rootFiles.size(),
                    rootFiles.size() == 1 ? "root" : "roots", keyringFiles.size(),
                    keyringFiles.size() == 1 ? "keyring" : "keyrings");
        }
        VerifierConfig pinned = VerifierConfig.pinned(
                keyrings,
                roots,
                pin,
                Set.copyOf(props.getOrigins()),
                "",
                new InMemoryNonceCache(VerifierConfig.nonceTtlFor(props.getMaxAgeMs())),
                () -> startup,
                props.getMaxAgeMs(),
                runMaxAgeMs);
        return new Verifier(new VerifierConfig(pinned.keyrings(), pinned.roots(), pinned.policyNotAfter(),
                pinned.allowedOrigins(), pinned.sess(), pinned.nonces(), System::currentTimeMillis,
                pinned.callMaxAgeMs(), pinned.runMaxAgeMs()));
    }

    private static List<Path> paths(List<String> names) {
        return names.stream().map(Path::of).toList();
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
