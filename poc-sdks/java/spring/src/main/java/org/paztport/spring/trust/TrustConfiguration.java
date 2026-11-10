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
import org.paztport.core.verify.NonceCache;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.core.verify.Verifier;
import org.paztport.http.ModeHolder;
import org.paztport.http.VerificationMode;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.StartupMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Builds what this service signs and verifies with from its {@code paztport.*} files and settings: its stamper and
 * route proofs, the pinned verifiers for requests and for responses, and the verification mode with its admin
 * endpoint. {@link PaztportAutoConfiguration} imports it; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class TrustConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(TrustConfiguration.class);

    @Bean
    @ConditionalOnProperty("paztport.key-path")
    Stamper paztportStamper(PaztportProperties props) {
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
    ProofBundle paztportProofBundle(PaztportProperties props) {
        return StartupMaterial.loadProofs(Path.of(props.getProofsPath()));
    }

    /**
     * The requests' replay cache, in memory, unless the application defines its own {@link NonceCache}, as a service
     * run as several replicas may, to share one expiring store. The default remembers a key for
     * {@link VerifierConfig#nonceTtlFor(long)} of the call window.
     */
    @Bean
    @ConditionalOnMissingBean(NonceCache.class)
    @ConditionalOnProperty({"paztport.keyring-path", "paztport.root-path", "paztport.policy-key-path"})
    NonceCache paztportNonceCache(PaztportProperties props) {
        return new InMemoryNonceCache(VerifierConfig.nonceTtlFor(props.getMaxAgeMs()));
    }

    /** The requests' verifier: the response verifier's pinned material, over the requests' {@link NonceCache}. */
    @Bean
    @ConditionalOnProperty({"paztport.keyring-path", "paztport.root-path", "paztport.policy-key-path"})
    Verifier paztportVerifier(PaztportProperties props, NonceCache nonces, ResponseVerifier responses) {
        long minTtlMs;
        try {
            minTtlMs = Math.multiplyExact(2L, props.getMaxAgeMs());
        } catch (ArithmeticException overflow) {
            throw new IllegalStateException("paztport.max-age-ms (" + props.getMaxAgeMs()
                    + ") is too large: twice the call window must fit in a long");
        }
        if (nonces.ttlMs() < minTtlMs) {
            throw new IllegalStateException("the nonce cache remembers a key for " + nonces.ttlMs()
                    + " ms, under the " + minTtlMs + " ms that paztport.max-age-ms (" + props.getMaxAgeMs()
                    + ") needs: at least twice the call window, or a replay could outlive its record");
        }
        VerifierConfig m = responses.material();
        return new Verifier(new VerifierConfig(m.keyrings(), m.roots(), m.policyNotAfter(), m.allowedOrigins(),
                m.sess(), nonces, m.clock(), m.callMaxAgeMs(), m.runMaxAgeMs()));
    }

    /**
     * The pinned material, read and judged once, and the verifier for responses over the starter's own in-memory
     * cache, which remembers a key for {@link VerifierConfig#nonceTtlFor(long)} of the call window.
     */
    @Bean
    @ConditionalOnProperty({"paztport.keyring-path", "paztport.root-path", "paztport.policy-key-path"})
    ResponseVerifier paztportResponseVerifier(PaztportProperties props) {
        if (props.getOrigins() == null || props.getOrigins().isEmpty()) {
            throw new IllegalStateException("paztport.origins is not set: a service holding trust material names "
                    + "the origins it accepts, for example paztport.origins=gateway (at a partner they check only "
                    + "its own calls' responses, and paztport.partner.client-origins governs entry)");
        }
        long runMaxAgeMs = props.getRunMaxAgeMs() != null ? props.getRunMaxAgeMs() : props.getMaxAgeMs();
        Path keyringFile = Path.of(props.getKeyringPath());
        Path rootFile = Path.of(props.getRootPath());
        KeyringFile keyring = StartupMaterial.loadKeyring(keyringFile);
        SignedRoot root = StartupMaterial.loadRoot(rootFile);
        String pin = KeyFiles.loadPolicyPin(Path.of(props.getPolicyKeyPath()));
        // One reading of the clock judges every file at startup and pins them, so none can pass one check and
        // expire before the next. The verifier itself keeps the live clock.
        long startup = System.currentTimeMillis();
        StartupMaterial.require(keyring, keyringFile, root, rootFile, pin, startup);
        // This service's own keyring and root first, then the overlap files in the order given.
        List<Path> keyringFiles = paths(props.getOverlap().getKeyringPaths());
        List<Path> rootFiles = paths(props.getOverlap().getRootPaths());
        List<KeyringFile> keyrings = new ArrayList<>(List.of(keyring));
        List<SignedRoot> roots = new ArrayList<>(List.of(root));
        for (int i = 0; i < keyringFiles.size(); i++) {
            keyrings.add(StartupMaterial.loadOverlapKeyring(keyringFiles.get(i), i));
        }
        for (int i = 0; i < rootFiles.size(); i++) {
            roots.add(StartupMaterial.loadOverlapRoot(rootFiles.get(i), i));
        }
        StartupMaterial.requireOverlap(keyrings.subList(1, keyrings.size()), keyringFiles,
                roots.subList(1, roots.size()), rootFiles, keyring, keyringFile, root, rootFile, pin, startup);
        if (!keyringFiles.isEmpty() || !rootFiles.isEmpty()) {
            LOG.info("pinning {} overlap {} and {} overlap {} beside this service's own", rootFiles.size(),
                    rootFiles.size() == 1 ? "root" : "roots", keyringFiles.size(),
                    keyringFiles.size() == 1 ? "keyring" : "keyrings");
        }
        return new ResponseVerifier(VerifierConfig.pinned(
                keyrings,
                roots,
                pin,
                startup,
                Set.copyOf(props.getOrigins()),
                "",
                new InMemoryNonceCache(VerifierConfig.nonceTtlFor(props.getMaxAgeMs())),
                System::currentTimeMillis,
                props.getMaxAgeMs(),
                runMaxAgeMs), roots);
    }

    private static List<Path> paths(List<String> names) {
        return names.stream().map(Path::of).toList();
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    ModeHolder paztportModeHolder(PaztportProperties props) {
        return new ModeHolder(VerificationMode.fromProperty(props.getMode()));
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    @Conditional(AdminTokenSet.class)
    AdminModeController paztportAdminModeController(ModeHolder modeHolder, PaztportProperties props) {
        return new AdminModeController(modeHolder, props.getAdminToken());
    }

    /** Holds where {@code paztport.admin-token} has text: a blank value, as an unset variable gives, is no token. */
    static final class AdminTokenSet implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String token = context.getEnvironment().getProperty("paztport.admin-token");
            return token != null && !token.isBlank();
        }
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
