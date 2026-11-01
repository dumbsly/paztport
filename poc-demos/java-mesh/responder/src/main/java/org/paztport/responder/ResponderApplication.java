// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.transport.DockerHttpClient;
import com.github.dockerjava.zerodep.ZerodepDockerHttpClient;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.paztport.core.event.EventVerifier;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ResponderApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResponderApplication.class, args);
    }

    @Bean
    DockerClient dockerClient() {
        DefaultDockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder().build();
        DockerHttpClient httpClient = new ZerodepDockerHttpClient.Builder()
                .dockerHost(config.getDockerHost())
                .build();
        return DockerClientImpl.getInstance(config, httpClient);
    }

    @Bean
    QuarantineDecider quarantineDecider(
            @Value("${quarantine.threshold}") int threshold,
            @Value("${quarantine.window-ms}") long windowMs,
            @Value("${quarantine.max-per-svc}") int maxPerSvc,
            @Value("${quarantine.svc-window-ms}") long svcWindowMs) {
        return new QuarantineDecider(
                new QuarantineConfig(threshold, windowMs, maxPerSvc, svcWindowMs), System::currentTimeMillis);
    }

    @Bean
    Quarantiner quarantiner(
            DockerClient docker,
            @Value("${quarantine.mesh-network}") String meshNetwork,
            @Value("${quarantine.quarantine-network}") String quarantineNetwork) {
        return new DockerQuarantiner(docker, meshNetwork, quarantineNetwork);
    }

    /**
     * Reads the mounted keyring with the strict reader, so a {@code notAfter} that is not an integer fails startup
     * rather than being truncated. The keyring is trusted as mounted: neither its signature nor its window is
     * checked here.
     */
    @Bean
    EventVerifier eventVerifier(
            @Value("${responder.keyring-path}") String keyringPath,
            @Value("${responder.allowed-signers}") Set<String> allowedSigners) {
        KeyringFile file = KeyringFile.load(Path.of(keyringPath));
        return new EventVerifier(Keyring.fromFile(file), allowedSigners, System::currentTimeMillis);
    }

    @Bean
    Executor quarantineExecutor() {
        return Executors.newSingleThreadExecutor();
    }

    @Bean
    ResponderService responderService(QuarantineDecider decider, Quarantiner quarantiner, Executor quarantineExecutor) {
        return new ResponderService(decider, quarantiner, quarantineExecutor);
    }
}
