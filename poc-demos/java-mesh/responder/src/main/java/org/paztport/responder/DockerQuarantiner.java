// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Quarantine via the Docker API: move the suspect off the mesh and onto an
 * isolated network (kept running for forensics), then clone a clean replacement
 * back onto the mesh under the same service alias. docker-java and the mounted
 * docker socket are the POC's stand-in for a ReplicaSet controller.
 *
 * <p>The service in an event is proven by its key, but the instance is whatever
 * that service's key holder chose to sign, so a compromised service could name
 * another service's container. Before touching anything we check that the named
 * container really runs the named service (its Compose service label), and
 * refuse otherwise. Replacements carry the same label, so a replacement that
 * misbehaves can itself be quarantined.
 */
public final class DockerQuarantiner implements Quarantiner {

    private static final Logger log = LoggerFactory.getLogger(DockerQuarantiner.class);

    /** Let the triggering request drain before we cut the suspect off the mesh. */
    private static final long GRACE_MILLIS = 750;

    /** The label Compose puts on every container it runs, naming its service. */
    static final String SERVICE_LABEL = "com.docker.compose.service";

    private final DockerClient docker;
    private final String meshNetwork;
    private final String quarantineNetwork;

    public DockerQuarantiner(DockerClient docker, String meshNetwork, String quarantineNetwork) {
        this.docker = docker;
        this.meshNetwork = meshNetwork;
        this.quarantineNetwork = quarantineNetwork;
        ensureQuarantineNetwork();
    }

    /** The quarantine network has no members, so Compose never creates it — we do. */
    private void ensureQuarantineNetwork() {
        boolean present = docker.listNetworksCmd().withNameFilter(quarantineNetwork).exec().stream()
                .anyMatch(n -> quarantineNetwork.equals(n.getName()));
        if (!present) {
            docker.createNetworkCmd().withName(quarantineNetwork).withDriver("bridge").withInternal(true).exec();
            log.info("created quarantine network {}", quarantineNetwork);
        }
    }

    @Override
    public void quarantine(String suspectSvc, String suspectInst) {
        InspectContainerResponse suspect;
        try {
            suspect = docker.inspectContainerCmd(suspectInst).exec();
        } catch (NotFoundException e) {
            log.warn("suspect container {} not found; nothing to quarantine", LogSafe.of(suspectInst));
            return;
        }
        Map<String, String> labels = suspect.getConfig() == null ? null : suspect.getConfig().getLabels();
        if (!runsService(labels, suspectSvc)) {
            log.warn("refusing to quarantine {}: that container does not run {}",
                    LogSafe.of(suspectInst), LogSafe.of(suspectSvc));
            return;
        }
        String id = suspect.getId();

        // Capture what we need to clone before we touch anything.
        String image = suspect.getConfig().getImage();
        String[] env = suspect.getConfig().getEnv();
        Bind[] binds = suspect.getHostConfig().getBinds();
        // Let the request that triggered this finish before we sever the suspect.
        sleep(GRACE_MILLIS);

        // Isolate: off the mesh, onto the quarantine network, still running.
        docker.disconnectFromNetworkCmd().withContainerId(id).withNetworkId(meshNetwork).exec();
        docker.connectToNetworkCmd().withContainerId(id).withNetworkId(quarantineNetwork).exec();
        log.warn("isolated {} ({}) onto {}", LogSafe.of(suspectSvc), LogSafe.of(suspectInst), quarantineNetwork);

        // Replace: clone image/env/labels/binds straight onto the mesh under the
        // service alias (one step — a "none"-mode container cannot also join a
        // network), so gateway's http://<svc> resolves to the clean replacement.
        Map<String, String> cloneLabels = replacementLabels(labels, suspectSvc);
        HostConfig hostConfig = HostConfig.newHostConfig().withBinds(binds).withNetworkMode(meshNetwork);
        CreateContainerResponse replacement = docker.createContainerCmd(image)
                .withEnv(env)
                .withLabels(cloneLabels)
                .withHostConfig(hostConfig)
                .withAliases(suspectSvc)
                .withName(suspectSvc + "-repl-" + (System.nanoTime() % 1_000_000))
                .exec();
        docker.startContainerCmd(replacement.getId()).exec();
        log.warn("started replacement {} on {} as {}", shortId(replacement.getId()), meshNetwork, LogSafe.of(suspectSvc));
    }

    /** Whether a container with these labels runs {@code svc}; a missing label or service is a no. */
    static boolean runsService(Map<String, String> labels, String svc) {
        if (labels == null || svc == null || svc.isBlank()) {
            return false;
        }
        return svc.equals(labels.get(SERVICE_LABEL));
    }

    /** The suspect's labels plus the service label and the replacement marker. */
    static Map<String, String> replacementLabels(Map<String, String> labels, String svc) {
        Map<String, String> cloneLabels = new LinkedHashMap<>(labels == null ? Map.of() : labels);
        cloneLabels.put(SERVICE_LABEL, svc);
        cloneLabels.put("paztport.replacement", "true"); // marker so the demo can clean replacements up
        return cloneLabels;
    }

    private static String shortId(String id) {
        return id.length() > 12 ? id.substring(0, 12) : id;
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
