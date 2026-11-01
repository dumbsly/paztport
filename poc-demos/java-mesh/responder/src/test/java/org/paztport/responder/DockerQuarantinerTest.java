// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.model.Network;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DockerQuarantinerTest {

    private static final String SERVICE_LABEL = "com.docker.compose.service";
    private static final String MESH = "paztport-mesh";
    private static final String QUARANTINE = "paztport-quarantine";

    @Test
    void resolvesPeerAddress() {
        DockerClient docker = mock(DockerClient.class, RETURNS_DEEP_STUBS);
        Network quarantine = mock(Network.class);
        when(quarantine.getName()).thenReturn(QUARANTINE);
        when(docker.listNetworksCmd().withNameFilter(QUARANTINE).exec()).thenReturn(List.of(quarantine));
        // Docker lists each member's address with its prefix length.
        Network.ContainerNetworkConfig c1 = mock(Network.ContainerNetworkConfig.class);
        when(c1.getIpv4Address()).thenReturn("172.18.0.5/16");
        when(docker.inspectNetworkCmd().withNetworkId(MESH).exec().getContainers()).thenReturn(Map.of("c1", c1));
        when(docker.inspectContainerCmd("search-1").exec().getId()).thenReturn("c9");

        DockerQuarantiner quarantiner = new DockerQuarantiner(docker, MESH, QUARANTINE);

        assertEquals("c1", quarantiner.resolve("172.18.0.5"));
        assertNull(quarantiner.resolve("172.18.0.9"));
        // Not an address: a container name or id, inspected by that name.
        assertEquals("c9", quarantiner.resolve("search-1"));
    }

    @Test
    void actsOnlyWhenTheContainerRunsTheNamedService() {
        assertTrue(DockerQuarantiner.runsService(Map.of(SERVICE_LABEL, "search"), "search"));
    }

    @Test
    void refusesAContainerOfAnotherService() {
        // search names gateway's container as its own instance
        assertFalse(DockerQuarantiner.runsService(Map.of(SERVICE_LABEL, "gateway"), "search"));
    }

    @Test
    void refusesAContainerWithoutTheLabel() {
        assertFalse(DockerQuarantiner.runsService(Map.of(), "search"));
        assertFalse(DockerQuarantiner.runsService(null, "search"));
        Map<String, String> nullValue = new HashMap<>();
        nullValue.put(SERVICE_LABEL, null);
        assertFalse(DockerQuarantiner.runsService(nullValue, "search"));
    }

    @Test
    void refusesABlankOrMissingService() {
        assertFalse(DockerQuarantiner.runsService(Map.of(SERVICE_LABEL, ""), ""));
        assertFalse(DockerQuarantiner.runsService(Map.of(SERVICE_LABEL, "search"), null));
    }

    @Test
    void aReplacementCanItselfBeQuarantinedLater() {
        Map<String, String> suspect = Map.of(SERVICE_LABEL, "search", "com.docker.compose.project", "paztport");
        Map<String, String> clone = DockerQuarantiner.replacementLabels(suspect, "search");
        assertTrue(DockerQuarantiner.runsService(clone, "search"));
        assertEquals("true", clone.get("paztport.replacement"));
        assertEquals("paztport", clone.get("com.docker.compose.project"));
    }

    @Test
    void replacementLabelsNameTheServiceEvenWhenTheSuspectHadNone() {
        Map<String, String> clone = DockerQuarantiner.replacementLabels(null, "search");
        assertTrue(DockerQuarantiner.runsService(clone, "search"));
    }
}
