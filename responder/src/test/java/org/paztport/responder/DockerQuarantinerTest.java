// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DockerQuarantinerTest {

    private static final String SERVICE_LABEL = "com.docker.compose.service";

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
