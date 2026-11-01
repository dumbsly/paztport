// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.PublicApi;
import org.paztport.http.wire.HttpWire;

/**
 * The HTTP module's public API names no JSON library, for the reason core's does: a user brings whichever Jackson
 * their framework uses and never meets the one the SDK reads with. The walk is core's {@link PublicApi}, from
 * core's test jar, whose own test is in core.
 */
class PublicApiTest {

    @Test
    void namesNoJsonLibrary() throws Exception {
        assertTrue(PublicApi.moduleClasses(HttpWire.class, "org.paztport.http").size() > 5, "found the module's classes");
        PublicApi.Findings found = PublicApi.module(HttpWire.class, "org.paztport.http");
        assertTrue(found.types().isEmpty(),
                "public signatures naming a JSON library:\n  " + String.join("\n  ", found.types()));
        assertEquals(Set.of(), found.annotations(), "JSON library annotations on public types");
    }
}
