// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.Jcs;

/**
 * The SDK's public API names no JSON library: a user brings whichever Jackson their framework uses (Spring Boot 4's
 * web layer is on Jackson 3) and never meets the one the SDK reads with. {@link PublicApi} walks every class a user
 * can name in core's exported packages; the http module runs the same walk over its own.
 */
class PublicApiTest {

    /**
     * The Jackson annotations still on public types, each known and kept on purpose: the tools write
     * {@code root.json} and {@code keyring.json}, and the starter reads them, by binding these records, so the
     * annotations decide those files' form until the records gain writers of their own. They bind no user to
     * Jackson, since an annotation whose class is absent is ignored. Any other is a failure, and so is an entry
     * here that no longer matches, so the list cannot go stale.
     */
    private static final Set<String> ANNOTATIONS_KEPT = Set.of(
            "org.paztport.core.policy.KeyringFile: @com.fasterxml.jackson.annotation.JsonInclude",
            "org.paztport.core.policy.SignedRoot: @com.fasterxml.jackson.annotation.JsonInclude");

    @Test
    void namesNoJsonLibrary() throws Exception {
        assertTrue(PublicApi.moduleClasses(Jcs.class, "org.paztport.core").size() > 50, "found the module's classes");
        PublicApi.Findings found = PublicApi.module(Jcs.class, "org.paztport.core");
        assertTrue(found.types().isEmpty(),
                "public signatures naming a JSON library:\n  " + String.join("\n  ", found.types()));
        assertEquals(ANNOTATIONS_KEPT, found.annotations(), "JSON library annotations on public types");
    }

    /**
     * The walk reaches a forbidden type wherever it hides: a type argument, a wildcard's or a type variable's bound,
     * an array, a supertype, a protected member, a thrown type, an annotation, and a member inherited from a
     * supertype no user can name. It skips what a user cannot reach: a private method, and classes that are not
     * visible.
     */
    @Test
    void walkFindsEveryWayATypeIsExposed() {
        String f = PublicApiFixture.class.getName();
        assertEquals(Set.of(
                f + "$Exposed component tree: com.fasterxml.jackson.databind.JsonNode",
                f + "$Exposed.<init> param 0: com.fasterxml.jackson.databind.JsonNode",
                f + "$Exposed.of param 0: com.fasterxml.jackson.databind.node.ArrayNode",
                f + "$Exposed.of returns: com.fasterxml.jackson.databind.node.ObjectNode",
                f + "$Exposed.tree returns: com.fasterxml.jackson.databind.JsonNode"),
                PublicApi.of(PublicApiFixture.Exposed.class).types());

        PublicApi.Findings shown = PublicApi.of(PublicApiFixture.Shown.class);
        assertEquals(Set.of(
                f + "$Shown <T>: com.fasterxml.jackson.databind.node.ObjectNode",
                f + "$Shown extends: com.fasterxml.jackson.databind.JsonNode",
                f + "$Shown implements: com.fasterxml.jackson.databind.node.ArrayNode",
                f + "$Shown.field: com.fasterxml.jackson.databind.JsonNode",
                f + "$Shown.get returns: com.fasterxml.jackson.databind.node.ArrayNode",
                f + "$Shown.pick <U>: com.fasterxml.jackson.databind.JsonNode",
                f + "$Shown.pick param 0: com.fasterxml.jackson.databind.node.ObjectNode",
                f + "$Shown.pick returns: com.fasterxml.jackson.databind.JsonNode",
                f + "$Shown.pick throws: com.fasterxml.jackson.core.JsonProcessingException"),
                shown.types());
        assertEquals(Set.of(
                f + "$Shown: @com.fasterxml.jackson.annotation.JsonInclude",
                f + "$Shown.<init> param name: @com.fasterxml.jackson.annotation.JsonProperty",
                f + "$Shown.pick: @com.fasterxml.jackson.annotation.JsonIgnore"),
                shown.annotations());

        assertEquals(Set.of(
                f + "$Child (from " + f + "$Base).leaked returns: com.fasterxml.jackson.databind.JsonNode",
                f + "$Child (from " + f + "$Base).leakedToSubclasses returns: "
                        + "com.fasterxml.jackson.databind.node.ObjectNode"),
                PublicApi.of(PublicApiFixture.Child.class).types());

        assertTrue(PublicApi.visible(PublicApiFixture.Shown.class));
        assertTrue(PublicApi.visible(PublicApiFixture.Shown.Inner.class), "a protected member class");
        assertFalse(PublicApi.visible(PublicApiFixture.Shown.Unnamed.class), "a package-private member class");
        assertFalse(PublicApi.visible(PublicApiFixtureHidden.class), "a package-private class");
        assertFalse(PublicApi.visible(PublicApiFixtureHidden.Nested.class), "public, inside a hidden class");
    }
}
