// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Classes that hide a Jackson type in every place {@link PublicApi} looks, for {@code PublicApiTest} to check the
 * walk against. Never used otherwise.
 */
public final class PublicApiFixture {

    private PublicApiFixture() {
    }

    /** A record whose every exposed signature hides a Jackson type one level down; the private method is not seen. */
    public record Exposed(List<Map<String, JsonNode>> tree) {

        public static Optional<? extends ObjectNode> of(ArrayNode[][] nodes) {
            return Optional.empty();
        }

        private static JsonNode hidden() {
            return null;
        }
    }

    /** A bounded type parameter, a supertype argument, an interface argument, protected members and a throw. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Shown<T extends ObjectNode> extends ArrayList<JsonNode> implements Supplier<ArrayNode> {

        protected JsonNode field;

        protected Shown(@JsonProperty("name") String name) {
        }

        @Override
        public ArrayNode get() {
            return null;
        }

        @JsonIgnore
        protected <U extends JsonNode> List<U> pick(T from) throws JsonProcessingException {
            return List.of();
        }

        /** A protected member class a subclass can name; its own public field is seen. */
        protected static class Inner {
            public ObjectNode inner;
        }

        /** A package-private member class nobody outside can name. */
        static class Unnamed {
            public JsonNode unnamed;
        }
    }

    /** A supertype a user cannot name, whose public members a visible subclass hands on. */
    abstract static class Base {

        public JsonNode leaked() {
            return null;
        }

        protected abstract ObjectNode leakedToSubclasses();
    }

    /** Visible, and inherits {@link Base}'s members, which a user reaches through it. */
    public abstract static class Child extends Base {
    }
}
