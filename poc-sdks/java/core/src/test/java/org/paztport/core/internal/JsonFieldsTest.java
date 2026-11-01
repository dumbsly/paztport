// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The same cases as the TypeScript SDK's {@code fields.test.ts}, so both refuse the same objects. */
class JsonFieldsTest {

    private static final Set<String> REQUIRED = Set.of("one", "two");
    private static final Set<String> OPTIONAL = Set.of("three");

    private static JsonValue read(String json) {
        return JsonReader.file(json.getBytes(StandardCharsets.UTF_8));
    }

    private static JsonValue.Obj obj(String json) {
        return JsonFields.object(read(json));
    }

    @Test
    void anObjectIsAnObjectAndNothingElseIs() {
        assertEquals(Set.of(), obj("{}").names());
        for (String json : List.of("[]", "\"a\"", "1", "null", "true")) {
            assertThrows(IllegalArgumentException.class, () -> JsonFields.object(read(json)), json);
        }
    }

    @Test
    void anArrayIsAnArrayAndNothingElseIs() {
        assertEquals(List.of(), JsonFields.array(read("[]")));
        for (String json : List.of("{}", "\"a\"", "1", "null", "true")) {
            assertThrows(IllegalArgumentException.class, () -> JsonFields.array(read(json)), json);
        }
    }

    @Test
    void exactlyTakesTheRequiredMembersAndTheOptionalOnes() {
        for (String json : List.of("{\"one\":1,\"two\":2}", "{\"one\":1,\"three\":3,\"two\":2}",
                "{\"one\":null,\"two\":2}")) {
            assertDoesNotThrow(() -> JsonFields.exactly(obj(json), REQUIRED, OPTIONAL), json);
        }
    }

    @Test
    void exactlyRefusesAMissingMemberByName() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> JsonFields.exactly(obj("{\"one\":1,\"three\":3}"), REQUIRED, OPTIONAL));
        assertTrue(e.getMessage().contains("two"), e.getMessage());
    }

    @Test
    void exactlyNamesTheFirstMissingMemberInSortedOrder() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> JsonFields.exactly(obj("{}"), Set.of("two", "one", "three"), Set.of()));
        assertEquals("no member one", e.getMessage());
    }

    @Test
    void exactlyRefusesAMemberTheSchemaDoesNotDefineWithoutEchoingIt() {
        for (String json : List.of("{\"evil\":3,\"one\":1,\"two\":2}", "{\"__proto__\":{},\"one\":1,\"two\":2}")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> JsonFields.exactly(obj(json), REQUIRED, OPTIONAL), json);
            assertFalse(e.getMessage().contains("evil") || e.getMessage().contains("proto"), e.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () -> JsonFields.exactly(obj("{\"one\":1}"), Set.of(), Set.of()));
    }

    @Test
    void eachMemberIsReadAsItsTypeOnly() {
        JsonValue.Obj o = obj("{\"count\":9007199254740991,\"flag\":true,\"nothing\":null,\"text\":\"x\"}");
        assertEquals("x", JsonFields.string(o, "text"));
        assertEquals((1L << 53) - 1, JsonFields.integer(o, "count"));
        assertTrue(JsonFields.bool(o, "flag"));
        for (String name : List.of("flag", "count", "nothing", "absent")) {
            assertTrue(assertThrows(IllegalArgumentException.class, () -> JsonFields.string(o, name)).getMessage()
                    .contains(name));
        }
        for (String name : List.of("flag", "text", "nothing", "absent")) {
            assertTrue(assertThrows(IllegalArgumentException.class, () -> JsonFields.integer(o, name)).getMessage()
                    .contains(name));
        }
        for (String name : List.of("count", "text", "nothing", "absent")) {
            assertTrue(assertThrows(IllegalArgumentException.class, () -> JsonFields.bool(o, name)).getMessage()
                    .contains(name));
        }
    }

    @Test
    void anObjectOrArrayMemberIsReadAsItsTypeOnly() {
        JsonValue.Obj o = obj("{\"inner\":{\"a\":1},\"list\":[1,\"x\"],\"nothing\":null,\"text\":\"x\"}");
        assertEquals(Set.of("a"), JsonFields.object(o, "inner").names());
        assertEquals(List.of(new JsonValue.Int(1), new JsonValue.Str("x")), JsonFields.array(o, "list"));
        for (String name : List.of("list", "text", "nothing", "absent")) {
            assertTrue(assertThrows(IllegalArgumentException.class, () -> JsonFields.object(o, name)).getMessage()
                    .contains(name));
        }
        for (String name : List.of("inner", "text", "nothing", "absent")) {
            assertTrue(assertThrows(IllegalArgumentException.class, () -> JsonFields.array(o, name)).getMessage()
                    .contains(name));
        }
    }

    @Test
    void aStringMapHoldsStringsOnlyInTheOrderRead() {
        Map<String, String> m = JsonFields.stringMap(read("{\"y\":\"2\",\"x\":\"1\"}"));
        assertEquals(List.of("y", "x"), List.copyOf(m.keySet()));
        assertEquals("1", m.get("x"));
        assertThrows(UnsupportedOperationException.class, () -> m.put("z", "3"));
        assertEquals(Map.of(), JsonFields.stringMap(read("{}")));
        for (String json : List.of("{\"x\":1}", "{\"x\":null}", "{\"x\":{}}", "[]", "\"x\"")) {
            assertThrows(IllegalArgumentException.class, () -> JsonFields.stringMap(read(json)), json);
        }
    }

    @Test
    void aStringMapMemberNamesItsMemberAndNothingTheInputChose() {
        Map<String, String> m = JsonFields.stringMap(obj("{\"m\":{\"y\":\"2\",\"x\":\"1\"}}"), "m");
        assertEquals(List.of("y", "x"), List.copyOf(m.keySet()));
        assertEquals("member m holds a value that is not a string", assertThrows(IllegalArgumentException.class,
                () -> JsonFields.stringMap(obj("{\"m\":{\"secret\":1}}"), "m")).getMessage());
        for (String json : List.of("{\"m\":[]}", "{\"m\":\"x\"}", "{}")) {
            assertEquals("member m is not an object", assertThrows(IllegalArgumentException.class,
                    () -> JsonFields.stringMap(obj(json), "m"), json).getMessage());
        }
    }
}
