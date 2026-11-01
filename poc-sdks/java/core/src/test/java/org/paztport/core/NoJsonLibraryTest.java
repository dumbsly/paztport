// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** The SDK reads and writes JSON itself: no main source of a module or tool names a JSON library. */
class NoJsonLibraryTest {

    private static final Path SDK = Path.of("..").toAbsolutePath().normalize();

    @Test
    void noMainSourceImportsAJsonLibrary() throws IOException {
        List<Path> roots = new ArrayList<>();
        roots.add(SDK.resolve("core/src/main"));
        roots.add(SDK.resolve("http/src/main"));
        roots.add(SDK.resolve("spring/src/main"));
        try (Stream<Path> tools = Files.list(SDK.resolve("tools"))) {
            tools.filter(Files::isDirectory).map(t -> t.resolve("src/main")).sorted().forEach(roots::add);
        }
        assertTrue(roots.size() >= 5, "core, http, spring and the tools: " + roots);

        List<String> found = new ArrayList<>();
        int scanned = 0;
        for (Path root : roots) {
            assertTrue(Files.isDirectory(root), "a source directory this test scans is missing: " + root);
            try (Stream<Path> files = Files.walk(root)) {
                for (Path file : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".java"))::iterator) {
                    scanned++;
                    for (String line : Files.readAllLines(file)) {
                        if (line.contains("com.fasterxml") || line.contains("tools.jackson")) {
                            found.add(SDK.relativize(file) + ": " + line.strip());
                        }
                    }
                }
            }
        }
        assertFalse(scanned == 0, "no source file was scanned");
        assertEquals(List.of(), found);
    }
}
