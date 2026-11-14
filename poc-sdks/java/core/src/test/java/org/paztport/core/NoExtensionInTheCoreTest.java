// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The core guarantees who made an extension's claim and that it arrived intact, and never reads it (spec README.md),
 * so no main source of the core outside the influence package names that package: influence reads what the
 * verifier hands on, and nothing the core does depends on it.
 */
class NoExtensionInTheCoreTest {

    private static final Path CORE = Path.of("src/main/java/org/paztport/core").toAbsolutePath();
    private static final Path INFLUENCE = CORE.resolve("influence");
    private static final String PACKAGE = "org.paztport.core.influence";

    @Test
    void noCoreSourceOutsideTheInfluencePackageNamesIt() throws IOException {
        assertTrue(Files.isDirectory(INFLUENCE), "the influence package is where this test looks for it: " + INFLUENCE);
        List<String> found = new ArrayList<>();
        int scanned = 0;
        int own = 0;
        try (Stream<Path> files = Files.walk(CORE)) {
            for (Path file : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".java"))::iterator) {
                scanned++;
                if (file.startsWith(INFLUENCE)) {
                    own += Files.readString(file).contains(PACKAGE) ? 1 : 0;
                } else if (Files.readString(file).contains(PACKAGE)) {
                    found.add(CORE.relativize(file).toString());
                }
            }
        }
        // so the test cannot pass by scanning nothing, or by looking in the wrong place
        assertTrue(scanned > 50, "core main sources scanned: " + scanned);
        assertTrue(own > 0, "the influence package's own files name it");
        assertEquals(List.of(), found);
    }
}
