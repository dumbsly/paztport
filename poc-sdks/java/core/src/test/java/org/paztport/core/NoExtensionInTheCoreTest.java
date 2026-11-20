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
 * so no main source of the core outside an extension's own package names that package: influence and intent read
 * what the verifier hands on, and nothing the core does depends on them.
 */
class NoExtensionInTheCoreTest {

    private static final Path CORE = Path.of("src/main/java/org/paztport/core").toAbsolutePath();

    @Test
    void noCoreSourceOutsideTheInfluencePackageNamesIt() throws IOException {
        assertNamedOnlyByItsOwn("influence");
    }

    @Test
    void noCoreSourceOutsideTheIntentPackageNamesIt() throws IOException {
        assertNamedOnlyByItsOwn("intent");
    }

    private static void assertNamedOnlyByItsOwn(String extension) throws IOException {
        Path own = CORE.resolve(extension);
        String packageName = "org.paztport.core." + extension;
        assertTrue(Files.isDirectory(own), "the " + extension + " package is where this test looks for it: " + own);
        List<String> found = new ArrayList<>();
        int scanned = 0;
        int ownNaming = 0;
        try (Stream<Path> files = Files.walk(CORE)) {
            for (Path file : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".java"))::iterator) {
                scanned++;
                if (file.startsWith(own)) {
                    ownNaming += Files.readString(file).contains(packageName) ? 1 : 0;
                } else if (Files.readString(file).contains(packageName)) {
                    found.add(CORE.relativize(file).toString());
                }
            }
        }
        // so the test cannot pass by scanning nothing, or by looking in the wrong place
        assertTrue(scanned > 50, "core main sources scanned: " + scanned);
        assertTrue(ownNaming > 0, "the " + extension + " package's own files name it");
        assertEquals(List.of(), found);
    }
}
