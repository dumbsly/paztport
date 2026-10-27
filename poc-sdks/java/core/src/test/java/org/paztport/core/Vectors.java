// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Finds and loads a committed vector file from {@code spec/vectors/} by walking up from the working directory,
 * so a test does not depend on which module or directory Maven was started from.
 */
final class Vectors {

    private Vectors() {
    }

    static JsonNode load(String name) throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/" + name);
            if (Files.isRegularFile(candidate)) {
                return new ObjectMapper().readTree(Files.readAllBytes(candidate));
            }
        }
        throw new IllegalStateException("spec/vectors/" + name + " not found above " + dir);
    }
}
