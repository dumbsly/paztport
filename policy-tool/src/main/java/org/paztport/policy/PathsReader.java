// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.util.List;

/** Reads {@code paths.yaml} into a list of routes, in file order. Fails closed. */
public final class PathsReader {

    private static final YAMLMapper MAPPER = (YAMLMapper) new YAMLMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    private PathsReader() {
    }

    private record PathsFile(List<List<String>> paths) {
    }

    public static List<List<String>> parse(byte[] yaml) {
        PathsFile file;
        try {
            file = MAPPER.readValue(yaml, PathsFile.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed paths.yaml", e);
        }
        if (file == null || file.paths() == null || file.paths().isEmpty()) {
            throw new IllegalArgumentException("paths.yaml has no 'paths' entries");
        }
        return file.paths();
    }
}
