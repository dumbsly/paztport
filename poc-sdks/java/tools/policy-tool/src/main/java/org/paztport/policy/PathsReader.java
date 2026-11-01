// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.policy;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Reads {@code paths.yaml} into a list of routes, in file order. Fails closed: the document is one mapping whose
 * only key is {@code paths}, a non-empty list of routes, each a list of strings. A duplicate key, a type tag, or
 * anything else is malformed.
 */
public final class PathsReader {

    private PathsReader() {
    }

    public static List<List<String>> parse(byte[] yaml) {
        Object document;
        try {
            LoaderOptions options = new LoaderOptions();
            options.setAllowDuplicateKeys(false);
            document = new Yaml(new SafeConstructor(options)).load(new ByteArrayInputStream(yaml));
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed paths.yaml", e);
        }
        if (!(document instanceof Map<?, ?> top)) {
            throw new IllegalArgumentException("malformed paths.yaml");
        }
        for (Object key : top.keySet()) {
            if (!"paths".equals(key)) {
                throw new IllegalArgumentException("malformed paths.yaml");
            }
        }
        if (!(top.get("paths") instanceof List<?> routes) || routes.isEmpty()) {
            throw new IllegalArgumentException("paths.yaml has no 'paths' entries");
        }
        List<List<String>> result = new ArrayList<>();
        for (Object route : routes) {
            if (!(route instanceof List<?> steps)) {
                throw new IllegalArgumentException("malformed paths.yaml");
            }
            List<String> path = new ArrayList<>();
            for (Object step : steps) {
                if (!(step instanceof String s)) {
                    throw new IllegalArgumentException("malformed paths.yaml");
                }
                path.add(s);
            }
            result.add(List.copyOf(path));
        }
        return List.copyOf(result);
    }
}
