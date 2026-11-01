// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * One service's {@code proofs-<service>.json}: the membership proofs for exactly
 * the routes where this service is the second-to-last hop, keyed by the full
 * route string. A caller looks up the route it is about to complete
 * ({@code <its chain> / <target>}) and attaches the matching proof. Produced by
 * policy-tool, read by calling services.
 */
public record ProofBundle(String service, String rootId, Map<String, MerkleProof> proofs) {

    private static final Set<String> MEMBERS = Set.of("proofs", "rootId", "service");

    public ProofBundle {
        proofs = Map.copyOf(proofs);
    }

    /**
     * The bundle as a file, {@code {proofs, rootId, service}} in the spec's file format. A bundle is only ever a file,
     * so it may be as large as one.
     */
    public String toFile() {
        Map<String, JsonValue> byRoute = new LinkedHashMap<>();
        proofs.forEach((route, proof) -> byRoute.put(route, proof.tree()));
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("service", new JsonValue.Str(service));
        o.put("rootId", new JsonValue.Str(rootId));
        o.put("proofs", new JsonValue.Obj(byRoute));
        return JsonWriter.file(new JsonValue.Obj(o));
    }

    /** The proof for a full route string, or null if this service holds none for it. */
    public MerkleProof proofFor(String route) {
        return proofs.get(route);
    }

    /**
     * Reads {@code proofs-<service>.json} as a file, in any member order and spacing: exactly a string
     * {@code service}, a string {@code rootId} and a {@code proofs} object, each of whose names is a route and each
     * of whose values a proof object. Anything else throws {@link IllegalArgumentException}, naming the member, and
     * a file that cannot be read {@link UncheckedIOException}.
     */
    public static ProofBundle load(Path file) {
        JsonValue.Obj o = JsonFields.object(JsonReader.file(file));
        JsonFields.exactly(o, MEMBERS, Set.of());
        Map<String, MerkleProof> proofs = new LinkedHashMap<>();
        JsonFields.object(o, "proofs").members().forEach((route, proof) -> {
            if (!isRoute(route)) {
                throw new IllegalArgumentException("member proofs holds a name that is not a route");
            }
            proofs.put(route, MerkleProof.fromTree(proof));
        });
        return new ProofBundle(JsonFields.string(o, "service"), JsonFields.string(o, "rootId"), proofs);
    }

    /** Whether {@code route} is a route: at least two nodes joined by {@code /}, each a valid route node. */
    private static boolean isRoute(String route) {
        List<String> nodes = List.of(route.split("/", -1));
        try {
            nodes.forEach(Routes::requireValidNode);
        } catch (IllegalArgumentException e) {
            return false;
        }
        return nodes.size() >= 2;
    }
}
