// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
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

    private static final ObjectMapper READER = new ObjectMapper();

    public ProofBundle {
        proofs = Map.copyOf(proofs);
    }

    /** The wire form: the object's JCS text, {@code {proofs, rootId, service}}. */
    public String toJson() {
        Map<String, JsonValue> byRoute = new LinkedHashMap<>();
        proofs.forEach((route, proof) -> byRoute.put(route, proof.tree()));
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("service", new JsonValue.Str(service));
        o.put("rootId", new JsonValue.Str(rootId));
        o.put("proofs", new JsonValue.Obj(byRoute));
        return JsonWriter.text(new JsonValue.Obj(o));
    }

    /** The proof for a full route string, or null if this service holds none for it. */
    public MerkleProof proofFor(String route) {
        return proofs.get(route);
    }

    /**
     * Reads {@code proofs-<service>.json} as the policy tool writes it.
     *
     * @throws UncheckedIOException when the file cannot be read or is not a proof bundle
     */
    public static ProofBundle load(Path file) {
        try {
            return READER.readValue(Files.readAllBytes(file), ProofBundle.class);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }
}
