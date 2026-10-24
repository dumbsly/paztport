// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.Base64;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the last request a verifier received, for the demo's replay/mutate
 * harness. Present only when {@code path-attest.capture=true}; not part of the
 * attestation model.
 */
@RestController
public class DebugCaptureController {

    private final CaptureStore store;

    public DebugCaptureController(CaptureStore store) {
        this.store = store;
    }

    /** The captured request, with the body base64-encoded so it survives JSON. */
    public record CapturedView(String chain, String proof, String method, String path, String bodyBase64) {
    }

    @GetMapping("/debug/last-request")
    public ResponseEntity<CapturedView> lastRequest() {
        return store.last()
                .map(r -> ResponseEntity.ok(new CapturedView(
                        r.chainHeader(), r.proofHeader(), r.method(), r.path(),
                        Base64.getEncoder().encodeToString(r.body()))))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
