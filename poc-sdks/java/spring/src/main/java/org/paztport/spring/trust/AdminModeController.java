// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import org.paztport.http.ModeHolder;
import org.paztport.http.VerificationMode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Runtime mode control for verifying services, so the mode can be switched to audit and back without a restart. The
 * starter registers it only where {@code paztport.admin-token} is set. Both verbs need the
 * {@code X-Admin-Token} header to match the token, compared in constant time, since a peer that reached the endpoint
 * could otherwise turn verification off. {@code /admin} is verified like any other path unless
 * {@code paztport.unverified-paths} lists it, and a deployment keeps the endpoint on a network only its operators
 * reach.
 */
@RestController
public class AdminModeController {

    private final ModeHolder modeHolder;
    private final byte[] token;

    /**
     * @param adminToken the token the {@code X-Admin-Token} header must match; not blank, since the switch exists
     *     only where a token is configured
     */
    public AdminModeController(ModeHolder modeHolder, String adminToken) {
        if (adminToken == null || adminToken.isBlank()) {
            throw new IllegalArgumentException("the admin mode switch needs a token (paztport.admin-token)");
        }
        this.modeHolder = modeHolder;
        this.token = adminToken.getBytes(StandardCharsets.UTF_8);
    }

    @GetMapping("/admin/mode")
    public ResponseEntity<Map<String, String>> get(
            @RequestHeader(name = "X-Admin-Token", required = false) String presented) {
        if (!authorised(presented)) {
            return forbidden();
        }
        return ResponseEntity.ok(Map.of("mode", modeHolder.get().name()));
    }

    @PostMapping("/admin/mode")
    public ResponseEntity<Map<String, String>> set(
            @RequestParam String value,
            @RequestHeader(name = "X-Admin-Token", required = false) String presented) {
        if (!authorised(presented)) {
            return forbidden();
        }
        modeHolder.set(VerificationMode.fromProperty(value));
        return ResponseEntity.ok(Map.of("mode", modeHolder.get().name()));
    }

    private boolean authorised(String presented) {
        if (presented == null) {
            return false;
        }
        return MessageDigest.isEqual(token, presented.getBytes(StandardCharsets.UTF_8));
    }

    private static ResponseEntity<Map<String, String>> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "admin token required"));
    }
}
