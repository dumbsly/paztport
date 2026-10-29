// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Runtime mode control for verifying services, so the demo can switch to audit
 * and back without restarting containers. {@code InboundFilter} skips
 * {@code /admin}, and every service shares one network, so a compromised peer
 * could otherwise turn verification off. Both verbs therefore need the
 * {@code X-Admin-Token} header to match {@code paztport.admin-token}, compared
 * in constant time. With no token configured every request is refused. This is a
 * demo control channel; a real deployment would keep it on a separate management
 * network.
 */
@RestController
public class AdminModeController {

    private static final Logger log = LoggerFactory.getLogger(AdminModeController.class);

    private final ModeHolder modeHolder;
    private final byte[] token;

    public AdminModeController(ModeHolder modeHolder, String adminToken) {
        this.modeHolder = modeHolder;
        boolean disabled = adminToken == null || adminToken.isBlank();
        this.token = disabled ? null : adminToken.getBytes(StandardCharsets.UTF_8);
        if (disabled) {
            log.warn("paztport.admin-token is not set; /admin/mode is disabled");
        }
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
        if (token == null || presented == null) {
            return false;
        }
        return MessageDigest.isEqual(token, presented.getBytes(StandardCharsets.UTF_8));
    }

    private static ResponseEntity<Map<String, String>> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "admin token required"));
    }
}
