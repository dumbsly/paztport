// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Runtime mode control for verifying services, so the demo can switch to audit
 * and back without restarting containers. Local POC only; not an authenticated
 * admin surface.
 */
@RestController
public class AdminModeController {

    private final ModeHolder modeHolder;

    public AdminModeController(ModeHolder modeHolder) {
        this.modeHolder = modeHolder;
    }

    @GetMapping("/admin/mode")
    public Map<String, String> get() {
        return Map.of("mode", modeHolder.get().name());
    }

    @PostMapping("/admin/mode")
    public Map<String, String> set(@RequestParam String value) {
        modeHolder.set(VerificationMode.fromProperty(value));
        return Map.of("mode", modeHolder.get().name());
    }
}
