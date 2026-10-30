// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.http.ModeHolder;
import org.paztport.http.VerificationMode;
import org.springframework.http.ResponseEntity;

class AdminModeControllerTest {

    private static final String TOKEN = "s3cret-token";

    @Test
    void noTokenConfiguredRefusesEvenWithAHeader() {
        ModeHolder holder = new ModeHolder(VerificationMode.ENFORCE);
        for (String configured : new String[] {null, "", "  "}) {
            AdminModeController controller = new AdminModeController(holder, configured);
            assertEquals(403, controller.get(configured).getStatusCode().value());
            assertEquals(403, controller.get("anything").getStatusCode().value());
            assertEquals(403, controller.set("off", configured).getStatusCode().value());
            assertEquals(403, controller.set("off", "anything").getStatusCode().value());
        }
        assertEquals(VerificationMode.ENFORCE, holder.get());
    }

    @Test
    void wrongOrMissingTokenIsForbiddenOnGetAndPost() {
        ModeHolder holder = new ModeHolder(VerificationMode.ENFORCE);
        AdminModeController controller = new AdminModeController(holder, TOKEN);

        assertEquals(403, controller.get(null).getStatusCode().value());
        assertEquals(403, controller.get("wrong").getStatusCode().value());
        assertEquals(403, controller.set("off", null).getStatusCode().value());
        assertEquals(403, controller.set("off", "wrong").getStatusCode().value());
        assertEquals(VerificationMode.ENFORCE, holder.get());
    }

    @Test
    void rightTokenReadsAndChangesTheMode() {
        ModeHolder holder = new ModeHolder(VerificationMode.ENFORCE);
        AdminModeController controller = new AdminModeController(holder, TOKEN);

        ResponseEntity<Map<String, String>> got = controller.get(TOKEN);
        assertEquals(200, got.getStatusCode().value());
        assertEquals("ENFORCE", got.getBody().get("mode"));

        ResponseEntity<Map<String, String>> set = controller.set("audit", TOKEN);
        assertEquals(200, set.getStatusCode().value());
        assertEquals("AUDIT", set.getBody().get("mode"));
        assertEquals(VerificationMode.AUDIT, holder.get());
    }
}
