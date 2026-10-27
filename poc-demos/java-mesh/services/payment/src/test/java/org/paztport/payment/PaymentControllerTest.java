// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

// Verification disabled so the context loads without mounted key/root files; this
// test covers the controller contract. End-to-end verification is proven by the
// glue tests and the Docker scenario-1 run.
@SpringBootTest(properties = "paztport.verify=false")
@AutoConfigureMockMvc
class PaymentControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void payReturnsPaid() throws Exception {
        mvc.perform(post("/pay").contentType(MediaType.APPLICATION_JSON).content("{\"amount\":100}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PAID"));
    }

    // The boundary client exists only where compose names a partner, so a charge here has nowhere to go.
    @Test
    void chargeWithNoPartnerIsUnavailable() throws Exception {
        mvc.perform(post("/charge").contentType(MediaType.APPLICATION_JSON).content("{\"order\":\"123\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.reason").value("NO_PARTNER"));
    }
}
