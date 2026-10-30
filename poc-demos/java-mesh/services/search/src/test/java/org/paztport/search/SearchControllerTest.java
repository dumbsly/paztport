// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

// The TLS client is off: it reads its certificates at startup, and none are mounted here.
@SpringBootTest(properties = "paztport.tls-bundle=false")
@AutoConfigureMockMvc
class SearchControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void searchReturnsResults() throws Exception {
        mvc.perform(get("/search").param("q", "shoes"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.query").value("shoes"))
                .andExpect(jsonPath("$.results").isArray());
    }
}
