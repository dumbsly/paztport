// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.tickets;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

@SpringBootApplication
public class TicketsApplication {

    public static void main(String[] args) {
        SpringApplication.run(TicketsApplication.class, args);
    }

    /** Built from the auto-customized builder, so the outbound stamping interceptor is attached. */
    @Bean
    RestClient restClient(RestClient.Builder builder) {
        return builder.build();
    }
}
