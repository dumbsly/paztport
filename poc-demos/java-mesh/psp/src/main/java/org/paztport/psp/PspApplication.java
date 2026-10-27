// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * A payment service provider run by another organisation. It is the shop's partner, not part of its mesh: it
 * never sees the shop's routes, only a boundary stamp from the shop's egress, in a session opened by handshake.
 */
@SpringBootApplication
public class PspApplication {

    public static void main(String[] args) {
        SpringApplication.run(PspApplication.class, args);
    }
}
