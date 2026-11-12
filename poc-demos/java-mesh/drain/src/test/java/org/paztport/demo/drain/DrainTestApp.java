// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** The smallest application that has the drain: one endpoint, and one that holds its request until released. */
@SpringBootApplication
class DrainTestApp {

    /** Counted down when {@code /wait} is entered. */
    static final CountDownLatch HANDLER_ENTERED = new CountDownLatch(1);
    /** {@code /wait} returns once this is counted down. */
    static final CountDownLatch RELEASE = new CountDownLatch(1);

    static ConfigurableApplicationContext start(String... args) {
        String[] all = new String[args.length + 1];
        all[0] = "--server.port=0";
        System.arraycopy(args, 0, all, 1, args.length);
        return SpringApplication.run(DrainTestApp.class, all);
    }

    @RestController
    static class Endpoints {
        @GetMapping("/ping")
        String ping() {
            return "pong";
        }

        @GetMapping("/wait")
        String await() throws InterruptedException {
            HANDLER_ENTERED.countDown();
            RELEASE.await(10, TimeUnit.SECONDS);
            return "done";
        }
    }
}
