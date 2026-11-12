// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import java.time.Duration;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.boot.web.server.context.WebServerGracefulShutdownLifecycle;
import org.springframework.context.ApplicationContext;
import org.springframework.context.SmartLifecycle;

/**
 * Holds the context's close for the drain window. Its phase is one above Spring Boot's web-server graceful shutdown,
 * and lifecycle beans stop from the highest phase down, so this stops first: the service keeps serving, marking
 * every response {@code Connection: close}, and then graceful shutdown stops new requests and waits for those in
 * progress. Nothing drains in a context without a running web server, which has no connections to retire.
 */
public final class DrainLifecycle implements SmartLifecycle {

    /** One above the graceful shutdown's phase, so that this stops before it. */
    public static final int PHASE = WebServerGracefulShutdownLifecycle.SMART_LIFECYCLE_PHASE + 1;

    private final DrainState state;
    private final Duration window;
    private final ApplicationContext context;
    private volatile boolean running;

    public DrainLifecycle(DrainState state, Duration window, ApplicationContext context) {
        this.state = state;
        this.window = window;
        this.context = context;
    }

    @Override
    public void start() {
        running = true;
    }

    @Override
    public void stop() {
        running = false;
        if (window.isZero() || !hasRunningServer()) {
            return;
        }
        state.begin();
        try {
            Thread.sleep(window);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return PHASE;
    }

    private boolean hasRunningServer() {
        return context instanceof WebServerApplicationContext server && server.getWebServer() != null;
    }
}
