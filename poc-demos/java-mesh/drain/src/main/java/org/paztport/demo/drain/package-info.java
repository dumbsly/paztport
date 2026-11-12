// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Lets a mesh demo service finish its connections before it stops. When the application context starts to close,
 * the service serves for a drain window with {@code Connection: close} on every response, so that each caller
 * retires its pooled connection to it, and only then does Spring Boot's graceful shutdown begin. Draining is
 * general HTTP hygiene, not part of Paztport, so it lives with the demo rather than in the starter.
 * {@code demo.drain-seconds} sets the window; the default is 5 seconds and 0 turns the drain off.
 */
package org.paztport.demo.drain;
