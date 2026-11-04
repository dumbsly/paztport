// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * What this starter records about verification, as Micrometer observations: the names and tag keys of each, for the
 * filters and the outbound interceptor that record them. Where the application has an {@code ObservationRegistry}
 * bean the starter records into it, and a meter registry behind it gives a timer and a count per observation; where
 * it has none, the starter records nothing.
 */
package org.paztport.spring.observation;
