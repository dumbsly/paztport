// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

/**
 * Thresholds for the responder.
 *
 * @param threshold    rejections from one instance within {@code windowMs} that trigger a quarantine
 * @param windowMs     sliding window for counting per-instance rejections
 * @param maxPerSvc    quarantines allowed for one service within {@code svcWindowMs} before escalating
 * @param svcWindowMs  sliding window for the per-service circuit breaker
 */
public record QuarantineConfig(int threshold, long windowMs, int maxPerSvc, long svcWindowMs) {
}
