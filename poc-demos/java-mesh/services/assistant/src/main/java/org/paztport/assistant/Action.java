// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.assistant;

/**
 * One call the assistant made, as it reports it: what it did, the status it got back, and the reply's
 * {@code reason}, else its {@code status}, else {@code ok}. The components are written in this order.
 */
public record Action(String action, int status, String result) {
}
