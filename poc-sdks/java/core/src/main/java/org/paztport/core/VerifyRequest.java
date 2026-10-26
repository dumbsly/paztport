// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/**
 * Everything the verifier needs about the request it received, with no notion
 * of the transport it came over. The transport extension supplies:
 *
 * <ul>
 *   <li>the two header strings, either of which may be null;
 *   <li>{@code expectedBind}, the binding it computed from the request actually
 *       received, which the last stamp must match;
 *   <li>{@code receiver}, the name of the verifying service, which closes the route;
 *   <li>{@code peer}, the authenticated transport peer, or null. Not checked yet.
 * </ul>
 */
public record VerifyRequest(
        String chainHeader, String proofHeader, String expectedBind, String receiver, String peer) {
}
