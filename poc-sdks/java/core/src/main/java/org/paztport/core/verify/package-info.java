// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The live verifier, what it pins and takes per request, and the typed result with its reason codes. Also the replay
 * guard and the transport-authenticated peer a result can name. The checks the live and the offline verifiers share
 * (3 to 6, 8, 9 and 11) are written once, in {@code org.paztport.core.internal.ChainChecks}.
 */
package org.paztport.core.verify;
