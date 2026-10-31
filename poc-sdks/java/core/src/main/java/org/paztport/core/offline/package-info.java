// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Verifies records read back from a record set, such as a client's evidence file: a chain, with the live checks in
 * the live order and the recorded times in place of a clock; a recorded handshake, judged at the times the client
 * signed; and the record set's own state, the calls' spent nonce keys and the limit each session sets on them.
 */
package org.paztport.core.offline;
