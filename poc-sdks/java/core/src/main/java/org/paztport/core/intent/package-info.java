// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The extension intent (spec intent.md): facts the origin states about a request, which a receiver compares with the
 * request it is sent. It is a set of functions over what the verifier hands on, and the core reads none of it: the
 * reading and building of the origin's item, the item check (P1) and the check that every fact a handler requires is
 * named (P2). Comparing a fact with the request is the handler's. No source of the core outside this package names
 * it.
 */
package org.paztport.core.intent;
