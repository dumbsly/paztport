// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The extension influence (spec influence.md): a record of what content the context held when an action was decided.
 * It is a set of functions over what the verifier hands on, and the core reads none of it: the entries a hop adds to
 * its request's block and the labels a responder puts on its response's, the reading of the items handed on, the
 * every-stamp and owner-aware rules a guarded write is decided by, and the blinded influence an egress hands another
 * organisation. No source of the core outside this package names it.
 */
package org.paztport.core.influence;
