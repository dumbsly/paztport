// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The policy owner's signed material and the builder that makes it: the salted Merkle tree of allowed routes and
 * its signed root, the per-service proof bundles, the route string, and the keyring of every service's public key.
 * {@code OperationTable} is a service's operations, signed into the root as a route; {@code PolicyOwner} makes the
 * checks the owner's tools run before they sign; {@code OwnMaterial} checks the keyring and root a service starts with.
 */
package org.paztport.core.policy;
