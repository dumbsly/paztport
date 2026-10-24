// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

/** A real route committed to the tree: its secret salt and its path string. */
public record MerkleLeaf(byte[] salt, String path) {
}
