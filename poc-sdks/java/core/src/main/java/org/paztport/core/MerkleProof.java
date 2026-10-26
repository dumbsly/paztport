// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A membership proof for one route, carried in {@code X-Path-Proof}. Padded to a
 * fixed depth so its length leaks nothing about how many routes the tree holds.
 *
 * <p>{@code dirs} has one character per level: {@code 'L'} means the working
 * hash is the left input at that level (sibling on the right), {@code 'R'} the
 * reverse. Every field is required; a null field or sibling is rejected at
 * construction, so a decoded proof is never partly empty.
 */
public record MerkleProof(String leafSalt, List<String> siblings, String dirs, String rootId) {

    /** Every leaf salt is exactly this long; see {@link #verify}. */
    public static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;

    public MerkleProof {
        Objects.requireNonNull(leafSalt, "leafSalt");
        Objects.requireNonNull(dirs, "dirs");
        Objects.requireNonNull(rootId, "rootId");
        siblings = List.copyOf(siblings);
    }

    /**
     * Recomputes the leaf from {@code path} and the carried salt, then walks to the root.
     *
     * <p>The salt must be exactly {@link #SALT_BYTES} long. A leaf hashes
     * {@code salt || path} with no separator, so a longer salt could absorb the
     * start of the path and prove a different route string. Siblings must be
     * hash-sized and {@code dirs} only {@code L}/{@code R}. Fails closed: any
     * malformed field returns {@code false}, never throws.
     */
    public boolean verify(String path, byte[] root) {
        if (siblings.size() != dirs.length() || !dirs.matches("[LR]*")) {
            return false;
        }
        byte[] salt;
        try {
            salt = Base64Url.decode(leafSalt);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (salt.length != SALT_BYTES) {
            return false;
        }
        byte[] working = MerkleHash.leaf(salt, path);
        for (int i = 0; i < siblings.size(); i++) {
            byte[] sibling;
            try {
                sibling = Base64Url.decode(siblings.get(i));
            } catch (IllegalArgumentException e) {
                return false;
            }
            if (sibling.length != HASH_BYTES) {
                return false;
            }
            working = dirs.charAt(i) == 'L'
                    ? MerkleHash.node(working, sibling)
                    : MerkleHash.node(sibling, working);
        }
        return Arrays.equals(working, root);
    }

    public String encode() {
        return Base64Url.encode(Json.write(this));
    }

    public static MerkleProof decode(String header) {
        return Json.read(Base64Url.decode(header), MerkleProof.class);
    }
}
