// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Arrays;
import java.util.List;

/**
 * A membership proof for one route, carried in {@code X-Path-Proof}. Padded to a
 * fixed depth so its length leaks nothing about how many routes the tree holds.
 *
 * <p>{@code dirs} has one character per level: {@code 'L'} means the working
 * hash is the left input at that level (sibling on the right), {@code 'R'} the
 * reverse.
 */
public record MerkleProof(String leafSalt, List<String> siblings, String dirs, String rootId) {

    public MerkleProof {
        siblings = List.copyOf(siblings);
    }

    /** Recomputes the leaf from {@code path} and the carried salt, then walks to the root. */
    public boolean verify(String path, byte[] root) {
        if (siblings.size() != dirs.length()) {
            return false;
        }
        byte[] working = MerkleHash.leaf(Base64Url.decode(leafSalt), path);
        for (int i = 0; i < siblings.size(); i++) {
            byte[] sibling = Base64Url.decode(siblings.get(i));
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
