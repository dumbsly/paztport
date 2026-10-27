// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
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

    /**
     * Reads a proof object off the wire: the proof-object checks that need no root. All four fields must be
     * strings (siblings an array of them), {@code dirs} only {@code L}/{@code R} with one per sibling, the salt
     * exactly {@link #SALT_BYTES} and each sibling exactly one hash. Anything else throws
     * {@link IllegalArgumentException}, which a verifier turns into "not proven". Unknown fields are ignored,
     * as in the TypeScript SDK.
     */
    public static MerkleProof fromJson(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("proof must be an object");
        }
        JsonNode salt = node.get("leafSalt");
        JsonNode dirs = node.get("dirs");
        JsonNode rootId = node.get("rootId");
        JsonNode siblings = node.get("siblings");
        if (salt == null || !salt.isTextual() || dirs == null || !dirs.isTextual() || rootId == null
                || !rootId.isTextual() || siblings == null || !siblings.isArray()) {
            throw new IllegalArgumentException("malformed proof");
        }
        List<String> out = new ArrayList<>();
        for (JsonNode s : siblings) {
            if (!s.isTextual() || Base64Url.decode(s.textValue()).length != HASH_BYTES) {
                throw new IllegalArgumentException("malformed proof sibling");
            }
            out.add(s.textValue());
        }
        if (!dirs.textValue().matches("[LR]*") || dirs.textValue().length() != out.size()
                || Base64Url.decode(salt.textValue()).length != SALT_BYTES) {
            throw new IllegalArgumentException("malformed proof");
        }
        return new MerkleProof(salt.textValue(), out, dirs.textValue(), rootId.textValue());
    }
}
