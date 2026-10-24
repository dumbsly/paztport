// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A salted Merkle tree of allowed routes, built to a fixed depth so every proof
 * has the same length. Real leaves fill the low slots; the rest are opaque
 * random padding that hides the true route count.
 */
public final class MerkleTree {

    private final List<byte[][]> levels; // levels.get(0) = leaves, last = {root}
    private final Map<String, Integer> indexByPath;
    private final Map<String, String> saltByPath; // base64url salt
    private final String rootId;

    private MerkleTree(
            List<byte[][]> levels, Map<String, Integer> indexByPath, Map<String, String> saltByPath, String rootId) {
        this.levels = levels;
        this.indexByPath = indexByPath;
        this.saltByPath = saltByPath;
        this.rootId = rootId;
    }

    public static MerkleTree build(List<MerkleLeaf> leaves, int depth, String rootId) {
        int slots = 1 << depth;
        if (leaves.size() > slots) {
            throw new IllegalArgumentException(
                    "depth " + depth + " holds " + slots + " leaves, got " + leaves.size());
        }

        byte[][] level0 = new byte[slots][];
        Map<String, Integer> indexByPath = new LinkedHashMap<>();
        Map<String, String> saltByPath = new LinkedHashMap<>();
        for (int i = 0; i < leaves.size(); i++) {
            MerkleLeaf leaf = leaves.get(i);
            level0[i] = MerkleHash.leaf(leaf.salt(), leaf.path());
            indexByPath.put(leaf.path(), i);
            saltByPath.put(leaf.path(), Base64Url.encode(leaf.salt()));
        }
        for (int i = leaves.size(); i < slots; i++) {
            // Opaque padding, indistinguishable from a real salted leaf hash.
            level0[i] = Crypto.randomBytes(32);
        }

        List<byte[][]> levels = new ArrayList<>();
        levels.add(level0);
        byte[][] current = level0;
        while (current.length > 1) {
            byte[][] parent = new byte[current.length / 2][];
            for (int i = 0; i < parent.length; i++) {
                parent[i] = MerkleHash.node(current[2 * i], current[2 * i + 1]);
            }
            levels.add(parent);
            current = parent;
        }
        return new MerkleTree(levels, indexByPath, saltByPath, rootId);
    }

    public byte[] root() {
        byte[][] top = levels.get(levels.size() - 1);
        return top[0].clone();
    }

    public String rootId() {
        return rootId;
    }

    public MerkleProof proofFor(String path) {
        Integer idx = indexByPath.get(path);
        if (idx == null) {
            throw new IllegalArgumentException("no leaf for route " + path);
        }
        List<String> siblings = new ArrayList<>();
        StringBuilder dirs = new StringBuilder();
        int index = idx;
        for (int level = 0; level < levels.size() - 1; level++) {
            boolean working = index % 2 == 0; // this node is the left input
            int siblingIndex = working ? index + 1 : index - 1;
            siblings.add(Base64Url.encode(levels.get(level)[siblingIndex]));
            dirs.append(working ? 'L' : 'R');
            index /= 2;
        }
        return new MerkleProof(saltByPath.get(path), siblings, dirs.toString(), rootId);
    }
}
