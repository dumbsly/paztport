// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

/**
 * A salted Merkle tree of allowed routes, built to a fixed depth so every proof
 * has the same length. Real leaves sit in the slots the caller names (the policy
 * builder picks them at random, so a proof's {@code dirs} reveals nothing about
 * the route's position in the policy or the route count); every other slot is
 * opaque random padding that hides the true route count.
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

    /** Places leaf i in slot i, for callers (tests, vectors) that need a fixed layout. */
    public static MerkleTree build(List<MerkleLeaf> leaves, int depth, String rootId) {
        int[] slots = new int[leaves.size()];
        for (int i = 0; i < slots.length; i++) {
            slots[i] = i;
        }
        return build(leaves, depth, rootId, slots);
    }

    /**
     * Places leaf i in {@code slots[i]}. Slots must be distinct and within
     * {@code [0, 2^depth)}, otherwise two routes would share a position or a proof
     * would not fit the tree.
     */
    public static MerkleTree build(List<MerkleLeaf> leaves, int depth, String rootId, int[] leafSlots) {
        int slots = 1 << depth;
        if (leaves.size() > slots) {
            throw new IllegalArgumentException(
                    "depth " + depth + " holds " + slots + " leaves, got " + leaves.size());
        }
        if (leafSlots.length != leaves.size()) {
            throw new IllegalArgumentException(
                    "need one slot per leaf: " + leaves.size() + " leaves, " + leafSlots.length + " slots");
        }
        boolean[] taken = new boolean[slots];
        for (int slot : leafSlots) {
            if (slot < 0 || slot >= slots || taken[slot]) {
                throw new IllegalArgumentException("slot " + slot + " is out of range or used twice");
            }
            taken[slot] = true;
        }

        byte[][] level0 = new byte[slots][];
        Map<String, Integer> indexByPath = new LinkedHashMap<>();
        Map<String, String> saltByPath = new LinkedHashMap<>();
        for (int i = 0; i < leaves.size(); i++) {
            MerkleLeaf leaf = leaves.get(i);
            level0[leafSlots[i]] = MerkleHash.leaf(leaf.salt(), leaf.path());
            indexByPath.put(leaf.path(), leafSlots[i]);
            saltByPath.put(leaf.path(), Base64Url.encode(leaf.salt()));
        }
        for (int i = 0; i < slots; i++) {
            // Opaque padding, indistinguishable from a real salted leaf hash.
            if (!taken[i]) {
                level0[i] = Crypto.randomBytes(32);
            }
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
