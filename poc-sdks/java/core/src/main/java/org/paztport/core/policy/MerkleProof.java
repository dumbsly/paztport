// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

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
    private static final Set<String> MEMBERS = Set.of("leafSalt", "siblings", "dirs", "rootId");

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
        if (!Text.isWellFormed(path)) {
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

    /** The wire form: the object's JCS text, {@code {dirs, leafSalt, rootId, siblings}}. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The header form: the base64url of {@link #toJson()}'s bytes. */
    public String encode() {
        return JsonWriter.token(tree());
    }

    JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("leafSalt", new JsonValue.Str(leafSalt));
        o.put("siblings", new JsonValue.Arr(siblings.stream().map(s -> (JsonValue) new JsonValue.Str(s)).toList()));
        o.put("dirs", new JsonValue.Str(dirs));
        o.put("rootId", new JsonValue.Str(rootId));
        return new JsonValue.Obj(o);
    }

    /** Reads the header form: a token of the proof's JCS bytes, by {@link #parse}'s checks. */
    public static MerkleProof decode(String header) {
        return fromTree(JsonReader.token(header));
    }

    /**
     * Reads a proof object off the wire from its bytes: the proof-object checks that need no root. {@code json} must
     * be the JCS text of an object with exactly the proof's four members, all strings but {@code siblings}, an
     * array of them; {@code dirs} only {@code L}/{@code R} with one per sibling, the salt exactly
     * {@link #SALT_BYTES} and each sibling exactly one hash. Anything else throws {@link IllegalArgumentException},
     * which a verifier turns into "not proven".
     */
    public static MerkleProof parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("proof must be an object");
        }
        return fromTree(JsonReader.wireText(json));
    }

    /** The proof's schema, the checks of wire.md's proof object that need no root, in the order they are made. */
    private static MerkleProof fromTree(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, Set.of());
        List<String> siblings = new ArrayList<>();
        for (JsonValue s : JsonFields.array(o, "siblings")) {
            if (!(s instanceof JsonValue.Str sibling) || decodedLength(sibling.value()) != HASH_BYTES) {
                throw new IllegalArgumentException("member siblings holds a value that is not 32 bytes of base64url");
            }
            siblings.add(sibling.value());
        }
        String salt = JsonFields.string(o, "leafSalt");
        if (decodedLength(salt) != SALT_BYTES) {
            throw new IllegalArgumentException("member leafSalt is not 16 bytes of base64url");
        }
        String dirs = JsonFields.string(o, "dirs");
        if (!dirs.matches("[LR]*") || dirs.length() != siblings.size()) {
            throw new IllegalArgumentException("member dirs is not one L or R per sibling");
        }
        return new MerkleProof(salt, siblings, dirs, JsonFields.string(o, "rootId"));
    }

    /** The length of what canonical base64url {@code text} decodes to, or -1 when it does not decode. */
    private static int decodedLength(String text) {
        try {
            return Base64Url.decode(text).length;
        } catch (IllegalArgumentException e) {
            return -1;
        }
    }
}
