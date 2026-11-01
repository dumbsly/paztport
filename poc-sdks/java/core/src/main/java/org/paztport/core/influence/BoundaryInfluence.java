// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.influence;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * The influence a sender's egress hands to another organisation. The full entries name internal services and
 * items in {@code src}, and their {@code h} values are plain hashes a partner could confirm by guessing; the
 * owner-aware rule needs neither, only each entry's class and owner. So the egress groups its entries by
 * (class, owner), with "no owner" a group of its own, and sends one entry per group: the class, the owner, a
 * {@code src} of {@code boundary:<egress>} and, as {@code h}, a salted commitment to the group's originals.
 * Every (class, owner) pair survives, so the partner's verdict under {@link InfluenceRule} is the one it would
 * reach on the full list.
 *
 * <p>The salt is derived from a 32-byte boundary key that never leaves the sender, the request's rid, the
 * partner's entry service and the group's class and owner. Per request, so the partner can't link the same
 * content across requests; derived, so the sender stores nothing per call and can always re-derive it. To show
 * what a sent entry stood for, the sender reveals that entry's salt and originals as an {@link Opening}; one
 * salt opens only its own entry, never another group's or another request's. An opening proves what the sender
 * committed to when it sent the entry, not that the originals were true.
 *
 * <p>What the signer must have verified: the egress reduces, commits to and signs only influence its request
 * context holds after the internal chain passed the live order at this hop. A request that did not pass there
 * has nothing reduced or sent for it.
 */
public final class BoundaryInfluence {

    /** The boundary key's length in bytes; any other length is refused rather than stretched or cut. */
    public static final int KEY_LENGTH = 32;

    /** A salt's length in bytes: the first half of the HMAC-SHA256 output. */
    public static final int SALT_LENGTH = 16;

    private static final Set<String> REQUIRED = Set.of("cls", "salt", "originals");
    private static final Set<String> OPTIONAL = Set.of("owner");

    private static final byte[] SALT_DOMAIN = "paztport-boundary-salt\n".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ENTRY_DOMAIN = "paztport-boundary-entry\n".getBytes(StandardCharsets.UTF_8);

    private BoundaryInfluence() {
    }

    /**
     * The boundary key: the trimmed text of the file, base64url of exactly {@link #KEY_LENGTH} bytes. Anything else
     * fails here, at startup, naming {@code name} (how the caller calls the setting that points at the file) but
     * never the file's content.
     *
     * @throws IllegalStateException when the text is not base64url of {@link #KEY_LENGTH} bytes
     * @throws UncheckedIOException when the file cannot be read
     */
    public static byte[] loadKey(Path file, String name) {
        String text;
        try {
            text = Files.readString(file).trim();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
        byte[] key;
        try {
            key = Base64Url.decode(text);
        } catch (IllegalArgumentException e) {
            key = null;
        }
        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalStateException(name + " must hold " + KEY_LENGTH + " bytes as base64url: " + file);
        }
        return key;
    }

    /**
     * The entries to send in place of {@code entries}: normalised, one per (class, owner) group of the normalised
     * input, as {@code {cls, src: "boundary:<egress>", h: commitment, owner?}} with no {@code cid}. No influence
     * gives no entries, whose commitment is {@code ""}. The caller passes only influence held after the internal
     * chain verified at this hop.
     */
    public static List<InfluenceEntry> reduce(List<InfluenceEntry> entries, byte[] key, String rid,
            String partnerEntry, String egress) {
        checkKey(key);
        if (entries == null || rid == null || partnerEntry == null || egress == null || egress.isEmpty()) {
            throw new IllegalArgumentException("boundary reduction needs entries, a rid, a partner entry and an egress");
        }
        Map<InfluenceFact, List<InfluenceEntry>> groups = new LinkedHashMap<>();
        for (InfluenceEntry e : Influence.normalise(entries)) {
            groups.computeIfAbsent(e.fact(), f -> new ArrayList<>()).add(e);
        }
        List<InfluenceEntry> out = new ArrayList<>();
        for (Map.Entry<InfluenceFact, List<InfluenceEntry>> g : groups.entrySet()) {
            InfluenceFact f = g.getKey();
            byte[] salt = salt(key, rid, partnerEntry, f.cls(), f.owner());
            out.add(new InfluenceEntry(f.cls(), "boundary:" + egress, commitment(salt, g.getValue()), null, f.owner()));
        }
        return Influence.normalise(out);
    }

    /**
     * The first 16 bytes of {@code HMAC-SHA256(key, utf8("paztport-boundary-salt\n") || JCS({cls, owner?, rcv,
     * rid}))}, with {@code owner} left out when null. The domain prefix keeps these bytes from ever matching
     * another signed or hashed form.
     */
    public static byte[] salt(byte[] key, String rid, String partnerEntry, InfluenceClass cls, String owner) {
        checkKey(key);
        if (rid == null || partnerEntry == null || cls == null) {
            throw new IllegalArgumentException("a boundary salt needs a rid, a partner entry and a class");
        }
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("cls", new JsonValue.Str(cls.wire()));
        if (owner != null) {
            o.put("owner", new JsonValue.Str(owner));
        }
        o.put("rcv", new JsonValue.Str(partnerEntry));
        o.put("rid", new JsonValue.Str(rid));
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(SALT_DOMAIN);
            mac.update(JsonWriter.wire(new JsonValue.Obj(o)));
            return Arrays.copyOf(mac.doFinal(), SALT_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /**
     * {@code b64url(SHA-256(utf8("paztport-boundary-entry\n") || salt || JCS(normalise(group))))}. The originals
     * are committed in full, every field, so an opening must reproduce them exactly; normalising first means
     * their order and repeats don't matter.
     */
    public static String commitment(byte[] salt, List<InfluenceEntry> group) {
        if (salt == null || salt.length != SALT_LENGTH || group == null) {
            throw new IllegalArgumentException("a boundary commitment needs a 16-byte salt and a group");
        }
        byte[] body = JsonWriter.wire(Influence.tree(Influence.normalise(group)));
        byte[] message = new byte[ENTRY_DOMAIN.length + SALT_LENGTH + body.length];
        System.arraycopy(ENTRY_DOMAIN, 0, message, 0, ENTRY_DOMAIN.length);
        System.arraycopy(salt, 0, message, ENTRY_DOMAIN.length, SALT_LENGTH);
        System.arraycopy(body, 0, message, ENTRY_DOMAIN.length + SALT_LENGTH, body.length);
        return Base64Url.encode(Crypto.sha256(message));
    }

    /**
     * True only when {@code opening} opens {@code sent}: there is at least one original, every original and the
     * opening itself have the sent entry's class and owner (both absent or equal), the salt decodes to 16 bytes,
     * and the commitment to the originals under it is the sent entry's {@code h}. Never throws: any malformed
     * input, a null anywhere included, is simply not an opening.
     */
    public static boolean opens(InfluenceEntry sent, Opening opening) {
        try {
            if (sent == null || opening == null || opening.cls() == null || opening.salt() == null
                    || opening.originals() == null || opening.originals().isEmpty()) {
                return false;
            }
            if (opening.cls() != sent.cls() || !Objects.equals(opening.owner(), sent.owner())) {
                return false;
            }
            for (InfluenceEntry o : opening.originals()) {
                if (o == null || o.cls() != sent.cls() || !Objects.equals(o.owner(), sent.owner())) {
                    return false;
                }
            }
            byte[] salt = Base64Url.decode(opening.salt());
            if (salt.length != SALT_LENGTH) {
                return false;
            }
            return commitment(salt, opening.originals()).equals(sent.h());
        } catch (RuntimeException e) {
            // Fail closed on anything the checks above did not foresee: an opening that can't be read opens nothing.
            return false;
        }
    }

    /**
     * What a sender reveals to open one sent entry: its class and owner, its salt (base64url) and the original
     * entries it stood for. Fields may be null here so that {@link #opens} can be asked about anything; only
     * {@link #parse} guarantees a well-formed one.
     */
    public record Opening(InfluenceClass cls, String owner, String salt, List<InfluenceEntry> originals) {

        public Opening {
            originals = originals == null ? null : Collections.unmodifiableList(new ArrayList<>(originals));
        }

        /** {@code {cls, owner?, salt, originals}}, with {@code owner} left out when null; needs a well-formed opening. */
        public String toJson() {
            if (cls == null || salt == null || originals == null || originals.contains(null)) {
                throw new IllegalArgumentException("only a well-formed opening has a JSON form");
            }
            Map<String, JsonValue> o = new LinkedHashMap<>();
            o.put("cls", new JsonValue.Str(cls.wire()));
            if (owner != null) {
                o.put("owner", new JsonValue.Str(owner));
            }
            o.put("salt", new JsonValue.Str(salt));
            o.put("originals", Influence.tree(originals));
            return JsonWriter.text(new JsonValue.Obj(o));
        }

        /**
         * Reads the wire form from its text, as the wire bytes of its UTF-8. See {@link #parse(byte[])}.
         *
         * @throws MalformedJsonException if {@code json} is not the JCS text of one value
         * @throws NotAnObjectException if the value is not an object
         * @throws IllegalArgumentException if the object is not a well-formed opening
         */
        public static Opening parse(String json) {
            if (json == null) {
                throw new IllegalArgumentException("an opening must be an object");
            }
            return fromValue(JsonReader.wireText(json));
        }

        /**
         * Reads the wire form from its bytes, which must be the JCS bytes of an object with exactly {@code cls},
         * {@code salt} and {@code originals}, and an optional {@code owner}: a known {@code cls}, a non-empty
         * {@code owner}, a {@code salt} that is base64url of 16 bytes and well-formed {@code originals}. Whether it
         * opens anything is {@link #opens}'s question, not this one's.
         *
         * @throws MalformedJsonException if {@code body} is not the JCS bytes of one value
         * @throws NotAnObjectException if the value is not an object
         * @throws IllegalArgumentException if the object is not a well-formed opening
         */
        public static Opening parse(byte[] body) {
            if (body == null) {
                throw new IllegalArgumentException("an opening must be an object");
            }
            return fromValue(JsonReader.wire(body));
        }

        /**
         * A value that reads, as wire bytes, but is not a JSON object, so no schema applies to it. It is an
         * {@link IllegalArgumentException} like any other refusal of the schema, and apart from the others so that a
         * caller that tells "not an object" from "an object that is not an opening" can.
         */
        public static final class NotAnObjectException extends IllegalArgumentException {

            NotAnObjectException() {
                super("an opening must be one JSON object");
            }
        }

        private static Opening fromValue(JsonValue value) {
            if (!(value instanceof JsonValue.Obj o)) {
                throw new NotAnObjectException();
            }
            JsonFields.exactly(o, REQUIRED, OPTIONAL);
            InfluenceClass cls = InfluenceClass.fromWire(JsonFields.string(o, "cls"));
            if (cls == null) {
                throw new IllegalArgumentException("malformed opening cls");
            }
            String owner = null;
            if (o.get("owner") != null) {
                owner = JsonFields.string(o, "owner");
                if (owner.isEmpty()) {
                    throw new IllegalArgumentException("malformed opening owner");
                }
            }
            String salt = JsonFields.string(o, "salt");
            if (Base64Url.decode(salt).length != SALT_LENGTH) {
                throw new IllegalArgumentException("malformed opening salt");
            }
            return new Opening(cls, owner, salt, Influence.fromTree(o.get("originals")));
        }
    }

    private static void checkKey(byte[] key) {
        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("the boundary key must be 32 bytes");
        }
    }
}
