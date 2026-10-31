// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Supplier;
import org.paztport.core.internal.Json;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/**
 * A handshake read back from a record set, and what it gives the records that rely on it
 * (sessions-and-influence.md &sect;Recorded handshakes): whether it opened an attested session at a given time and
 * at all, and the limit on a response recorded in it. It is built from the request and reply
 * as recorded, the server policy key the client pinned, and the server's entry service from the verifier's own
 * configuration, never the record's.
 *
 * <p>Its limits are the certificate's {@code notAfter} (entry-key form) and the {@code notAfter} of each root and
 * keyring, both sides. It is attested at all when attested at the earliest of them. The windows are read before
 * the signatures over them are checked, but none counts unless the session is attested at it, which checks each
 * signature. A response is limited only by the server's root and, in the entry-key form, its keyring: the client's
 * windows and the certificate do not limit it. Nothing here throws on what the record holds.
 */
public final class RecordedSession {

    private final String reply;
    private final SessionRequest request;
    private final String pin;
    private final String serverEntry;
    private final String sess;
    private final boolean attested;
    private final long responseNotAfter;

    private RecordedSession(String requestJson, String replyJson, String pin, String serverEntry) {
        this.reply = replyJson;
        this.request = readOrNull(() -> SessionRequest.parse(requestJson));
        this.pin = pin;
        this.serverEntry = serverEntry;
        JsonNode tree = readOrNull(() -> Json.tree(replyJson));
        JsonNode id = tree == null ? null : tree.get("sess");
        this.sess = id != null && id.isTextual() ? id.textValue() : null;
        SignedRoot clientRoot = request == null ? null : request.clientRoot();
        Long serverRoot = window(tree == null ? null : tree.get("serverRoot"), "notAfter");
        Long serverKeyring = window(tree, "serverKeyringNotAfter");
        this.attested = attestedAt(earliest(0, certNotAfter(tree), clientRoot == null ? null : clientRoot.notAfter(),
                request == null ? null : request.clientKeyringNotAfter(), serverRoot, serverKeyring));
        boolean entryKeyForm = tree != null && tree.has("serverKeyringSig");
        this.responseNotAfter = earliest(JsonIntegers.MAX_SAFE, serverRoot, entryKeyForm ? serverKeyring : null);
    }

    /**
     * Reads a recorded handshake: {@code requestJson} and {@code replyJson} as recorded, {@code pin} the server
     * policy key the client pinned, and {@code serverEntry} the server's entry service from the verifier's own
     * configuration. A request or reply that does not read is a handshake that opened no attested session.
     */
    public static RecordedSession of(String requestJson, String replyJson, String pin, String serverEntry) {
        return new RecordedSession(requestJson, replyJson, pin, serverEntry);
    }

    /**
     * Whether it opened an attested session judged at {@code t}: a time the client signed, a call's last stamp's
     * {@code ts}, never one read from the handshake record. See {@link Sessions#attestedOffline}.
     */
    public boolean attestedAt(long t) {
        return Sessions.attestedOffline(reply, request, pin, serverEntry, t);
    }

    /**
     * The session id the reply names, which a call recorded in the session is checked against
     * ({@link OfflineConfig#sess}), so it is the id of the reply this session judged; null when the reply holds no
     * text there. A reader relies on it only for a session that is {@link #attested}.
     */
    public String sess() {
        return sess;
    }

    /** Attested at all: judged at the earliest of its limits, since each is an upper bound. */
    public boolean attested() {
        return attested;
    }

    /**
     * The {@code policyNotAfter} a response recorded in the session is checked with: the earlier of the server
     * root's window and, in the entry-key form, the server keyring's; 2^53 &minus; 1 when the reply holds neither
     * (it then opens no attested session). It is read
     * from the reply's windows whether or not the session is attested: a reader gives a response in a session that
     * is not attested no result.
     */
    public long responseNotAfter() {
        return responseNotAfter;
    }

    /** The earliest of {@code windows}, or {@code none} when none of them is set. */
    private static long earliest(long none, Long... windows) {
        return Arrays.stream(windows).filter(Objects::nonNull).mapToLong(Long::longValue).min().orElse(none);
    }

    /** The certificate's {@code notAfter} when the reply carries one that reads, else null. */
    private static Long certNotAfter(JsonNode reply) {
        JsonNode cert = reply == null ? null : reply.get("serverReplyCert");
        if (cert == null) {
            return null;
        }
        ReplyCert read = readOrNull(() -> ReplyCert.parse(Json.text(cert)));
        return read == null ? null : read.notAfter();
    }

    /** {@code o}'s own {@code field} when it is a valid {@code notAfter}, else null, a limit the record lacks. */
    private static Long window(JsonNode o, String field) {
        return o != null && o.isObject() && o.has(field) ? JsonIntegers.notAfter(o.get(field)) : null;
    }

    /** What {@code reader} reads, or null when the record does not read. */
    private static <T> T readOrNull(Supplier<T> reader) {
        try {
            return reader.get();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
