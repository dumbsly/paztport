// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.util.Arrays;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.function.Supplier;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.policy.SignedRoot;
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
 * signature. A response is limited only by the server's root and, in the entry-key form, its keyring, once the
 * server's signatures over them verify: the client's windows and the certificate do not limit it. Nothing here
 * throws on what the record holds.
 */
public final class RecordedSession {

    private final String reply;
    private final SessionRequest request;
    private final String pin;
    private final String serverEntry;
    private final String sess;
    private final boolean attested;
    private final OptionalLong responseNotAfter;

    private RecordedSession(String requestJson, String replyJson, String pin, String serverEntry) {
        this.reply = replyJson;
        this.request = readOrNull(() -> SessionRequest.parse(requestJson));
        this.pin = pin;
        this.serverEntry = serverEntry;
        JsonValue.Obj tree = readOrNull(() -> JsonReader.wireText(replyJson)) instanceof JsonValue.Obj o ? o : null;
        this.sess = tree != null && tree.get("sess") instanceof JsonValue.Str id ? id.value() : null;
        SignedRoot clientRoot = request == null ? null : request.clientRoot();
        Long serverRoot = window(member(tree, "serverRoot"), "notAfter");
        Long serverKeyring = window(tree, "serverKeyringNotAfter");
        Long cert = window(member(tree, "serverReplyCert"), "notAfter");
        this.attested = attestedAt(earliest(cert, clientRoot == null ? null : clientRoot.notAfter(),
                request == null ? null : request.clientKeyringNotAfter(), serverRoot, serverKeyring));
        this.responseNotAfter = Sessions.responseNotAfterOffline(replyJson, pin, serverEntry);
    }

    /**
     * Reads a recorded handshake: {@code requestJson} and {@code replyJson} as recorded, each its message's wire
     * bytes as text, {@code pin} the server policy key the client pinned, and {@code serverEntry} the server's entry
     * service from the verifier's own configuration. A request or reply that does not read is a handshake that
     * opened no attested session.
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
     * root's window and, in the entry-key form, the server keyring's, once the server's signatures over them verify,
     * judged at no time, whether or not the session is attested. Empty for a reply that does not read, has no server
     * root, or whose signatures do not verify against the pin and the configured entry: a response relying on it is
     * {@code POLICY_EXPIRED}. See {@link Sessions#responseNotAfterOffline}.
     */
    public OptionalLong responseNotAfter() {
        return responseNotAfter;
    }

    /** The earliest of {@code windows}, or 0 when none of them is set, as only for a request that does not read. */
    private static long earliest(Long... windows) {
        return Arrays.stream(windows).filter(Objects::nonNull).mapToLong(Long::longValue).min().orElse(0);
    }

    /** {@code o}'s own {@code field} when it is an integer, else null, a limit the record lacks. */
    private static Long window(JsonValue.Obj o, String field) {
        return o != null && o.get(field) instanceof JsonValue.Int i ? i.value() : null;
    }

    /** {@code o}'s member {@code name} when it is an object, else null. */
    private static JsonValue.Obj member(JsonValue.Obj o, String name) {
        return o != null && o.get(name) instanceof JsonValue.Obj m ? m : null;
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
