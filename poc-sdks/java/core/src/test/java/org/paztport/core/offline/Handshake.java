// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleLeaf;
import org.paztport.core.policy.MerkleTree;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/**
 * A recorded handshake built for a test: an attested reply in the entry-key form (signed by the entry's certified
 * key, carrying the server keyring's signature and the certificate) or the policy-key form, every window
 * {@link #FAR} unless given. The request and reply are held as JSON values, so a test can alter one as a record
 * could be, and are recorded as their wire bytes.
 */
final class Handshake {

    static final String ENTRY = "mcp-entry";
    static final long NOW = 1_767_225_600_000L;
    /** Far past every time judged here. */
    static final long FAR = 4_102_444_800_000L;
    static final long MAX_SAFE = (1L << 53) - 1;

    /** How to build one: each window's {@code notAfter}. */
    static final class Options {
        boolean policyKeyForm;
        String status = "attested";
        long cert = FAR;
        long clientRoot = FAR;
        long clientKeyring = FAR;
        long serverRoot = FAR;
        long serverKeyring = FAR;
    }

    final KeyPair clientPolicy = Crypto.generateEd25519KeyPair();
    final KeyPair serverPolicy = Crypto.generateEd25519KeyPair();
    final KeyPair entry = Crypto.generateEd25519KeyPair();
    final KeyPair session = Crypto.generateEd25519KeyPair();
    final KeyPair pi = Crypto.generateEd25519KeyPair();
    final MerkleTree clientTree =
            MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "session/pi/orders")), 4, "c1");
    final MerkleTree serverTree =
            MerkleTree.build(List.of(new MerkleLeaf(Crypto.randomBytes(16), "mcp-entry/tools")), 4, "s1");
    final JsonValue.Obj request;
    final JsonValue.Obj reply;
    /** The server policy key the client pinned. */
    final String pin = key(serverPolicy);

    private Handshake(Options o) {
        String clientKey = key(clientPolicy);
        SignedRoot clientRoot = SignedRoot.sign(clientTree.root(), "c1", o.clientRoot, clientPolicy.getPrivate());
        Map<String, String> clientServices = Map.of("session", key(session), "pi", key(pi));
        KeyringFile clientRing = KeyringFile.sign(clientServices, clientKey, o.clientKeyring,
                clientPolicy.getPrivate());
        SessionRequest req = SessionRequest.of(clientRoot, clientKey, clientRing, Sessions.newNonce());
        request = tree(req.toJson());

        SignedRoot serverRoot = SignedRoot.sign(serverTree.root(), "s1", o.serverRoot, serverPolicy.getPrivate());
        Map<String, String> serverServices = Map.of(ENTRY, key(entry), "tools", key(entry));
        KeyringFile serverRing = KeyringFile.sign(serverServices, pin, o.serverKeyring, serverPolicy.getPrivate());
        String nonce = Sessions.newNonce();
        String sess = Sessions.deriveSessionId(clientRoot.sig(), serverRoot.sig(), req.nonce(), nonce, clientKey,
                clientServices);
        boolean entryKey = !o.policyKeyForm;
        SessionReply unsigned = new SessionReply(serverRoot, pin, serverServices,
                entryKey ? serverRing.sig() : null, entryKey ? serverRing.notAfter() : null,
                entryKey ? ReplyCert.issue(pin, ENTRY, key(entry), o.cert, serverPolicy.getPrivate()) : null,
                nonce, sess, o.status, List.of(), null);
        reply = tree(Sessions.signReply(unsigned, entryKey ? entry.getPrivate() : serverPolicy.getPrivate())
                .toJson());
    }

    /** An attested handshake in the entry-key form, every window far off. */
    static Handshake attested() {
        return new Handshake(new Options());
    }

    /** A handshake built with the options {@code how} sets. */
    static Handshake with(Consumer<Options> how) {
        Options o = new Options();
        how.accept(o);
        return new Handshake(o);
    }

    static String key(KeyPair pair) {
        return Base64Url.encode(Crypto.encodePublicKey(pair.getPublic()));
    }

    static JsonValue.Obj tree(String json) {
        return (JsonValue.Obj) JsonReader.wireText(json);
    }

    /** A message's wire bytes as text, as a record holds it. */
    static String text(JsonValue.Obj message) {
        return JsonWriter.text(message);
    }

    /** {@code o} with its member {@code name} set to {@code value}, added or replaced. */
    static JsonValue.Obj with(JsonValue.Obj o, String name, JsonValue value) {
        Map<String, JsonValue> members = new LinkedHashMap<>(o.members());
        members.put(name, value);
        return new JsonValue.Obj(members);
    }

    /** {@code o} without its member {@code name}. */
    static JsonValue.Obj without(JsonValue.Obj o, String name) {
        Map<String, JsonValue> members = new LinkedHashMap<>(o.members());
        members.remove(name);
        return new JsonValue.Obj(members);
    }

    /** {@code o}'s member {@code name}, an object, with {@code edit} applied to it. */
    static JsonValue.Obj inMember(JsonValue.Obj o, String name, UnaryOperator<JsonValue.Obj> edit) {
        return with(o, name, edit.apply((JsonValue.Obj) o.get(name)));
    }

    String sess() {
        return ((JsonValue.Str) reply.get("sess")).value();
    }

    /** This handshake as recorded, read by the verifier configured for {@link #ENTRY}. */
    RecordedSession recorded() {
        return recorded(request, reply, pin, ENTRY);
    }

    static RecordedSession recorded(JsonValue.Obj request, JsonValue.Obj reply, String pin, String serverEntry) {
        return RecordedSession.of(text(request), text(reply), pin, serverEntry);
    }

    /** The reply with {@code edit} applied and signed again by the entry key, over every member it then has. */
    JsonValue.Obj resigned(UnaryOperator<JsonValue.Obj> edit) {
        JsonValue.Obj body = edit.apply(without(reply, "sig"));
        byte[] prefix = "paztport-session-reply\n".getBytes(StandardCharsets.UTF_8);
        byte[] json = JsonWriter.wire(body);
        byte[] signed = new byte[prefix.length + json.length];
        System.arraycopy(prefix, 0, signed, 0, prefix.length);
        System.arraycopy(json, 0, signed, prefix.length, json.length);
        return with(body, "sig", new JsonValue.Str(Base64Url.encode(Crypto.sign(entry.getPrivate(), signed))));
    }
}
