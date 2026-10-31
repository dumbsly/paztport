// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.offline;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Jcs;
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
 * {@link #FAR} unless given. The request and reply are held as trees, so a test can alter one as a record could be.
 */
final class Handshake {

    static final String ENTRY = "mcp-entry";
    static final long NOW = 1_767_225_600_000L;
    /** Far past every time judged here. */
    static final long FAR = 4_102_444_800_000L;
    static final long MAX_SAFE = (1L << 53) - 1;

    private static final ObjectMapper JSON = new ObjectMapper();

    /** How to build one: each window's {@code notAfter}, where null signs that root or keyring in the old form. */
    static final class Options {
        boolean policyKeyForm;
        boolean legacy;
        String status = "attested";
        long cert = FAR;
        Long clientRoot = FAR;
        Long clientKeyring = FAR;
        Long serverRoot = FAR;
        Long serverKeyring = FAR;
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
    final ObjectNode request;
    final ObjectNode reply;
    /** The server policy key the client pinned. */
    final String pin = key(serverPolicy);

    private Handshake(Options o) {
        String clientKey = key(clientPolicy);
        SignedRoot clientRoot = o.clientRoot == null
                ? SignedRoot.signOldForm(clientTree.root(), "c1", clientPolicy.getPrivate())
                : SignedRoot.sign(clientTree.root(), "c1", o.clientRoot, clientPolicy.getPrivate());
        Map<String, String> clientServices = Map.of("session", key(session), "pi", key(pi));
        KeyringFile clientRing = o.clientKeyring == null
                ? KeyringFile.signOldForm(clientServices, clientKey, clientPolicy.getPrivate())
                : KeyringFile.sign(clientServices, clientKey, o.clientKeyring, clientPolicy.getPrivate());
        SessionRequest req = SessionRequest.of(clientRoot, clientKey, clientRing, Sessions.newNonce());
        request = tree(req.toJson());
        if (o.legacy) {
            request.remove("clientKeyringSig");
            request.remove("clientKeyringNotAfter");
        }

        SignedRoot serverRoot = o.serverRoot == null
                ? SignedRoot.signOldForm(serverTree.root(), "s1", serverPolicy.getPrivate())
                : SignedRoot.sign(serverTree.root(), "s1", o.serverRoot, serverPolicy.getPrivate());
        Map<String, String> serverServices = Map.of(ENTRY, key(entry), "tools", key(entry));
        KeyringFile serverRing = o.serverKeyring == null
                ? KeyringFile.signOldForm(serverServices, pin, serverPolicy.getPrivate())
                : KeyringFile.sign(serverServices, pin, o.serverKeyring, serverPolicy.getPrivate());
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

    static ObjectNode tree(String json) {
        try {
            return (ObjectNode) JSON.readTree(json);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    String sess() {
        return reply.get("sess").textValue();
    }

    /** This handshake as recorded, read by the verifier configured for {@link #ENTRY}. */
    RecordedSession recorded() {
        return recorded(request, reply, pin, ENTRY);
    }

    static RecordedSession recorded(ObjectNode request, ObjectNode reply, String pin, String serverEntry) {
        return RecordedSession.of(request.toString(), reply.toString(), pin, serverEntry);
    }

    /** A copy of the request with {@code edit} applied. */
    ObjectNode request(Consumer<ObjectNode> edit) {
        ObjectNode copy = request.deepCopy();
        edit.accept(copy);
        return copy;
    }

    /** The reply with {@code edit} applied and signed again by the entry key, over every field it then has. */
    ObjectNode resigned(Consumer<ObjectNode> edit) {
        ObjectNode copy = reply.deepCopy();
        copy.remove("sig");
        edit.accept(copy);
        byte[] prefix = "paztport-session-reply\n".getBytes(StandardCharsets.UTF_8);
        byte[] body = Jcs.bytes(copy.toString());
        byte[] signed = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, signed, 0, prefix.length);
        System.arraycopy(body, 0, signed, prefix.length, body.length);
        copy.put("sig", Base64Url.encode(Crypto.sign(entry.getPrivate(), signed)));
        return copy;
    }
}
