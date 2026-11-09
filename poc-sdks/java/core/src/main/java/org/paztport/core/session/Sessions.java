// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.Supplier;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * The session handshake as pure functions over messages, with no transport: building and checking the request and
 * reply, deriving the session id and deciding the status. A transport carries the JSON forms between the two
 * sides. Every check that reads untrusted input fails closed rather than throwing; the request's reader,
 * {@link SessionRequest#parse}, throws so a server can answer Invalid params.
 */
public final class Sessions {

    private static final String REPLY_DOMAIN = "paztport-session-reply\n";
    private static final String ATTESTED = "attested";
    private static final String UNSAFE = "unsafe";

    private Sessions() {
    }

    /** 16 fresh random bytes, base64url. */
    public static String newNonce() {
        return Base64Url.encode(Crypto.randomBytes(16));
    }

    /** A root's wire form: JSON null when there is none, its {@code notAfter} written inside it. */
    static JsonValue rootJson(SignedRoot root) {
        if (root == null) {
            return new JsonValue.Null();
        }
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("rootId", new JsonValue.Str(root.rootId()));
        o.put("root", new JsonValue.Str(root.root()));
        o.put("sig", new JsonValue.Str(root.sig()));
        o.put("notAfter", new JsonValue.Int(root.notAfter()));
        return new JsonValue.Obj(o);
    }

    /** A map of strings as a JSON object. */
    static JsonValue.Obj stringMapJson(Map<String, String> map) {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        map.forEach((name, value) -> o.put(name, new JsonValue.Str(value)));
        return new JsonValue.Obj(o);
    }

    /**
     * Whether a well-shaped request may open a session at all: the nonce is 16 bytes, a present client root's
     * signature is 64, and the keyring and policy key can be canonicalised. A server answers a request that fails
     * this with an error other than Method not found and leaves its current session in place.
     */
    public static boolean opensSession(SessionRequest req) {
        return length(req.nonce(), 16)
                && (req.clientRoot() == null || length(req.clientRoot().sig(), 64))
                && keysHash(req.clientPolicyKey(), req.clientKeyring()) != null;
    }

    private static boolean length(String b64, int n) {
        try {
            return Base64Url.decode(b64).length == n;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * The hash of the client's keys as one Paztport object, {@code {clientKeyring, clientPolicyKey}}, over its
     * canonical bytes; null when there are none, so there is no session id.
     */
    private static byte[] keysHash(String clientPolicyKey, Map<String, String> clientKeyring) {
        if (clientPolicyKey == null || clientKeyring == null
                || clientKeyring.values().stream().anyMatch(Objects::isNull)) {
            return null;
        }
        try {
            Map<String, JsonValue> o = new LinkedHashMap<>();
            o.put("clientPolicyKey", new JsonValue.Str(clientPolicyKey));
            o.put("clientKeyring", stringMapJson(clientKeyring));
            return Crypto.sha256(JsonWriter.wire(new JsonValue.Obj(o)));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Binds both roots, both nonces and the client's policy key and keyring. A null root signature means that root
     * is absent, and the flags byte says so. Returns null when any part is not exactly the length it must be (or
     * cannot be decoded or canonicalised), so there is no session id for it.
     */
    public static String deriveSessionId(String clientRootSig, String serverRootSig, String clientNonce,
            String serverNonce, String clientPolicyKey, Map<String, String> clientKeyring) {
        try {
            byte[] clientSig = clientRootSig == null ? new byte[0] : Base64Url.decode(clientRootSig);
            byte[] serverSig = serverRootSig == null ? new byte[0] : Base64Url.decode(serverRootSig);
            byte[] cn = Base64Url.decode(clientNonce);
            byte[] sn = Base64Url.decode(serverNonce);
            byte[] keys = keysHash(clientPolicyKey, clientKeyring);
            if (keys == null || clientSig.length != (clientRootSig == null ? 0 : 64)
                    || serverSig.length != (serverRootSig == null ? 0 : 64) || cn.length != 16 || sn.length != 16) {
                return null;
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(0x02);
            out.write((clientRootSig != null ? 1 : 0) | (serverRootSig != null ? 2 : 0));
            out.writeBytes(clientSig);
            out.writeBytes(serverSig);
            out.writeBytes(cn);
            out.writeBytes(sn);
            out.writeBytes(keys);
            return Base64Url.encode(Crypto.sha256(out.toByteArray()));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * {@code "attested"} only when both roots verify under their own side's policy key, the client's policy key is
     * pinned, the client's keyring is signed by it, and at {@code nowMs} the client's root and keyring and this
     * side's own root and keyring are all current; otherwise {@code "unsafe"}. With no pins every session is unsafe.
     * Never throws.
     *
     * <p>Each signature is checked over its object's window: a root over its own {@code notAfter}, the keyring over
     * {@code clientKeyringNotAfter} (see {@link SessionRequest#clientKeyringFile}). A window is trusted only because
     * the signature over it verified: a client window moved in transit fails its signature, and the root's own
     * signature is all that guards the root's window. What the client's policy owner vouched for by signing, and
     * until when, is in {@link SignedRoot} and {@link KeyringFile}.
     *
     * <p>{@code ownKeyring} is judged only by its window, never by its signature: the caller must already have
     * verified it under {@code ownPolicyKey} when it loaded it, and must pass that keyring and no other. (The root is
     * verified here.) A side whose own root or keyring
     * has expired therefore opens every new session unsafe and goes on serving unattested callers, rather than
     * stopping; sessions it attested earlier are verified against the client's material, which has its own window.
     */
    public static String status(SessionRequest req, SignedRoot ownRoot, KeyringFile ownKeyring, PublicKey ownPolicyKey,
            Set<String> pinnedClientKeys, long nowMs) {
        try {
            PublicKey clientKey = Crypto.decodePublicKey(Base64Url.decode(req.clientPolicyKey()));
            KeyringFile clientKeyring = req.clientKeyringFile();
            boolean ok = req.clientRoot() != null && ownRoot != null && ownKeyring != null
                    && pinnedClientKeys.contains(req.clientPolicyKey())
                    && req.clientRoot().verify(clientKey) && ownRoot.verify(ownPolicyKey)
                    && clientKeyring.verifies(req.clientPolicyKey())
                    && req.clientRoot().isCurrent(nowMs) && clientKeyring.isCurrent(nowMs)
                    && ownRoot.isCurrent(nowMs) && ownKeyring.isCurrent(nowMs);
            return ok ? ATTESTED : UNSAFE;
        } catch (IllegalArgumentException e) {
            return UNSAFE;
        }
    }

    /**
     * The bytes the reply signature covers: a domain prefix, then the JCS of the reply without its signature. For a
     * reply read from its bytes these are the bytes received less {@code sig}, since a reply reads only from its
     * canonical bytes and only with the members it has.
     */
    public static byte[] replySigningBytes(SessionReply reply) {
        Map<String, JsonValue> body = new LinkedHashMap<>(reply.tree().members());
        body.remove("sig");
        return withDomain(JsonWriter.wire(new JsonValue.Obj(body)));
    }

    private static byte[] withDomain(byte[] json) {
        byte[] prefix = REPLY_DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[prefix.length + json.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(json, 0, out, prefix.length, json.length);
        return out;
    }

    /**
     * Signs the reply with {@code signingKey}: the entry service's key when the reply carries
     * {@code serverKeyringSig} and {@code serverReplyCert}, the policy key when it carries neither. Any signature
     * already on the input is replaced. The two forms differ only in the signing key: the server must still say
     * {@code "attested"} only after its status checks ({@link #status}), since the signature vouches for whatever
     * the reply says. In the entry-key form {@code serverKeyringNotAfter} must be the window
     * {@code serverKeyringSig} was made over, the keyring's own, or the client's check of that signature fails.
     */
    public static SessionReply signReply(SessionReply unsigned, PrivateKey signingKey) {
        SessionReply bare = new SessionReply(unsigned.serverRoot(), unsigned.serverPolicyKey(),
                unsigned.serverKeyring(), unsigned.serverKeyringSig(), unsigned.serverKeyringNotAfter(),
                unsigned.serverReplyCert(), unsigned.nonce(), unsigned.sess(), unsigned.status(), unsigned.disabled(),
                null);
        String sig = Base64Url.encode(Crypto.sign(signingKey, replySigningBytes(bare)));
        return new SessionReply(bare.serverRoot(), bare.serverPolicyKey(), bare.serverKeyring(),
                bare.serverKeyringSig(), bare.serverKeyringNotAfter(), bare.serverReplyCert(), bare.nonce(),
                bare.sess(), bare.status(), bare.disabled(), sig);
    }

    /**
     * The client's live check of a reply against the request it sent, the server policy key it pinned, the server's
     * entry service from its own configuration (never from the reply) and the time {@code nowMs}, in the spec's
     * order: shape, pin, then signature, roots and session id, then status. Takes the reply's wire bytes as text,
     * not a parsed reply, so that reading it is the first outcome: text that does not read as a reply by
     * {@link SessionReply#parse}, null included, is {@code MALFORMED_REPLY}. The signature is then checked over the
     * reply read, which is the reply as received. Never throws.
     *
     * <p>The form is decided by which fields are present, never by which key verifies: trying the policy key and
     * then the entry key would let a reply stripped of its certificate, or carrying a certificate it should not,
     * pass under whichever key an attacker holds.
     *
     * <p>The server's material is judged at {@code nowMs}, in either form and whatever the status: its root, and in
     * the entry-key form its keyring, must be current, or the reply is {@code BAD_SIGNATURE} and the client takes its
     * replacement path. Each window is relied on only after the policy key's signature over it
     * has verified (the root's under the pin, the keyring's in {@link #replySigner}): the entry key signs the reply,
     * window included, so the reply's own signature cannot vouch for either. A degraded server, its own material
     * expired, therefore ends up unsafe at the client too. A recorded handshake is read offline instead, by
     * {@link #attestedOffline}.
     */
    public static ReplyCheck checkReply(String reply, SessionRequest req, String pinnedServerPolicyKey,
            String serverEntry, long nowMs) {
        return checkReply(readOrNull(() -> SessionReply.parse(reply)), req, pinnedServerPolicyKey, serverEntry,
                nowMs);
    }

    /**
     * {@link #checkReply(String, SessionRequest, String, String, long)} over a reply body as it arrived: its wire
     * bytes, read as they are.
     */
    public static ReplyCheck checkReply(byte[] reply, SessionRequest req, String pinnedServerPolicyKey,
            String serverEntry, long nowMs) {
        return checkReply(readOrNull(() -> SessionReply.parse(reply)), req, pinnedServerPolicyKey, serverEntry,
                nowMs);
    }

    /**
     * Whether a recorded handshake opened an attested session, judged at {@code at} (sessions-and-influence.md
     * &sect;Recorded handshakes): the reply, as recorded, is attested and passes the client's check against the
     * recorded pin and the server's entry service from the verifier's own configuration, both roots verify under
     * their sides' policy keys, and the client keyring's signature verifies. Never throws.
     *
     * <p>It is the live check with no clock: {@code at} is the time of the record being judged, a call's last stamp's
     * {@code ts}, which the client signed, never a time read from the handshake record, which anyone holding it can
     * edit. Each root and keyring, on either side, counts only for a record no later than its {@code notAfter}, as
     * the certificate does, and only after its own signature has verified. There is no client pin offline: the
     * server's signed {@code "attested"} reply, whose session id binds the client's policy key and keyring, is its
     * statement that it pinned them.
     */
    public static boolean attestedOffline(String reply, SessionRequest req, String pinnedServerPolicyKey,
            String serverEntry, long at) {
        if (req == null) {
            return false;
        }
        try {
            if (checkReply(readOrNull(() -> SessionReply.parse(reply)), req, pinnedServerPolicyKey, serverEntry, at)
                    != ReplyCheck.ATTESTED) {
                return false;
            }
            // An attested reply has passed with both roots present, and the server's verified under the pin.
            PublicKey clientKey = Crypto.decodePublicKey(Base64Url.decode(req.clientPolicyKey()));
            KeyringFile clientKeyring = req.clientKeyringFile();
            return clientKeyring.verifies(req.clientPolicyKey()) && req.clientRoot().verify(clientKey)
                    && req.clientRoot().isCurrent(at) && clientKeyring.isCurrent(at);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * The {@code policyNotAfter} a response recorded under a recorded handshake's reply is checked with
     * (verification.md &sect;Offline verification): the earlier of the server root's {@code notAfter} and, in the
     * entry-key form, the server keyring's, once the server's signatures over them verify, judged at no time: the reply
     * reads and verifies against the recorded pin and the server's entry service from the verifier's own configuration,
     * and its root verifies under the pin. Whether the session is attested, and the client's side of the handshake, do
     * not decide it. The reply's status and session id are checked against no request, so a limit is not an
     * attestation: {@link #attestedOffline} judges that. Empty for a reply that does not read, has no server root, or
     * whose signatures do not verify, and a response relying on it is then {@code POLICY_EXPIRED}, which the caller
     * reports itself, since a {@link org.paztport.core.verify.VerifierConfig} has no empty window. Never throws.
     */
    public static OptionalLong responseNotAfterOffline(String reply, String pinnedServerPolicyKey,
            String serverEntry) {
        try {
            SessionReply read = readOrNull(() -> SessionReply.parse(reply));
            if (read == null || read.serverRoot() == null
                    || !serverSignaturesVerify(read, pinnedServerPolicyKey, serverEntry)) {
                return OptionalLong.empty();
            }
            long root = read.serverRoot().notAfter();
            return OptionalLong.of(read.serverKeyringSig() == null ? root
                    : Math.min(root, read.serverKeyringNotAfter()));
        } catch (RuntimeException e) {
            return OptionalLong.empty();
        }
    }

    /** The reply read, or null when it does not read, which the shape check then refuses. */
    private static SessionReply readOrNull(Supplier<SessionReply> reader) {
        try {
            return reader.get();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The one reply check behind the live and the offline reading: the server's signatures
     * ({@link #serverSignaturesVerify}), then its root, and in the entry-key form its certificate and keyring, current
     * at {@code nowMs}, the client's clock live and the time of the record judged offline, then the roots and the
     * session id.
     */
    private static ReplyCheck checkReply(SessionReply reply, SessionRequest req, String pinnedServerPolicyKey,
            String serverEntry, long nowMs) {
        if (reply == null) {
            return ReplyCheck.MALFORMED_REPLY;
        }
        if (!reply.serverPolicyKey().equals(pinnedServerPolicyKey)) {
            return ReplyCheck.PIN_MISMATCH;
        }
        try {
            if (!serverSignaturesVerify(reply, pinnedServerPolicyKey, serverEntry) || !serverCurrent(reply, nowMs)) {
                return ReplyCheck.BAD_SIGNATURE;
            }
            SignedRoot root = reply.serverRoot();
            boolean attested = reply.status().equals(ATTESTED);
            if (attested && (root == null || req.clientRoot() == null)) {
                return ReplyCheck.BAD_SIGNATURE;
            }
            String expected = deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                    root == null ? null : root.sig(), req.nonce(), reply.nonce(), req.clientPolicyKey(),
                    req.clientKeyring());
            if (expected == null || !expected.equals(reply.sess())) {
                return ReplyCheck.BAD_SIGNATURE;
            }
            return attested ? ReplyCheck.ATTESTED : ReplyCheck.UNSAFE;
        } catch (RuntimeException e) {
            return ReplyCheck.BAD_SIGNATURE;
        }
    }

    /**
     * Whether the server's signatures on a reply verify, judged at no time: the reply names the pin as its policy
     * key, its {@code sig} verifies under the key its form names ({@link #replySigner}, which checks the keyring's and
     * the certificate's signatures in the entry-key form), and its root, when there is one, verifies under the pin
     * over its own {@code notAfter}. Only then does a window the reply holds count. Throws on a pin that is not a key.
     */
    private static boolean serverSignaturesVerify(SessionReply reply, String pinnedServerPolicyKey,
            String serverEntry) {
        if (!reply.serverPolicyKey().equals(pinnedServerPolicyKey)) {
            return false;
        }
        PublicKey pin = Crypto.decodePublicKey(Base64Url.decode(pinnedServerPolicyKey));
        PublicKey signer = replySigner(reply, pin, pinnedServerPolicyKey, serverEntry);
        return signer != null && Crypto.verify(signer, replySigningBytes(reply), Base64Url.decode(reply.sig()))
                && (reply.serverRoot() == null || reply.serverRoot().verify(pin));
    }

    /**
     * Whether the server's material in a reply whose signatures verified is current at {@code nowMs}: its root,
     * when there is one, and in the entry-key form its certificate and keyring.
     */
    private static boolean serverCurrent(SessionReply reply, long nowMs) {
        SignedRoot root = reply.serverRoot();
        ReplyCert cert = reply.serverReplyCert();
        return (root == null || root.isCurrent(nowMs))
                && (cert == null || (nowMs <= cert.notAfter() && serverKeyring(reply).isCurrent(nowMs)));
    }

    /** The server keyring an entry-key reply presents, with the window its signature was made over. */
    private static KeyringFile serverKeyring(SessionReply reply) {
        return new KeyringFile(reply.serverKeyring(), reply.serverPolicyKey(), reply.serverKeyringSig(),
                reply.serverKeyringNotAfter());
    }

    /**
     * The key the reply's {@code sig} must verify under, or null when no key may. The policy-key form (none of the
     * keyring-signature fields) names the pin; a {@code serverKeyringNotAfter} there is a keyring window with no
     * keyring signature beside it, which nothing vouches for, so no key, as for either form field without the other.
     * The entry-key form names the certificate's key, and only when both fields are present, the keyring and the
     * certificate verify under the pin, and the certificate is for {@code serverEntry} and names the key the keyring
     * holds for it: the keyring alone is the reply's own claim until the policy key's signature covers it. The
     * keyring's signature is checked over {@code serverKeyringNotAfter}, so a window moved in transit fails it before
     * the window is judged. A reply read holds a keyring signature only beside its window. Says nothing about time:
     * see {@link #serverCurrent}, which is what says the certificate's key is still current.
     */
    private static PublicKey replySigner(SessionReply reply, PublicKey pin, String pinText, String serverEntry) {
        boolean hasRingSig = reply.serverKeyringSig() != null;
        boolean hasCert = reply.serverReplyCert() != null;
        if (!hasRingSig && !hasCert) {
            return reply.serverKeyringNotAfter() != null ? null : pin;
        }
        if (!hasRingSig || !hasCert || serverEntry == null) {
            return null;
        }
        ReplyCert cert = reply.serverReplyCert();
        if (!serverKeyring(reply).verifies(pinText) || !cert.verifies(pinText) || !cert.svc().equals(serverEntry)
                || !cert.key().equals(reply.serverKeyring().get(serverEntry))) {
            return null;
        }
        return Crypto.decodePublicKey(Base64Url.decode(cert.key()));
    }
}
