// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The session handshake as pure functions over messages, with no transport: building and checking the request and
 * reply, deriving the session id and deciding the status. A transport carries the JSON forms between the two
 * sides. Every check that reads untrusted input fails closed rather than throwing, except {@link #parseRequest},
 * which throws so a server can answer Invalid params.
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

    /**
     * A root's wire form: JSON null when there is none, and its {@code notAfter} written inside it only for the new
     * form, so an old-form root never carries one.
     */
    static JsonNode rootJson(SignedRoot root) {
        if (root == null) {
            return JsonNodeFactory.instance.nullNode();
        }
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.put("rootId", root.rootId());
        o.put("root", root.root());
        o.put("sig", root.sig());
        if (root.notAfter() != null) {
            o.put("notAfter", root.notAfter());
        }
        return o;
    }

    /**
     * Reads a request, throwing {@link IllegalArgumentException} on a shape error (the spec's Invalid params). A
     * missing {@code clientKeyringSig} is legacy (null); a present one that is not a string reads as the empty
     * string, which never verifies. The client root is read whole by {@link SignedRoot#parse}, its {@code notAfter}
     * included. A present {@code clientKeyringNotAfter}, or a client root {@code notAfter}, that is not an integer
     * in [0, 2^53 &minus; 1] (judged by value) is a shape error rather than an absent field: read as absent, a
     * damaged window would pass for the old form.
     */
    public static SessionRequest parseRequest(JsonNode params) {
        if (params == null || !params.isObject()) {
            throw new IllegalArgumentException("session request must be an object");
        }
        JsonNode r = params.get("clientRoot");
        SignedRoot root = null;
        if (r == null || !(r.isNull() || r.isObject())) {
            throw new IllegalArgumentException("clientRoot must be an object or null");
        }
        if (r.isObject()) {
            root = SignedRoot.parse(r);
        }
        JsonNode ring = params.get("clientKeyring");
        if (ring == null || !ring.isObject()) {
            throw new IllegalArgumentException("clientKeyring must be an object");
        }
        String sig = null;
        if (params.has("clientKeyringSig")) {
            sig = params.get("clientKeyringSig").isTextual() ? params.get("clientKeyringSig").textValue() : "";
        }
        Long ringNotAfter = null;
        if (params.has("clientKeyringNotAfter")) {
            ringNotAfter = JsonIntegers.notAfter(params.get("clientKeyringNotAfter"));
            if (ringNotAfter == null) {
                throw new IllegalArgumentException("clientKeyringNotAfter must be an integer in [0, 2^53 - 1]");
            }
        }
        return new SessionRequest(root, text(params.get("clientPolicyKey"), "clientPolicyKey"), stringMap(ring), sig,
                ringNotAfter, text(params.get("nonce"), "nonce"));
    }

    private static String text(JsonNode n, String what) {
        if (n == null || !n.isTextual()) {
            throw new IllegalArgumentException(what + " must be a string");
        }
        return n.textValue();
    }

    private static Map<String, String> stringMap(JsonNode o) {
        Map<String, String> out = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = o.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            out.put(e.getKey(), text(e.getValue(), "entry " + e.getKey()));
        }
        return out;
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

    private static byte[] keysHash(String clientPolicyKey, Map<String, String> clientKeyring) {
        try {
            ObjectNode o = JsonNodeFactory.instance.objectNode();
            o.put("clientPolicyKey", clientPolicyKey);
            ObjectNode ring = o.putObject("clientKeyring");
            clientKeyring.forEach(ring::put);
            return Crypto.sha256(Jcs.bytes(o));
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
     * side's own root and keyring are all in the new form and current; otherwise {@code "unsafe"}. With no pins every
     * session is unsafe, and a legacy request (no keyring signature) is unsafe live. Never throws.
     *
     * <p>Each signature is checked in its object's own form: a root over its own {@code notAfter} if it has one,
     * the keyring over {@code clientKeyringNotAfter} if the request has one (see
     * {@link SessionRequest#clientKeyringFile}). A window is trusted only because the signature over it verified: a
     * client window moved, added or dropped in transit fails its signature, and the root's own signature is all that
     * guards the root's window. What the client's policy owner vouched for by signing, and until when, is in
     * {@link SignedRoot} and {@link KeyringFile}; an old-form root or keyring carries no window, so its owner never
     * said how long it vouches for it, and it is never current.
     *
     * <p>{@code ownKeyring} is judged only by its window: its signature is the one this side checked against its pin
     * when it loaded the keyring, and the caller must pass that keyring and no other. A side whose own root or keyring
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
     * The bytes the reply signature covers: a domain prefix, then the JCS of the reply without its signature. A
     * certificate in the reply is covered as parsed, never as its raw text.
     */
    public static byte[] replySigningBytes(SessionReply reply) {
        return signingBytes(reply.toJson());
    }

    private static byte[] signingBytes(JsonNode replyJson) {
        ObjectNode body = replyJson.deepCopy();
        body.remove("sig");
        byte[] prefix = REPLY_DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] json = Jcs.bytes(body);
        byte[] out = new byte[prefix.length + json.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(json, 0, out, prefix.length, json.length);
        return out;
    }

    /**
     * The signing bytes of a received reply. The signature covers the reply's parsed value, as TypeScript's
     * {@code JSON.parse} then JCS does, never the text it arrived in. The numbers in a reply judged by value are the
     * certificate's {@code notAfter}, {@code serverKeyringNotAfter} and the root's {@code notAfter}, so each is
     * rewritten as the integer it parsed to: {@code 1798761600000.0} and {@code 1.7987616e12} then cover the same
     * bytes as the plain digits, which {@link Jcs} would otherwise refuse, and Java and TypeScript give the same
     * verdict. Everything else, extra certificate or root fields included, is canonicalised as received, so a
     * non-integral number anywhere else still fails. Assumes {@link #wellShaped}, which has already checked that
     * each is a safe integer in range.
     */
    private static byte[] receivedSigningBytes(JsonNode reply) {
        ObjectNode copy = reply.deepCopy();
        if (copy.get("serverReplyCert") instanceof ObjectNode cert) {
            cert.put("notAfter", ReplyCert.parse(cert).notAfter());
        }
        if (copy.has("serverKeyringNotAfter")) {
            copy.put("serverKeyringNotAfter", JsonIntegers.notAfter(copy.get("serverKeyringNotAfter")));
        }
        if (copy.get("serverRoot") instanceof ObjectNode root && root.has("notAfter")) {
            root.put("notAfter", JsonIntegers.notAfter(root.get("notAfter")));
        }
        return signingBytes(copy);
    }

    /**
     * Signs the reply with {@code signingKey}: the entry service's key when the reply carries
     * {@code serverKeyringSig} and {@code serverReplyCert}, the policy key when it carries neither. Any signature
     * already on the input is replaced. Only the key changed between the forms: the server must still say
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
     * order: shape, pin, then signature, roots and session id, then status. Takes the raw JSON so that the shape
     * check is the first outcome, and so the signature is checked over the reply as received, any extra field
     * included (with the three numbers judged by value, the certificate's {@code notAfter},
     * {@code serverKeyringNotAfter} and the root's {@code notAfter}, read as the integers they parse to; see
     * {@link #receivedSigningBytes}). Never throws.
     *
     * <p>The form is decided by which fields are present, never by which key verifies: trying the policy key and
     * then the entry key would let a reply stripped of its certificate, or carrying a certificate it should not,
     * pass under whichever key an attacker holds.
     *
     * <p>The server's material is judged at {@code nowMs}, in either form and whatever the status: its root, and in
     * the entry-key form its keyring, must be in the new form and current, or the reply is {@code BAD_SIGNATURE} and
     * the client takes its replacement path. Each window is relied on only after the policy key's signature over it
     * has verified (the root's under the pin, the keyring's in {@link #replySigner}): the entry key signs the reply,
     * window included, so the reply's own signature cannot vouch for either. A degraded server, its own material
     * expired, therefore ends up unsafe at the client too. There is no offline reading here: recorded handshakes are
     * judged by the TypeScript SDK, which accepts the old forms there.
     */
    public static ReplyCheck checkReply(JsonNode reply, SessionRequest req, String pinnedServerPolicyKey,
            String serverEntry, long nowMs) {
        if (!wellShaped(reply)) {
            return ReplyCheck.MALFORMED_REPLY;
        }
        String serverPolicyKey = reply.get("serverPolicyKey").textValue();
        if (!serverPolicyKey.equals(pinnedServerPolicyKey)) {
            return ReplyCheck.PIN_MISMATCH;
        }
        try {
            PublicKey pin = Crypto.decodePublicKey(Base64Url.decode(pinnedServerPolicyKey));
            PublicKey signer = replySigner(reply, pin, pinnedServerPolicyKey, serverEntry, nowMs);
            if (signer == null || !Crypto.verify(signer, receivedSigningBytes(reply),
                    Base64Url.decode(reply.get("sig").textValue()))) {
                return ReplyCheck.BAD_SIGNATURE;
            }
            JsonNode root = reply.get("serverRoot");
            boolean attested = reply.get("status").textValue().equals(ATTESTED);
            if (attested && (root.isNull() || req.clientRoot() == null)) {
                return ReplyCheck.BAD_SIGNATURE;
            }
            String expected = deriveSessionId(req.clientRoot() == null ? null : req.clientRoot().sig(),
                    root.isNull() ? null : root.get("sig").textValue(), req.nonce(), reply.get("nonce").textValue(),
                    req.clientPolicyKey(), req.clientKeyring());
            if (expected == null || !expected.equals(reply.get("sess").textValue())) {
                return ReplyCheck.BAD_SIGNATURE;
            }
            if (!root.isNull()) {
                SignedRoot serverRoot = SignedRoot.parse(root);
                if (!serverRoot.verify(pin) || !serverRoot.isCurrent(nowMs)) {
                    return ReplyCheck.BAD_SIGNATURE;
                }
            }
            return attested ? ReplyCheck.ATTESTED : ReplyCheck.UNSAFE;
        } catch (RuntimeException e) {
            return ReplyCheck.BAD_SIGNATURE;
        }
    }

    /**
     * The key the reply's {@code sig} must verify under, or null when no key may. The policy-key form (none of the
     * keyring-signature fields) names the pin; a {@code serverKeyringNotAfter} there is a keyring window with no
     * keyring signature beside it, which nothing vouches for, so no key, as for either form field without the other.
     * The entry-key form names the certificate's key, and only when both fields are present, the keyring and the
     * certificate verify under the pin, the certificate is for {@code serverEntry} and names the key the keyring
     * holds for it, {@code nowMs} is no later than its {@code notAfter}, and the keyring is new form and current at
     * {@code nowMs}: the keyring alone is the reply's own claim until the policy key's signature covers it, and the
     * certificate is what says the key is still current. The keyring's signature is checked in its own form, over
     * {@code serverKeyringNotAfter} when the reply has one, so a window moved or dropped in transit fails it before
     * the window is judged. Assumes {@link #wellShaped}.
     */
    private static PublicKey replySigner(JsonNode reply, PublicKey pin, String pinText, String serverEntry,
            long nowMs) {
        boolean hasRingSig = reply.has("serverKeyringSig");
        boolean hasCert = reply.has("serverReplyCert");
        if (!hasRingSig && !hasCert) {
            return reply.has("serverKeyringNotAfter") ? null : pin;
        }
        if (!hasRingSig || !hasCert || serverEntry == null) {
            return null;
        }
        Map<String, String> services = stringMap(reply.get("serverKeyring"));
        KeyringFile ring = new KeyringFile(services, reply.get("serverPolicyKey").textValue(),
                reply.get("serverKeyringSig").textValue(),
                reply.has("serverKeyringNotAfter") ? JsonIntegers.notAfter(reply.get("serverKeyringNotAfter")) : null);
        ReplyCert cert = ReplyCert.parse(reply.get("serverReplyCert"));
        if (!ring.verifies(pinText) || !cert.verifies(pinText) || !cert.svc().equals(serverEntry)
                || !cert.key().equals(services.get(serverEntry)) || nowMs > cert.notAfter()
                || !ring.isCurrent(nowMs)) {
            return null;
        }
        return Crypto.decodePublicKey(Base64Url.decode(cert.key()));
    }

    /**
     * The reply's shape. A present {@code serverKeyringNotAfter}, or a root {@code notAfter}, that is not an
     * integer in [0, 2^53 &minus; 1] (judged by value) makes the reply malformed rather than old form.
     */
    private static boolean wellShaped(JsonNode r) {
        if (r == null || !r.isObject()) {
            return false;
        }
        JsonNode root = r.get("serverRoot");
        boolean rootOk = root != null && (root.isNull() || parsesAsSignedRoot(root));
        JsonNode status = r.get("status");
        JsonNode ring = r.get("serverKeyring");
        JsonNode disabled = r.get("disabled");
        return rootOk && isText(r.get("serverPolicyKey")) && ring != null && ring.isObject() && allText(ring)
                && isText(r.get("nonce")) && isText(r.get("sess")) && status != null && status.isTextual()
                && (status.textValue().equals(ATTESTED) || status.textValue().equals(UNSAFE))
                && disabled != null && disabled.isArray() && allText(disabled) && isText(r.get("sig"))
                && (!r.has("serverKeyringSig") || r.get("serverKeyringSig").isTextual())
                && (!r.has("serverKeyringNotAfter") || JsonIntegers.notAfter(r.get("serverKeyringNotAfter")) != null)
                && (!r.has("serverReplyCert") || parsesAsReplyCert(r.get("serverReplyCert")));
    }

    private static boolean parsesAsSignedRoot(JsonNode n) {
        try {
            SignedRoot.parse(n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean parsesAsReplyCert(JsonNode n) {
        try {
            ReplyCert.parse(n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean isText(JsonNode n) {
        return n != null && n.isTextual();
    }

    private static boolean allText(JsonNode container) {
        List<JsonNode> items = new ArrayList<>();
        container.forEach(items::add);
        return items.stream().allMatch(JsonNode::isTextual);
    }
}
