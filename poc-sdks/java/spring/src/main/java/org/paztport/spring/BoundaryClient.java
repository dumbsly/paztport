// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import org.paztport.core.Base64Url;
import org.paztport.core.BoundaryInfluence;
import org.paztport.core.Crypto;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceClass;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.KeyringFile;
import org.paztport.core.ProofBundle;
import org.paztport.core.ReasonCode;
import org.paztport.core.ReplyCheck;
import org.paztport.core.SessionRequest;
import org.paztport.core.Sessions;
import org.paztport.core.SignedRoot;
import org.paztport.core.StampV3;
import org.paztport.core.StamperV3;
import org.paztport.http.HttpSessions;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The egress: the one way a request leaves this organisation for a partner. The partner must not see the internal
 * chain, which is the map the protocol keeps private, so this sends one boundary stamp instead, signed with this
 * service's key over the request it sends, in a session opened with the partner.
 *
 * <p>The boundary stamp vouches for the request that led to it, so it is signed only over a chain that passed the
 * full live order at this hop: {@link PaztportContext#verifiedChain()}, which only the inbound filter sets, and only
 * from the result that decides attestation. With no request scope, or with no verified chain (an origin, a hop
 * that is off, a chain that failed in audit, a hop with no verifier), {@link #post} throws before anything is sent,
 * the handshake included, so a request this service never accepted cannot even make it open a session.
 *
 * <p>The session is opened on the first call and shared by every call after it. The partner adds a session for
 * each handshake and replaces none, but it keeps only so many per peer and evicts the least recently used, so this
 * side opens one only when it needs one: concurrent first calls wait for the one handshake in flight rather than
 * each opening their own. The partner's reply is checked against its pinned policy key. A reply that is genuine
 * gives an attested or an unsafe session, as it says. Anything else (a reply this side cannot use, an HTTP error,
 * no answer) gives it no session it can stamp in, though the partner may have opened one, which it leaves to
 * expire there: the request is sent again with no root and a fresh nonce, which asks for an unsafe session, and
 * its {@code sess} is taken as unsafe whatever the reply says. That failure
 * may be passing (a partner restarting, a network blip), so a session from the replacement is kept for at most
 * {@link #FALLBACK_PERIOD}, and the first call after it tries the full handshake again; a genuine unsafe reply to
 * the full handshake is the partner's answer (it has not pinned this organisation), so that session is kept. A
 * handshake holds every first caller, so it is given a timeout, {@link #HANDSHAKE_TIMEOUT}; the calls themselves
 * have none.
 *
 * <p>The partner also forgets a session no call has used for its idle period, and a refused call is not retried
 * (below), so a session left idle at the partner would fail the next call. So this side drops a session, attested
 * or not, once no call has used it for its own idle period, which should be below the partner's, and the next call
 * opens a new one; a replacement's session goes at the end of its period or when idle, whichever comes first.
 *
 * <p>In an attested session a call carries the boundary stamp, the proof for {@code <this service>/<partner>}, and
 * the influence reduced by {@link BoundaryInfluence#reduce}: one entry per class and owner, its {@code src}
 * {@code boundary:<this service>} and its {@code h} a salted commitment to the originals of its group, so the
 * partner can apply the owner-aware rule without learning the internal sources or confirming a guess at the
 * content. What the signer has verified: the request's chain passed the live order at this hop (the guard), and
 * only influence the request context holds after that is reduced; every (class, owner) pair of it is kept, so
 * the partner's verdict is the one it would reach on the originals, and the boundary stamp commits to exactly the
 * list sent. The salts come from this service's boundary key, the rid, the partner and the group, not from the
 * service's name, so a boundary key belongs to one egress service and is never shared with another; its replicas
 * share it. In an unsafe session a call carries only the session id: the partner would not verify a stamp, and
 * the owners in the influence are private, so nothing is reduced.
 *
 * <p>The {@link BoundaryListener}, if there is one, is given the originals and the list sent before the request
 * goes, in an attested session only, so the shop can keep what it needs to open any entry it sent with
 * {@link #opening}. If it throws, the call stops there and nothing of the request is sent. Nothing about the
 * originals, their owners or the hashes is logged.
 *
 * <p>The partner does not attest what it answers, so every reply is recorded as one {@code local-untrusted} entry,
 * as any unattested response is, and this request's own response is labelled {@code local-untrusted}: a handler
 * that relays the partner's answer would otherwise have it attested with no labels, and its caller would take
 * the partner's words as clean. A {@code 403 SESSION_UNKNOWN} means the partner no longer knows the session (it
 * expired there, newer sessions of this peer's evicted it, or the partner restarted), so it is dropped and the next
 * call opens a new one; the refused call is not retried, since it may have changed something.
 *
 * <p>Each handshake logs one {@code PAZTPORT_TRACE session} line and each call one {@code PAZTPORT_TRACE boundary}
 * line. It owns its TLS client, built from the partner's bundle, and closes it with itself.
 */
public final class BoundaryClient implements AutoCloseable {

    /** The message every refusal by the guard carries. */
    static final String NO_VERIFIED_CHAIN = "no verified chain: nothing is signed at the boundary";

    /** Long enough for a handshake on a loaded partner, short enough that a silent one does not hold every caller. */
    static final Duration HANDSHAKE_TIMEOUT = Duration.ofSeconds(10);

    /**
     * How long a session from the replacement is kept: short enough that a passing failure does not leave the calls
     * unsafe for long, long enough that a partner that stays down is not asked for two handshakes on every call.
     */
    static final Duration FALLBACK_PERIOD = Duration.ofSeconds(30);

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    /** What a session id must look like before it goes in a header: base64url, as every derived id is. */
    private static final Pattern SESSION_ID = Pattern.compile("[A-Za-z0-9_-]{1,128}");

    /**
     * A session with the partner: its id, whether calls in it are stamped, whether it came from the replacement,
     * when it was opened and when a call last took it, both by the clock that ages sessions.
     */
    private record Session(String sess, boolean attested, boolean fallback, long openedAt, AtomicLong lastUsed) {

        Session(String sess, boolean attested, boolean fallback, long now) {
            this(sess, attested, fallback, now, new AtomicLong(now));
        }
    }

    /** The partner's answer: its status and body, and whether the call went out in an attested session. */
    public record Response(int status, byte[] body, boolean attested) {
    }

    private final StamperV3 stamper;
    private final ProofBundle bundle;
    private final SignedRoot ownRoot;
    private final KeyringFile ownKeyring;
    private final String ownPolicyKey;
    private final String partner;
    private final URI partnerUrl;
    private final String pinnedPartnerKey;
    private final byte[] blindingKey;
    private final BoundaryListener listener;
    private final PooledTlsClient tls;
    private final AtomicReference<Session> session = new AtomicReference<>();
    private final Object handshake = new Object();
    private final LongSupplier nanos;
    private final LongSupplier millis;
    private final long sessionIdleNanos;

    /**
     * @param stamper this service's stamper; the boundary stamp is signed with its key
     * @param bundle this service's proofs, which must hold {@code <this service>/<partner>}
     * @param ownRoot this organisation's signed root, sent in the handshake
     * @param ownKeyring this organisation's signed keyring, sent in the handshake
     * @param ownPolicyKey this organisation's policy public key, under which the root and keyring verify
     * @param partner the partner's entry service, the boundary stamp's receiver
     * @param partnerUrl the partner's base URL: a scheme and an authority, with no path
     * @param pinnedPartnerKey the partner's policy public key, pinned at onboarding
     * @param blindingKey this egress service's boundary key, exactly {@value BoundaryInfluence#KEY_LENGTH} bytes,
     *     which never leaves this organisation and is shared with no other service (its replicas excepted);
     *     copied
     * @param listener told the originals and the list sent before each attested call, or null for none
     * @param tls the client that presents this service's certificate to the partner; closed with this one
     * @param sessionIdleMs how long a session no call has used is kept, in milliseconds; positive, and below the
     *     partner's own idle period
     */
    public BoundaryClient(StamperV3 stamper, ProofBundle bundle, SignedRoot ownRoot, KeyringFile ownKeyring,
            String ownPolicyKey, String partner, URI partnerUrl, String pinnedPartnerKey, byte[] blindingKey,
            BoundaryListener listener, PooledTlsClient tls, long sessionIdleMs) {
        this(stamper, bundle, ownRoot, ownKeyring, ownPolicyKey, partner, partnerUrl, pinnedPartnerKey, blindingKey,
                listener, tls, System::nanoTime, System::currentTimeMillis, sessionIdleMs);
    }

    /**
     * As above, with the clocks: {@code nanos}, monotonic, ages sessions; {@code millis}, the time of day in
     * milliseconds since the epoch, is what a reply certificate's {@code notAfter} is compared with. Tests set both.
     */
    BoundaryClient(StamperV3 stamper, ProofBundle bundle, SignedRoot ownRoot, KeyringFile ownKeyring,
            String ownPolicyKey, String partner, URI partnerUrl, String pinnedPartnerKey, byte[] blindingKey,
            BoundaryListener listener, PooledTlsClient tls, LongSupplier nanos, LongSupplier millis,
            long sessionIdleMs) {
        this.stamper = Objects.requireNonNull(stamper, "stamper");
        this.bundle = Objects.requireNonNull(bundle, "bundle");
        this.ownRoot = Objects.requireNonNull(ownRoot, "ownRoot");
        this.ownKeyring = Objects.requireNonNull(ownKeyring, "ownKeyring");
        this.ownPolicyKey = Objects.requireNonNull(ownPolicyKey, "ownPolicyKey");
        this.partner = Objects.requireNonNull(partner, "partner");
        this.partnerUrl = Objects.requireNonNull(partnerUrl, "partnerUrl");
        this.pinnedPartnerKey = Objects.requireNonNull(pinnedPartnerKey, "pinnedPartnerKey");
        // Refused rather than stretched or cut: every salt is keyed by it.
        if (blindingKey == null || blindingKey.length != BoundaryInfluence.KEY_LENGTH) {
            throw new IllegalArgumentException("the boundary key must be " + BoundaryInfluence.KEY_LENGTH
                    + " bytes");
        }
        this.blindingKey = blindingKey.clone();
        this.listener = listener;
        this.tls = Objects.requireNonNull(tls, "tls");
        this.nanos = Objects.requireNonNull(nanos, "nanos");
        this.millis = Objects.requireNonNull(millis, "millis");
        if (partner.isEmpty()) {
            throw new IllegalArgumentException("the partner's entry service must be named");
        }
        if (stamper.svc() == null || stamper.svc().isEmpty()) {
            throw new IllegalArgumentException("the egress service must be named");
        }
        if (sessionIdleMs <= 0) {
            throw new IllegalArgumentException("the session idle period must be positive");
        }
        this.sessionIdleNanos = TimeUnit.MILLISECONDS.toNanos(sessionIdleMs);
        if (partnerUrl.getScheme() == null || partnerUrl.getRawAuthority() == null
                || !(partnerUrl.getRawPath() == null || partnerUrl.getRawPath().isEmpty()
                        || partnerUrl.getRawPath().equals("/"))
                || partnerUrl.getRawQuery() != null || partnerUrl.getRawFragment() != null) {
            throw new IllegalArgumentException("the partner URL must be a scheme and an authority only: "
                    + partnerUrl);
        }
        // A root or keyring the partner cannot verify could never open an attested session, so it fails here.
        if (!ownKeyring.verifies(ownPolicyKey)
                || !ownRoot.verify(Crypto.decodePublicKey(Base64Url.decode(ownPolicyKey)))) {
            throw new IllegalArgumentException("the root and keyring must both verify under the policy key");
        }
    }

    /**
     * POSTs {@code json} to {@code path} at the partner, in the session, opening it first if there is none. In an
     * attested session the influence is reduced, the listener told, and the boundary stamp signed over the reduced
     * list, in that order, before the request is sent.
     *
     * @param path the raw path, and {@code ?} and the raw query if any, exactly as it is to go on the wire
     * @throws IllegalStateException with nothing sent, when this request's chain did not verify at this hop or
     *     there is no request scope; or when no session could be opened
     * @throws IllegalArgumentException with nothing sent, when {@code path} would leave the partner's origin or
     *     would not be sent as given
     * @throws UncheckedIOException when the call itself fails
     * @throws RuntimeException whatever the listener throws, with the request not sent
     */
    public Response post(String path, byte[] json) {
        // The guard, before anything else: nothing is signed, or sent, on the strength of a chain not verified here.
        List<StampV3> verified = PaztportContext.isOpen() ? PaztportContext.verifiedChain() : null;
        if (verified == null || verified.isEmpty()) {
            throw new IllegalStateException(NO_VERIFIED_CHAIN);
        }
        List<InfluenceEntry> influence = PaztportContext.influence();
        Objects.requireNonNull(json, "json");
        URI target = target(path);
        String bind = RequestBinding.compute("POST", path, json);

        Session current = session();
        HttpRequest.Builder request = HttpRequest.newBuilder(target)
                .header("Content-Type", "application/json")
                .header(PaztportHeaders.SESSION, current.sess())
                .POST(HttpRequest.BodyPublishers.ofByteArray(json));
        List<InfluenceEntry> sent = List.of();
        String rid = verified.get(0).rid();
        if (current.attested()) {
            // Only influence held after the chain verified here, every (class, owner) pair of it kept.
            sent = List.copyOf(BoundaryInfluence.reduce(influence, blindingKey, rid, partner, stamper.svc()));
            if (listener != null) {
                // Before anything of the request goes: if the shop can't keep the originals, nothing is sent.
                listener.sent(rid, partner, List.copyOf(Influence.normalise(influence)), sent);
            }
            StamperV3.Stamped stamped = stamper.boundary(verified, current.sess(), partner, bind, sent, bundle);
            request.header(PaztportHeaders.CHAIN, HttpV3.encodeChain(stamped.chain()));
            if (stamped.proof() != null) {
                request.header(PaztportHeaders.PROOF, HttpV3.encodeProof(stamped.proof()));
            }
            String influenceHeader = HttpV3.encodeInfluence(sent);
            if (influenceHeader != null) {
                request.header(PaztportHeaders.INFLUENCE, influenceHeader);
            }
        }

        HttpResponse<byte[]> response;
        try {
            response = send(request.build());
        } catch (IOException e) {
            throw new UncheckedIOException("the call to " + partner + " failed", e);
        }
        int status = response.statusCode();
        byte[] body = response.body() == null ? new byte[0] : response.body();
        // The partner does not attest its answers, so what it says counts as untrusted content.
        PaztportContext.addInfluence(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:" + partner,
                HttpV3.resultHash(status, body), null, null));
        // And so does whatever this request answers, since a handler may relay it; the guard ensured a scope.
        PaztportContext.label(InfluenceClass.LOCAL_UNTRUSTED, null);
        if (status == 403 && ReasonCode.SESSION_UNKNOWN.name().equals(reason(body))) {
            // Only the session this call used: one a concurrent call has opened since is left alone.
            session.compareAndSet(current, null);
        }
        if (TRACE.isInfoEnabled()) {
            TRACE.info(boundaryLine(rid, partner, current.attested(), status, sent));
        }
        return new Response(status, body, current.attested());
    }

    /**
     * What to reveal to open the entry this client sent for the group ({@code cls}, {@code owner}) of request
     * {@code rid}: the originals of that group, normalised, and the salt derived again from this client's key and
     * partner. Pass the originals the {@link BoundaryListener} was given for that call; any of another group are
     * left out. The opening opens the sent entry only if the originals are those committed to.
     *
     * @throws IllegalArgumentException when no original is in the group, so there is nothing to open
     */
    public BoundaryInfluence.Opening opening(String rid, InfluenceClass cls, String owner,
            List<InfluenceEntry> originals) {
        Objects.requireNonNull(rid, "rid");
        Objects.requireNonNull(cls, "cls");
        Objects.requireNonNull(originals, "originals");
        List<InfluenceEntry> group = Influence.normalise(originals.stream()
                .filter(e -> e.cls() == cls && Objects.equals(e.owner(), owner)).toList());
        if (group.isEmpty()) {
            throw new IllegalArgumentException("no original is in that group");
        }
        byte[] salt = BoundaryInfluence.salt(blindingKey, rid, partner, cls, owner);
        return new BoundaryInfluence.Opening(cls, owner, Base64Url.encode(salt), group);
    }

    /**
     * The partner URL with {@code path} on it, refused unless the request line will carry exactly {@code path}, so
     * the binding covers what the partner receives, and the call cannot be pointed at another host.
     */
    private URI target(String path) {
        Objects.requireNonNull(path, "path");
        if (!path.startsWith("/") || path.startsWith("//")) {
            throw new IllegalArgumentException("the path must start with a single '/'");
        }
        URI uri = URI.create(partnerUrl.getScheme() + "://" + partnerUrl.getRawAuthority() + path);
        String sent = uri.getRawQuery() == null ? uri.getRawPath() : uri.getRawPath() + "?" + uri.getRawQuery();
        if (!Objects.equals(uri.getRawAuthority(), partnerUrl.getRawAuthority()) || !path.equals(sent)) {
            throw new IllegalArgumentException("the path would not be sent as given");
        }
        return uri;
    }

    /**
     * The current session, marked as used now, opened if there is none or it has expired; one handshake at a time,
     * and only when still needed.
     */
    private Session session() {
        Session s = session.get();
        if (s != null && !expired(s)) {
            return used(s);
        }
        synchronized (handshake) {
            s = session.get();
            if (s == null || expired(s)) {
                s = open();
                session.set(s);
            }
            return used(s);
        }
    }

    /** Starts the session's idle period again; never moved back by a call that read the clock earlier. */
    private Session used(Session s) {
        s.lastUsed().accumulateAndGet(nanos.getAsLong(), Math::max);
        return s;
    }

    /** No call has used it for the idle period, or it is a replacement's that has had its period. */
    private boolean expired(Session s) {
        long now = nanos.getAsLong();
        return now - s.lastUsed().get() >= sessionIdleNanos
                || s.fallback() && now - s.openedAt() >= FALLBACK_PERIOD.toNanos();
    }

    /**
     * Opens a session: the full request, then, if its reply cannot be used, the replacement with no root, whose
     * session is kept only for {@link #FALLBACK_PERIOD}. Logs the first reply's check ({@code -} when there was no
     * reply to check) and the status the session ends with.
     */
    private Session open() {
        SessionRequest full = SessionRequest.of(ownRoot, ownPolicyKey, ownKeyring, Sessions.newNonce());
        ReplyCheck check = null;
        try {
            JsonNode reply = handshake(full);
            check = Sessions.checkReply(reply, full, pinnedPartnerKey, partner, millis.getAsLong());
            if (check == ReplyCheck.ATTESTED || check == ReplyCheck.UNSAFE) {
                // The check derived the same id from both sides' inputs, so it is a real session id.
                Session s = new Session(reply.get("sess").textValue(), check == ReplyCheck.ATTESTED, false,
                        nanos.getAsLong());
                trace(check.name(), s);
                return s;
            }
        } catch (IOException e) {
            // No usable answer: whatever the partner opened is left to expire, and the replacement is asked for.
        }
        SessionRequest replacement = SessionRequest.of(null, ownPolicyKey, ownKeyring, Sessions.newNonce());
        JsonNode reply;
        try {
            reply = handshake(replacement);
        } catch (IOException e) {
            throw new IllegalStateException("no session could be opened with " + partner, e);
        }
        // Trusted either way, as unsafe: nothing is signed or carried in it, so only the id is taken from it.
        JsonNode sess = reply == null ? null : reply.get("sess");
        if (sess == null || !sess.isTextual() || !SESSION_ID.matcher(sess.textValue()).matches()) {
            throw new IllegalStateException("no session could be opened with " + partner);
        }
        Session s = new Session(sess.textValue(), false, true, nanos.getAsLong());
        trace(check == null ? "-" : check.name(), s);
        return s;
    }

    /**
     * Sends one handshake and reads its reply: the JSON, or null for a body that is not one JSON value. Any status
     * but 200, and no answer within the timeout, is an {@link IOException}.
     */
    private JsonNode handshake(SessionRequest req) throws IOException {
        byte[] body = JSON.writeValueAsBytes(req.toJson());
        HttpResponse<byte[]> response = send(HttpRequest.newBuilder(
                        URI.create(partnerUrl.getScheme() + "://" + partnerUrl.getRawAuthority() + HttpSessions.PATH))
                .header("Content-Type", "application/json")
                .timeout(HANDSHAKE_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build());
        if (response.statusCode() != 200) {
            throw new IOException("the session handshake was answered " + response.statusCode());
        }
        try {
            return JSON.readTree(response.body());
        } catch (IOException e) {
            return null;
        }
    }

    private HttpResponse<byte[]> send(HttpRequest request) throws IOException {
        try {
            return tls.httpClient().send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
    }

    /** The {@code reason} of a JSON refusal body, or null when there is none. */
    private static String reason(byte[] body) {
        try {
            JsonNode node = JSON.readTree(body);
            JsonNode reason = node == null ? null : node.get("reason");
            return reason != null && reason.isTextual() ? reason.textValue() : null;
        } catch (IOException e) {
            return null;
        }
    }

    private void trace(String check, Session s) {
        if (TRACE.isInfoEnabled()) {
            TRACE.info(String.format("PAZTPORT_TRACE session partner=%s check=%s status=%s", LogSafe.of(partner),
                    check, s.attested() ? "attested" : "unsafe"));
        }
    }

    /**
     * {@code PAZTPORT_TRACE boundary rid=… receiver=… session=attested|unsafe status=… classes=…|classes=-}. The
     * classes are those of the influence the call carried, so an unsafe session's are always {@code -}. The rid
     * comes from the request, so it goes through {@link LogSafe}, as do the receiver and the classes.
     */
    static String boundaryLine(String rid, String receiver, boolean attested, int status,
            List<InfluenceEntry> sent) {
        TreeSet<String> classes = new TreeSet<>();
        sent.forEach(e -> classes.add(e.cls().wire()));
        return String.format("PAZTPORT_TRACE boundary rid=%s receiver=%s session=%s status=%d classes=%s",
                rid.isEmpty() ? "-" : LogSafe.of(rid), LogSafe.of(receiver), attested ? "attested" : "unsafe",
                status, classes.isEmpty() ? "-" : LogSafe.of(String.join(",", classes)));
    }

    /** Closes the TLS client; calls after this fail. */
    @Override
    public void close() {
        tls.close();
    }
}
