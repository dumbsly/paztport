// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCheck;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.ReasonCode;
import org.paztport.http.internal.LogSafe;
import org.paztport.http.internal.WholeExchange;
import org.paztport.http.wire.HttpV3;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The egress: the one way a request leaves this organisation for a partner. The partner must not see the internal
 * chain, which is the map the protocol keeps private, so this sends one boundary stamp instead, signed with this
 * service's key over the request it sends, in a session opened with the partner.
 *
 * <p>The boundary stamp vouches for the request that led to it, so it is signed only over a chain that passed the
 * full live order at this hop: {@link RequestContext#verifiedChain()}, which only a receiver's result sets, and only
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
 * the full handshake is the partner's answer (it has not pinned this organisation), so that session is kept.
 *
 * <p>A handshake holds every first caller, so it has its own timeout, {@link #HANDSHAKE_TIMEOUT}; each call has
 * the read timeout this is built with ({@link #DEFAULT_READ_TIMEOUT} unless set), so that a partner that takes a
 * call and never answers cannot hold the calling thread for ever. Each bounds the whole
 * exchange, the body included, on every JDK ({@link WholeExchange#send}), since the partner is another
 * organisation: one that sends its headers and then stops is cut off too. A handshake past its timeout counts as no
 * answer (above). A call past its timeout is cancelled and {@link #post} throws, as for any call that fails; the
 * session is kept, since the partner may have taken the call in it, and the call is not retried.
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
 * call opens a new one; the refused call is not retried, since it may have changed something. A
 * {@code 403 POLICY_EXPIRED} means this side's root or keyring, as the handshake presented them, has passed its
 * {@code notAfter}, and the partner refuses every call in that session from then on, so it is dropped too: the next
 * call's handshake gives an unsafe session, which is what this side then has until its files are renewed and it is
 * restarted. Its own lapse is logged once, the first time a handshake or such a refusal finds it.
 *
 * <p>Each handshake logs one {@code PAZTPORT_TRACE session} line and each call one {@code PAZTPORT_TRACE boundary}
 * line. It owns the JDK client it is built with, which presents this service's certificate to the partner and
 * trusts the partner's CA, and shuts it down when it is closed.
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

    /**
     * Each call's read timeout unless one is given: far beyond any answer a working partner gives, so it ends only
     * calls that would otherwise wait for ever.
     */
    public static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);

    private static final Logger TRACE = LoggerFactory.getLogger("PAZTPORT_TRACE");
    private static final Logger LOG = LoggerFactory.getLogger(BoundaryClient.class);
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
    private final HttpClient http;
    private final Duration readTimeout;
    private final AtomicReference<Session> session = new AtomicReference<>();
    private final AtomicBoolean ownLapseLogged = new AtomicBoolean();
    private final Object handshake = new Object();
    private final LongSupplier nanos;
    private final LongSupplier millis;
    private final long sessionIdleNanos;
    private final Duration handshakeTimeout;

    /** A client with the settings {@link Builder#build} has checked. */
    private BoundaryClient(Builder b) {
        this.stamper = b.stamper;
        this.bundle = b.bundle;
        this.ownRoot = b.ownRoot;
        this.ownKeyring = b.ownKeyring;
        this.ownPolicyKey = b.ownPolicyKey;
        this.partner = b.partner;
        this.partnerUrl = b.partnerUrl;
        this.pinnedPartnerKey = b.pinnedPartnerKey;
        this.blindingKey = b.blindingKey.clone();
        this.listener = b.listener;
        this.http = b.http;
        this.readTimeout = b.readTimeout;
        this.nanos = b.nanos;
        this.millis = b.millis;
        this.sessionIdleNanos = TimeUnit.MILLISECONDS.toNanos(b.sessionIdleMs);
        this.handshakeTimeout = b.handshakeTimeout;
    }

    /** A client to build; see {@link Builder}. */
    public static Builder builder() {
        return new Builder();
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
     * @throws UncheckedIOException when the call itself fails, or has no whole answer within the read timeout (its
     *     cause then an {@link java.net.http.HttpTimeoutException})
     * @throws RuntimeException whatever the listener throws, with the request not sent
     */
    public Response post(String path, byte[] json) {
        // The guard, before anything else: nothing is signed, or sent, on the strength of a chain not verified here.
        List<StampV3> verified = RequestContext.isOpen() ? RequestContext.verifiedChain() : null;
        if (verified == null || verified.isEmpty()) {
            throw new IllegalStateException(NO_VERIFIED_CHAIN);
        }
        List<InfluenceEntry> influence = RequestContext.influence();
        Objects.requireNonNull(json, "json");
        URI target = target(path);
        String bind = RequestBinding.compute("POST", path, json);

        Session current = session();
        HttpRequest.Builder request = HttpRequest.newBuilder(target)
                .header("Content-Type", "application/json")
                .header(PaztportHeaders.SESSION, current.sess())
                .timeout(readTimeout)
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
        RequestContext.addInfluence(new InfluenceEntry(InfluenceClass.LOCAL_UNTRUSTED, "http:" + partner,
                HttpV3.resultHash(status, body), null, null));
        // And so does whatever this request answers, since a handler may relay it; the guard ensured a scope.
        RequestContext.label(InfluenceClass.LOCAL_UNTRUSTED, null);
        String reason = status == 403 ? reason(body) : null;
        if (ReasonCode.SESSION_UNKNOWN.name().equals(reason) || ReasonCode.POLICY_EXPIRED.name().equals(reason)) {
            // Only the session this call used: one a concurrent call has opened since is left alone.
            session.compareAndSet(current, null);
        }
        if (ReasonCode.POLICY_EXPIRED.name().equals(reason)) {
            logOwnLapse();
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
        logOwnLapse();
        SessionRequest full = SessionRequest.of(ownRoot, ownPolicyKey, ownKeyring, Sessions.newNonce());
        ReplyCheck check = null;
        try {
            byte[] reply = handshake(full);
            check = Sessions.checkReply(reply, full, pinnedPartnerKey, partner, millis.getAsLong());
            if (check == ReplyCheck.ATTESTED || check == ReplyCheck.UNSAFE) {
                // The check derived the same id from both sides' inputs, so it is a real session id.
                Session s = new Session(read(reply).get("sess").textValue(), check == ReplyCheck.ATTESTED, false,
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
            reply = read(handshake(replacement));
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
     * Sends one handshake and returns its reply's body, which the reply check reads as it arrived. Any status but
     * 200, and no whole answer within the timeout, is an {@link IOException}.
     */
    private byte[] handshake(SessionRequest req) throws IOException {
        // Written as bytes by the SDK's JSON library, as the handshake body always has been: the text is read back
        // and written out as bytes, which writes a character outside the Basic Multilingual Plane as an escaped
        // surrogate pair rather than as its four UTF-8 bytes, so the body keeps exactly the bytes it always had.
        byte[] body = JSON.writeValueAsBytes(JSON.readTree(req.toJson()));
        HttpResponse<byte[]> response = send(HttpRequest.newBuilder(
                        URI.create(partnerUrl.getScheme() + "://" + partnerUrl.getRawAuthority() + HttpSessions.PATH))
                .header("Content-Type", "application/json")
                .timeout(handshakeTimeout)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build());
        if (response.statusCode() != 200) {
            throw new IOException("the session handshake was answered " + response.statusCode());
        }
        return response.body();
    }

    /** A reply body's JSON, or null for a body that is not one JSON value. */
    private static JsonNode read(byte[] body) {
        try {
            return JSON.readTree(body);
        } catch (IOException e) {
            return null;
        }
    }

    /** Sends {@code request}, which has its timeout, and reads its whole answer within it. */
    private HttpResponse<byte[]> send(HttpRequest request) throws IOException {
        return WholeExchange.send(http, request, HttpResponse.BodyHandlers.ofByteArray());
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

    /**
     * Says, once, that this egress's own root or keyring has expired by its clock, which is why the partner refuses
     * its attested calls and judges its handshakes unsafe: the operator would otherwise see only refusals and unsafe
     * sessions and no cause. Checked by every handshake and every {@code POLICY_EXPIRED} refusal, and silent after the
     * first line; a refusal while both are still current by this clock (the two clocks disagree) logs nothing.
     */
    private void logOwnLapse() {
        long now = millis.getAsLong();
        boolean rootLapsed = !ownRoot.isCurrent(now);
        boolean keyringLapsed = !ownKeyring.isCurrent(now);
        if ((rootLapsed || keyringLapsed) && ownLapseLogged.compareAndSet(false, true)) {
            LOG.warn("this egress's own {} has expired, so the partner refuses its calls and opens only unsafe "
                    + "sessions until it is re-signed with the policy tool and the service restarted",
                    rootLapsed && keyringLapsed ? "root and keyring" : rootLapsed ? "root" : "keyring");
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

    /** The read timeout each call has. */
    Duration readTimeout() {
        return readTimeout;
    }

    /**
     * Shuts the JDK client down, without waiting for the calls in flight, so a call with no answer cannot hold up
     * the application's shutdown; calls after this fail.
     */
    @Override
    public void close() {
        http.shutdown();
    }

    /** Why {@link Builder#build} refused a setting, for a caller that words the refusal in its own terms. */
    public enum Fault {
        /** The partner URL is not {@code https}. */
        NOT_HTTPS,
        /** The boundary key is not {@value BoundaryInfluence#KEY_LENGTH} bytes. */
        KEY_LENGTH,
        /** The read timeout is not positive. */
        READ_TIMEOUT,
        /** The partner's entry service is empty. */
        UNNAMED_PARTNER,
        /** The stamper names no service. */
        UNNAMED_EGRESS,
        /** The session idle period is not positive. */
        IDLE_PERIOD,
        /** The partner URL has a path, a query or a fragment, or no authority. */
        NOT_AN_ORIGIN,
        /** This side's root or keyring does not verify under its policy key. */
        OWN_UNVERIFIED,
        /** This side's root or keyring is in the old form, with no {@code notAfter}. */
        OWN_OLD_FORM,
        /** This side's root or keyring has passed its {@code notAfter}. */
        OWN_EXPIRED
    }

    /** A setting {@link Builder#build} refused: its message says which, and {@link #fault} says why. */
    public static final class InvalidSetting extends IllegalArgumentException {

        private final Fault fault;

        InvalidSetting(Fault fault, String message) {
            super(message);
            this.fault = fault;
        }

        /** Why the setting was refused. */
        public Fault fault() {
            return fault;
        }
    }

    /**
     * Builds an egress client once its settings are checked. Everything is required but the listener (none unless
     * set), the read timeout ({@link #DEFAULT_READ_TIMEOUT} unless set) and the clocks (the system's).
     */
    public static final class Builder {

        private StamperV3 stamper;
        private ProofBundle bundle;
        private SignedRoot ownRoot;
        private KeyringFile ownKeyring;
        private String ownPolicyKey;
        private String partner;
        private URI partnerUrl;
        private String pinnedPartnerKey;
        private byte[] blindingKey;
        private BoundaryListener listener;
        private HttpClient http;
        private Duration readTimeout = DEFAULT_READ_TIMEOUT;
        private long sessionIdleMs;
        private LongSupplier nanos = System::nanoTime;
        private LongSupplier millis = System::currentTimeMillis;
        private Duration handshakeTimeout = HANDSHAKE_TIMEOUT;

        private Builder() {
        }

        /** This service's stamper; the boundary stamp is signed with its key. */
        public Builder stamper(StamperV3 stamper) {
            this.stamper = stamper;
            return this;
        }

        /** This service's proofs, which must hold {@code <this service>/<partner>}. */
        public Builder bundle(ProofBundle bundle) {
            this.bundle = bundle;
            return this;
        }

        /** This organisation's signed root, sent in the handshake. */
        public Builder ownRoot(SignedRoot root) {
            this.ownRoot = root;
            return this;
        }

        /** This organisation's signed keyring, sent in the handshake. */
        public Builder ownKeyring(KeyringFile keyring) {
            this.ownKeyring = keyring;
            return this;
        }

        /** This organisation's policy public key, base64url, under which the root and keyring verify. */
        public Builder ownPolicyKey(String pin) {
            this.ownPolicyKey = pin;
            return this;
        }

        /** The partner's entry service, the boundary stamp's receiver. */
        public Builder partner(String entry) {
            this.partner = entry;
            return this;
        }

        /** The partner's base URL: a scheme and an authority, with no path. */
        public Builder partnerUrl(URI url) {
            this.partnerUrl = url;
            return this;
        }

        /** The partner's policy public key, base64url, pinned at onboarding. */
        public Builder pinnedPartnerKey(String pin) {
            this.pinnedPartnerKey = pin;
            return this;
        }

        /**
         * This egress service's boundary key, exactly {@value BoundaryInfluence#KEY_LENGTH} bytes, which never
         * leaves this organisation and is shared with no other service (its replicas excepted); copied when built.
         */
        public Builder blindingKey(byte[] key) {
            this.blindingKey = key;
            return this;
        }

        /** Told the originals and the list sent before each attested call; null for none. */
        public Builder listener(BoundaryListener listener) {
            this.listener = listener;
            return this;
        }

        /**
         * The JDK client every handshake and call goes out on: it presents this service's certificate to the
         * partner and trusts the partner's CA. The built client owns it from then on and shuts it down when closed.
         */
        public Builder http(HttpClient client) {
            this.http = client;
            return this;
        }

        /** Each call's bound on the whole exchange, the response's body included; positive. */
        public Builder readTimeout(Duration timeout) {
            this.readTimeout = timeout;
            return this;
        }

        /**
         * How long a session no call has used is kept, in milliseconds; positive, and below the partner's own idle
         * period.
         */
        public Builder sessionIdleMs(long ms) {
            this.sessionIdleMs = ms;
            return this;
        }

        /** The monotonic clock, in nanoseconds, that ages sessions; tests move it. */
        Builder nanos(LongSupplier nanos) {
            this.nanos = nanos;
            return this;
        }

        /**
         * The time of day, in milliseconds since the epoch, that this side's own root and keyring and the reply
         * certificates are judged by; tests move it.
         */
        Builder millis(LongSupplier millis) {
            this.millis = millis;
            return this;
        }

        /**
         * Each handshake's bound on the whole exchange, {@link #HANDSHAKE_TIMEOUT} unless set; tests shorten it, so
         * that a handshake with no answer is replaced without waiting the full period.
         */
        Builder handshakeTimeout(Duration timeout) {
            this.handshakeTimeout = timeout;
            return this;
        }

        /**
         * The client, once its settings are checked, in this order: the partner URL is {@code https}, since the
         * calls carry the boundary stamp and the influence's owners; the boundary key is
         * {@value BoundaryInfluence#KEY_LENGTH} bytes; the read timeout is positive; the partner and this service
         * are named; the idle period is positive; the partner URL is a scheme and an authority only; and this
         * side's root and keyring verify under its policy key and are in the new form and current by the time of
         * day. Each refusal is an {@link InvalidSetting} naming its {@link Fault}.
         *
         * @throws NullPointerException if a required setting is missing
         * @throws InvalidSetting if a setting is refused
         */
        public BoundaryClient build() {
            Objects.requireNonNull(stamper, "stamper");
            Objects.requireNonNull(bundle, "bundle");
            Objects.requireNonNull(ownRoot, "ownRoot");
            Objects.requireNonNull(ownKeyring, "ownKeyring");
            Objects.requireNonNull(ownPolicyKey, "ownPolicyKey");
            Objects.requireNonNull(partner, "partner");
            Objects.requireNonNull(partnerUrl, "partnerUrl");
            Objects.requireNonNull(pinnedPartnerKey, "pinnedPartnerKey");
            // The calls carry the boundary stamp and the influence's owners, which must not cross in the clear.
            if (!"https".equalsIgnoreCase(partnerUrl.getScheme())) {
                throw new InvalidSetting(Fault.NOT_HTTPS, "the partner URL must be an https URL: " + partnerUrl);
            }
            // Refused rather than stretched or cut: every salt is keyed by it.
            if (blindingKey == null || blindingKey.length != BoundaryInfluence.KEY_LENGTH) {
                throw new InvalidSetting(Fault.KEY_LENGTH, "the boundary key must be " + BoundaryInfluence.KEY_LENGTH
                        + " bytes");
            }
            Objects.requireNonNull(http, "http");
            Objects.requireNonNull(readTimeout, "readTimeout");
            if (readTimeout.isNegative() || readTimeout.isZero()) {
                throw new InvalidSetting(Fault.READ_TIMEOUT, "the read timeout must be positive: " + readTimeout);
            }
            Objects.requireNonNull(nanos, "nanos");
            Objects.requireNonNull(millis, "millis");
            Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
            if (partner.isEmpty()) {
                throw new InvalidSetting(Fault.UNNAMED_PARTNER, "the partner's entry service must be named");
            }
            if (stamper.svc() == null || stamper.svc().isEmpty()) {
                throw new InvalidSetting(Fault.UNNAMED_EGRESS, "the egress service must be named");
            }
            if (sessionIdleMs <= 0) {
                throw new InvalidSetting(Fault.IDLE_PERIOD, "the session idle period must be positive");
            }
            if (partnerUrl.getRawAuthority() == null
                    || !(partnerUrl.getRawPath() == null || partnerUrl.getRawPath().isEmpty()
                            || partnerUrl.getRawPath().equals("/"))
                    || partnerUrl.getRawQuery() != null || partnerUrl.getRawFragment() != null) {
                throw new InvalidSetting(Fault.NOT_AN_ORIGIN, "the partner URL must be a scheme and an authority only: "
                        + partnerUrl);
            }
            // A root or keyring the partner cannot verify could never open an attested session, so it fails here.
            if (!ownKeyring.verifies(ownPolicyKey)
                    || !ownRoot.verify(Crypto.decodePublicKey(Base64Url.decode(ownPolicyKey)))) {
                throw new InvalidSetting(Fault.OWN_UNVERIFIED,
                        "the root and keyring must both verify under the policy key");
            }
            // The partner would judge them unsafe, and so would every reply, so a service holding them is
            // misconfigured.
            long now = millis.getAsLong();
            if (!ownRoot.isNewForm() || !ownKeyring.isNewForm()) {
                throw new InvalidSetting(Fault.OWN_OLD_FORM,
                        "the root and keyring must both be in the new form, with a notAfter");
            }
            if (!ownRoot.isCurrent(now) || !ownKeyring.isCurrent(now)) {
                throw new InvalidSetting(Fault.OWN_EXPIRED, "the root and keyring must both be current: "
                        + (ownRoot.isCurrent(now) ? "the keyring" : "the root") + " has expired");
            }
            return new BoundaryClient(this);
        }
    }
}
