// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.core.verify.VerifierV3;
import org.paztport.core.verify.VerifyInputV3;
import org.paztport.http.boundary.BoundaryAccess;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.boundary.BoundaryHooks;
import org.paztport.http.boundary.BoundaryListener;
import org.paztport.http.wire.HttpV3;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.slf4j.LoggerFactory;

/**
 * The egress on its own, against a stub partner: one handshake per session, one boundary stamp per attested call
 * and nothing else of the internal chain, no chain or influence in an unsafe session, the replacement after a reply
 * it cannot use, and a fresh session after the partner forgets one or this side has left one idle. Above all, nothing
 * at all leaves, the handshake included, unless this hop verified the request's chain.
 *
 * <p>It sits in the root package, not {@code boundary}, because it marks chains verified, which only
 * {@link RequestContext}'s package can, and scripts {@code StubPartner}; it reaches the egress's test hooks through
 * {@link BoundaryHooks}.
 */
class BoundaryClientTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] CHARGE = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    private static final List<InfluenceEntry> INFLUENCE = List.of(
            new InfluenceEntry(InfluenceClass.THIRD_PARTY, "http:tickets", "h-ticket", "cid-1", null),
            new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order", "cid-2", "alice"));

    private final KeyPair gateway = Crypto.generateEd25519KeyPair();
    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final String policyPub = pub(policy);
    private final PolicyBuilder.Result built = PolicyBuilder.build(
            List.of(List.of("gateway", "payment"), List.of("payment", "psp")), 4, NOT_AFTER, policy.getPrivate());
    private final KeyringFile keyring = KeyringFile.sign(
            Map.of("gateway", pub(gateway), "payment", pub(payment)), policyPub, NOT_AFTER, policy.getPrivate());

    private final ListAppender<ILoggingEvent> traces = new ListAppender<>();
    private final Logger traceLog = (Logger) LoggerFactory.getLogger("PAZTPORT_TRACE");

    /** How long this side keeps a session no call has used. */
    private static final long IDLE_MS = 600_000;

    /** The client's clock, in nanoseconds, which a test moves on by hand. */
    private final AtomicLong nanos = new AtomicLong();

    /** The client's time of day, in milliseconds since the epoch, against which reply certificates are judged. */
    private final AtomicLong millis = new AtomicLong(1_767_225_600_000L);

    /** This egress's boundary key. */
    private final byte[] blindingKey = new SecureRandom().generateSeed(BoundaryInfluence.KEY_LENGTH);

    /** One call of the listener, with how many calls the partner had received when it ran. */
    private record Heard(String rid, String partnerEntry, List<InfluenceEntry> originals,
            List<InfluenceEntry> sent, int callsBefore) {
    }

    private final List<Heard> heard = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** What the listener does after recording; a test makes it throw. */
    private volatile BoundaryListener onSent = (rid, partnerEntry, originals, sent) -> { };

    private StubPartner partner;
    private BoundaryClient client;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    @BeforeEach
    void start() throws Exception {
        partner = new StubPartner();
        client = egress(partner, tls()).build();
        traces.start();
        traceLog.addAppender(traces);
        traceLog.setLevel(Level.INFO);
        traceLog.setAdditive(false);
    }

    @AfterEach
    void stop() {
        traceLog.detachAppender(traces);
        traceLog.setLevel(null);
        traceLog.setAdditive(true);
        client.close();
        partner.close();
        RequestContext.reset();
    }

    private void listen(String rid, String partnerEntry, List<InfluenceEntry> originals, List<InfluenceEntry> sent) {
        heard.add(new Heard(rid, partnerEntry, originals, sent, partner.calls().size()));
        onSent.sent(rid, partnerEntry, originals, sent);
    }

    /**
     * An egress like {@link #client}, against {@code to} and on {@code http}, which the built client owns, for a
     * test to change before building it: payment's material, the listener, both clocks and {@link #IDLE_MS}.
     */
    private BoundaryClient.Builder egress(StubPartner to, HttpClient http) {
        BoundaryClient.Builder builder = BoundaryClient.builder()
                .stamper(new StamperV3("payment", "payment-1", payment.getPrivate(), false, () -> "unused",
                        System::currentTimeMillis))
                .bundle(built.bundles().get("payment"))
                .ownRoot(built.signedRoot())
                .ownKeyring(keyring)
                .ownPolicyKey(policyPub)
                .partner("psp")
                .partnerUrl(to.url())
                .pinnedPartnerKey(to.policyKey())
                .blindingKey(blindingKey)
                .listener(this::listen)
                .http(http)
                .sessionIdleMs(IDLE_MS);
        return BoundaryHooks.millis(BoundaryHooks.nanos(builder, nanos::get), millis::get);
    }

    /**
     * The JDK client the egress calls out on, as the starter's pooled one is made: HTTP/1.1, presenting the
     * fixture's {@code payment} certificate and trusting only the fixture CA, which the stub's certificate is under.
     */
    private static HttpClient tls() {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .sslContext(StubPartner.fixtureContext("payment"))
                .build();
    }

    /** A one-stamp chain from the gateway to payment, as payment's filter would have verified it. */
    private List<StampV3> gatewayChain(String rid) {
        return new StamperV3("gateway", "gw-1", gateway.getPrivate(), true, () -> rid, System::currentTimeMillis)
                .next(null, "payment", RequestBinding.compute("POST", "/pay", CHARGE), List.of(),
                        built.bundles().get("gateway"))
                .chain();
    }

    /** Runs {@code call} in a fresh scope holding a verified gateway chain and the two influence entries. */
    private <T> T verified(String rid, Callable<T> call) throws Exception {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.markVerified(gatewayChain(rid));
            RequestContext.addInfluence(INFLUENCE.toArray(InfluenceEntry[]::new));
            return call.call();
        }
    }

    private BoundaryClient.Response charge() {
        return client.post("/charge", CHARGE);
    }

    private List<String> lines(String prefix) {
        return traces.list.stream().map(ILoggingEvent::getFormattedMessage).filter(l -> l.startsWith(prefix))
                .toList();
    }

    @Test
    void theHandshakeBodyIsTheRequestsJcsBytes() throws Exception {
        verified("rid-1", this::charge);

        byte[] body = partner.handshakes().get(0).body();
        JsonValue request = JsonReader.wire(body);
        assertArrayEquals(body, JsonWriter.wire(request));
        assertFalse(new String(body, StandardCharsets.UTF_8).contains("\\u"), "characters are written as themselves");
        assertEquals(List.of("clientKeyring", "clientKeyringNotAfter", "clientKeyringSig", "clientPolicyKey",
                "clientRoot", "nonce"), List.copyOf(((JsonValue.Obj) request).names()));
    }

    @Test
    void attestedCallCarriesOneBoundaryStamp() throws Exception {
        BoundaryClient.Response response = verified("rid-1", this::charge);

        assertEquals(200, response.status());
        assertTrue(response.attested());
        assertEquals(1, partner.handshakes().size());
        JsonNode request = JSON.readTree(partner.handshakes().get(0).body());
        assertEquals(built.signedRoot().sig(), request.get("clientRoot").get("sig").textValue());
        assertEquals(policyPub, request.get("clientPolicyKey").textValue());
        assertEquals(keyring.sig(), request.get("clientKeyringSig").textValue());

        assertEquals(1, partner.calls().size());
        StubPartner.Received call = partner.calls().get(0);
        String sess = partner.issued().get(0);
        assertEquals("/charge", call.path());
        assertEquals(sess, call.header(PaztportHeaders.SESSION));

        String chainJson = HttpV3.decodeChain(call.header(PaztportHeaders.CHAIN));
        JsonNode chain = JSON.readTree(chainJson);
        assertEquals(1, chain.size(), "only the boundary stamp crosses");
        JsonNode stamp = chain.get(0);
        assertEquals("payment", stamp.get("svc").textValue());
        assertEquals("psp", stamp.get("rcv").textValue());
        assertEquals("", stamp.get("prev").textValue());
        assertEquals("rid-1", stamp.get("rid").textValue());
        assertEquals(sess, stamp.get("sess").textValue());
        assertEquals(RequestBinding.compute("POST", "/charge", CHARGE), stamp.get("bind").textValue());

        MerkleProof proof = MerkleProof.decode(call.header(PaztportHeaders.PROOF));
        assertTrue(proof.verify("payment/psp", built.signedRoot().rootBytes()));

        List<InfluenceEntry> sent = Influence.parse(HttpV3.decodeInfluence(call.header(PaztportHeaders.INFLUENCE)));
        assertEquals(BoundaryInfluence.reduce(INFLUENCE, blindingKey, "rid-1", "psp", "payment"), sent,
                "the owners cross, blinded");

        // And the partner, holding only payment's keyring and root, verifies it in that session.
        VerifierV3 atPartner = new VerifierV3(VerifierConfigV3.pinned(keyring, built.signedRoot(), policyPub,
                Set.of("payment"), sess, new InMemoryNonceCache(60_000), System::currentTimeMillis, 30_000, 300_000));
        assertEquals(ReasonCode.OK, atPartner.verify(new VerifyInputV3(chainJson,
                RequestBinding.compute("POST", "/charge", call.body()), HttpV3.decodeInfluence(
                        call.header(PaztportHeaders.INFLUENCE)), HttpV3.decodeProof(call.header(PaztportHeaders.PROOF)),
                "psp", true, "rid-1|payment|req", new Peer("payment", "127.0.0.1"))).reason());

        assertEquals(List.of("PAZTPORT_TRACE session partner=psp check=ATTESTED status=attested"),
                lines("PAZTPORT_TRACE session "));
        assertEquals(List.of("PAZTPORT_TRACE boundary rid=rid-1 receiver=psp session=attested status=200 "
                + "classes=private,third-party"), lines("PAZTPORT_TRACE boundary "));
    }

    // The partner needs only each entry's class and owner; the sources and plain hashes are the shop's to keep.
    @Test
    void sendsReducedInfluence() throws Exception {
        List<InfluenceEntry> influence = List.of(
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "http:tickets", "h-ticket", "cid-1", null),
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "web:example.com", "h-page", null, null),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order", "cid-2", "alice"),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order-2", "cid-3", "alice"),
                new InfluenceEntry(InfluenceClass.PRIVATE, "http:orders", "h-order", "cid-2", null));

        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.markVerified(gatewayChain("rid-1"));
            RequestContext.addInfluence(influence.toArray(InfluenceEntry[]::new));
            assertEquals(200, charge().status());
        }

        StubPartner.Received call = partner.calls().get(0);
        String header = call.header(PaztportHeaders.INFLUENCE);
        List<InfluenceEntry> sent = Influence.parse(HttpV3.decodeInfluence(header));
        assertEquals(3, sent.size(), "one entry per (class, owner)");
        assertEquals(Set.of(InfluenceClass.THIRD_PARTY + "|null", InfluenceClass.PRIVATE + "|alice",
                InfluenceClass.PRIVATE + "|null"), Set.copyOf(sent.stream().map(e -> e.cls() + "|" + e.owner())
                        .toList()));
        for (InfluenceEntry e : sent) {
            assertEquals("boundary:payment", e.src());
            assertNull(e.cid());
        }
        assertEquals(Influence.normalise(sent), sent, "the sent list is normalised");
        assertEquals(BoundaryInfluence.reduce(influence, blindingKey, "rid-1", "psp", "payment"), sent);
        JsonNode stamp = JSON.readTree(HttpV3.decodeChain(call.header(PaztportHeaders.CHAIN))).get(0);
        assertEquals(Influence.commit(sent), stamp.get("infl").textValue(), "the stamp commits to what was sent");

        String wire = new String(Base64Url.decode(header), StandardCharsets.UTF_8);
        for (String secret : List.of("http:tickets", "web:example.com", "http:orders", "h-ticket", "h-order",
                "cid-1")) {
            assertFalse(wire.contains(secret), secret + " crossed the boundary");
        }
        // Nor is any of it logged.
        for (String line : lines("PAZTPORT_TRACE ")) {
            for (String secret : List.of("http:", "web:", "h-", "alice", "boundary:")) {
                assertFalse(line.contains(secret), line);
            }
        }
    }

    @Test
    void listenerSeesOriginalsAndSent() throws Exception {
        verified("rid-1", this::charge);

        assertEquals(1, heard.size());
        Heard h = heard.get(0);
        assertEquals("rid-1", h.rid());
        assertEquals("psp", h.partnerEntry());
        assertEquals(Influence.normalise(INFLUENCE), h.originals(), "every field of every original");
        StubPartner.Received call = partner.calls().get(0);
        assertEquals(Influence.parse(HttpV3.decodeInfluence(call.header(PaztportHeaders.INFLUENCE))), h.sent(),
                "exactly the list sent");
        assertEquals(0, h.callsBefore(), "it runs before the request is sent");
        assertThrows(UnsupportedOperationException.class, () -> h.originals().clear());
    }

    @Test
    void openingFromListenerOpensWhatPartnerHolds() throws Exception {
        verified("rid-1", this::charge);
        verified("rid-2", this::charge);

        List<InfluenceEntry> first = Influence.parse(HttpV3.decodeInfluence(
                partner.calls().get(0).header(PaztportHeaders.INFLUENCE)));
        List<InfluenceEntry> originals = heard.get(0).originals();
        assertEquals(2, first.size());
        for (InfluenceEntry e : first) {
            BoundaryInfluence.Opening opening = client.opening("rid-1", e.cls(), e.owner(), originals);
            assertTrue(BoundaryInfluence.opens(e, opening), e.toString());
            assertEquals(1, opening.originals().size(), "only the group's own originals");
        }

        InfluenceEntry thirdParty = first.stream().filter(e -> e.cls() == InfluenceClass.THIRD_PARTY).findFirst()
                .orElseThrow();
        InfluenceEntry privateEntry = first.stream().filter(e -> e.cls() == InfluenceClass.PRIVATE).findFirst()
                .orElseThrow();
        // One group's opening does not open another's entry.
        assertFalse(BoundaryInfluence.opens(privateEntry,
                client.opening("rid-1", InfluenceClass.THIRD_PARTY, null, originals)));
        // An opening derived for another request does not open this one's, though the content is the same.
        assertFalse(BoundaryInfluence.opens(thirdParty,
                client.opening("rid-2", InfluenceClass.THIRD_PARTY, null, originals)));
        // Nor does one whose originals were changed.
        List<InfluenceEntry> altered = List.of(
                new InfluenceEntry(InfluenceClass.THIRD_PARTY, "http:tickets", "h-other", "cid-1", null));
        assertFalse(BoundaryInfluence.opens(thirdParty,
                client.opening("rid-1", InfluenceClass.THIRD_PARTY, null, altered)));
        // The same content in the next request was sent under another salt.
        List<InfluenceEntry> second = Influence.parse(HttpV3.decodeInfluence(
                partner.calls().get(1).header(PaztportHeaders.INFLUENCE)));
        assertNotEquals(first, second);
        assertThrows(IllegalArgumentException.class,
                () -> client.opening("rid-1", InfluenceClass.LOCAL_UNTRUSTED, null, originals),
                "no original is in that group");
    }

    // If the shop can't keep what the entries stood for, they must not be sent: it could never open them.
    @Test
    void listenerFailureSendsNothing() throws Exception {
        onSent = (rid, partnerEntry, originals, sent) -> {
            throw new IllegalStateException("store unavailable");
        };

        List<InfluenceEntry> after = verified("rid-1", () -> {
            IllegalStateException thrown = assertThrows(IllegalStateException.class, this::charge);
            assertEquals("store unavailable", thrown.getMessage());
            return RequestContext.influence();
        });

        assertEquals(1, heard.size());
        assertEquals(List.of(), partner.calls(), "the request is not sent");
        assertEquals(INFLUENCE, after, "and nothing came back to record");
        assertEquals(List.of(), lines("PAZTPORT_TRACE boundary "));
    }

    @Test
    void unsafeSessionSendsNoInfluenceAndNoListenerCall() throws Exception {
        partner.status("unsafe");
        verified("rid-1", this::charge);

        // And the replacement after a reply this side cannot use: unsafe too.
        try (BoundaryClient other = egress(partner, tls()).build()) {
            partner.status("attested");
            partner.signNextHandshakeWith(Crypto.generateEd25519KeyPair());
            assertFalse(verified("rid-2", () -> other.post("/charge", CHARGE)).attested());
        }

        assertEquals(2, partner.calls().size());
        for (StubPartner.Received call : partner.calls()) {
            assertNull(call.header(PaztportHeaders.INFLUENCE));
            assertNull(call.header(PaztportHeaders.CHAIN));
        }
        assertEquals(List.of(), heard, "no listener call in an unsafe session");
    }

    @Test
    void secondCallReusesSession() throws Exception {
        verified("rid-1", this::charge);
        verified("rid-2", this::charge);

        assertEquals(1, partner.handshakes().size());
        assertEquals(2, partner.calls().size());
        String sess = partner.issued().get(0);
        partner.calls().forEach(c -> assertEquals(sess, c.header(PaztportHeaders.SESSION)));
    }

    @Test
    void unsafeSendsNoChainOrInfluence() throws Exception {
        partner.status("unsafe");

        BoundaryClient.Response response = verified("rid-1", this::charge);

        assertEquals(200, response.status());
        assertFalse(response.attested());
        StubPartner.Received call = partner.calls().get(0);
        assertEquals(partner.issued().get(0), call.header(PaztportHeaders.SESSION));
        assertNull(call.header(PaztportHeaders.CHAIN));
        assertNull(call.header(PaztportHeaders.PROOF));
        assertNull(call.header(PaztportHeaders.INFLUENCE));
        assertEquals(List.of("PAZTPORT_TRACE session partner=psp check=UNSAFE status=unsafe"),
                lines("PAZTPORT_TRACE session "));
        assertEquals(List.of("PAZTPORT_TRACE boundary rid=rid-1 receiver=psp session=unsafe status=200 classes=-"),
                lines("PAZTPORT_TRACE boundary "));
    }

    @Test
    void pinMismatchReplacesWithNoRoot() throws Exception {
        partner.signNextHandshakeWith(Crypto.generateEd25519KeyPair());

        BoundaryClient.Response response = verified("rid-1", this::charge);

        List<StubPartner.Received> handshakes = partner.handshakes();
        assertEquals(2, handshakes.size());
        JsonNode first = JSON.readTree(handshakes.get(0).body());
        JsonNode second = JSON.readTree(handshakes.get(1).body());
        assertTrue(first.get("clientRoot").isObject());
        assertTrue(second.get("clientRoot").isNull(), "the replacement asks for an unsafe session");
        assertNotEquals(first.get("nonce").textValue(), second.get("nonce").textValue());
        assertEquals(first.get("clientPolicyKey"), second.get("clientPolicyKey"));
        assertEquals(first.get("clientKeyring"), second.get("clientKeyring"));
        assertEquals(first.get("clientKeyringSig"), second.get("clientKeyringSig"));

        assertFalse(response.attested());
        StubPartner.Received call = partner.calls().get(0);
        assertEquals(partner.issued().get(1), call.header(PaztportHeaders.SESSION));
        assertNull(call.header(PaztportHeaders.CHAIN));
        assertNull(call.header(PaztportHeaders.INFLUENCE));
        assertEquals(List.of("PAZTPORT_TRACE session partner=psp check=PIN_MISMATCH status=unsafe"),
                lines("PAZTPORT_TRACE session "));
    }

    /** A second egress like {@link #client}, against the same partner, with no session yet. */
    private BoundaryClient anotherClient() {
        return egress(partner, tls()).build();
    }

    // A partner signs with its entry key under a certificate, or, as before certificates, with its policy key.
    @Test
    void acceptsBothReplyForms() throws Exception {
        assertTrue(verified("rid-1", this::charge).attested());
        assertTrue(partner.replies().get(0).serverReplyCert() != null, "the entry-key form");

        partner.policyKeyForm();
        try (BoundaryClient other = anotherClient()) {
            assertTrue(verified("rid-2", () -> other.post("/charge", CHARGE)).attested());
        }
        assertNull(partner.replies().get(1).serverReplyCert(), "the policy-key form");
        assertNull(partner.replies().get(1).serverKeyringSig());
        assertEquals(2, partner.handshakes().size(), "no replacement for either");
        assertEquals(List.of("PAZTPORT_TRACE session partner=psp check=ATTESTED status=attested",
                "PAZTPORT_TRACE session partner=psp check=ATTESTED status=attested"),
                lines("PAZTPORT_TRACE session "));
    }

    // Forged: a reply signed by the entry key after its certificate's notAfter, by this side's clock. The key may
    // have been retired by not reissuing its certificate, so nothing it signs is accepted.
    @Test
    void expiredCertificateGivesUnsafeSession() throws Exception {
        partner.replyCertNotAfter(millis.get() - 1);

        BoundaryClient.Response response = verified("rid-1", this::charge);

        assertFalse(response.attested());
        List<StubPartner.Received> handshakes = partner.handshakes();
        assertEquals(2, handshakes.size());
        assertTrue(JSON.readTree(handshakes.get(1).body()).get("clientRoot").isNull(), "the replacement follows");
        StubPartner.Received call = partner.calls().get(0);
        assertEquals(partner.issued().get(1), call.header(PaztportHeaders.SESSION));
        assertNull(call.header(PaztportHeaders.CHAIN));
        assertNull(call.header(PaztportHeaders.INFLUENCE));
        assertEquals(List.of(), heard, "nothing was offered to the listener");
        assertEquals(List.of("PAZTPORT_TRACE session partner=psp check=BAD_SIGNATURE status=unsafe"),
                lines("PAZTPORT_TRACE session "));
    }

    // The certificate's notAfter is inclusive: at that very millisecond the reply is still accepted.
    @Test
    void certificateHoldsThroughItsNotAfter() throws Exception {
        partner.replyCertNotAfter(millis.get());

        assertTrue(verified("rid-1", this::charge).attested());
        assertEquals(1, partner.handshakes().size());
    }

    @Test
    void sessionUnknownReopensNextCall() throws Exception {
        partner.answerNext(403, "{\"reason\":\"SESSION_UNKNOWN\"}");

        BoundaryClient.Response refused = verified("rid-1", this::charge);
        assertEquals(403, refused.status());
        assertEquals(1, partner.handshakes().size());
        assertEquals(1, partner.calls().size(), "there is no retry");

        verified("rid-2", this::charge);
        assertEquals(2, partner.handshakes().size());
        assertEquals(partner.issued().get(1), partner.calls().get(1).header(PaztportHeaders.SESSION));
    }

    // A refusal is read from its wire bytes, {"reason":"<code>"} and nothing more. Any other body gives no reason, so
    // the session is kept, as after any refusal that names none.
    @Test
    void aRefusalBodyThatIsNotItsWireBytesGivesNoReason() throws Exception {
        List<String> bodies = List.of("{\"reason\": \"SESSION_UNKNOWN\"}", "{\"reason\":\"SESSION_UNKNOWN\"}\n",
                "{\"detail\":\"gone\",\"reason\":\"SESSION_UNKNOWN\"}", "{\"reason\":\"POLICY_EXPIRED\",\"x\":1}");
        bodies.forEach(body -> partner.answerNext(403, body));

        for (int i = 0; i < bodies.size(); i++) {
            assertEquals(403, verified("rid-" + i, this::charge).status(), bodies.get(i));
        }
        assertEquals(1, partner.handshakes().size(), "the session is kept");
    }

    // Once the egress's own root or keyring lapses, the partner refuses every call in the attested session
    // POLICY_EXPIRED; the session is dropped so that the next call opens a new handshake, which the partner judges
    // unsafe, and the egress says why, once.
    @Test
    void policyExpiredDropsTheSessionAndOwnLapseIsLoggedOnce() throws Exception {
        long notAfter = millis.get() + 60_000;
        PolicyBuilder.Result lapsing = PolicyBuilder.build(List.of(List.of("gateway", "payment"),
                List.of("payment", "psp")), 4, notAfter, policy.getPrivate());
        KeyringFile lapsingRing = KeyringFile.sign(Map.of("gateway", pub(gateway), "payment", pub(payment)),
                policyPub, notAfter, policy.getPrivate());
        ListAppender<ILoggingEvent> warnings = new ListAppender<>();
        Logger clientLog = (Logger) LoggerFactory.getLogger(BoundaryClient.class);
        warnings.start();
        clientLog.addAppender(warnings);
        clientLog.setLevel(Level.WARN);
        try (BoundaryClient egress = egress(partner, tls()).bundle(lapsing.bundles().get("payment"))
                .ownRoot(lapsing.signedRoot()).ownKeyring(lapsingRing).listener(null).build()) {
            assertTrue(verified("rid-1", () -> egress.post("/charge", CHARGE)).attested());
            assertThat(warnings.list).isEmpty();

            millis.set(notAfter + 1);
            partner.status("unsafe");
            partner.answerNext(403, "{\"reason\":\"POLICY_EXPIRED\"}");
            BoundaryClient.Response refused = verified("rid-2", () -> egress.post("/charge", CHARGE));
            assertEquals(403, refused.status());
            assertTrue(refused.attested());
            assertEquals(1, partner.handshakes().size());

            BoundaryClient.Response next = verified("rid-3", () -> egress.post("/charge", CHARGE));
            assertEquals(2, partner.handshakes().size(), "the next call opens a new session");
            assertFalse(next.attested());
            assertEquals(partner.issued().get(1), partner.calls().get(2).header(PaztportHeaders.SESSION));
            verified("rid-4", () -> egress.post("/charge", CHARGE));
            assertEquals(2, partner.handshakes().size());

            List<String> said = warnings.list.stream().filter(e -> e.getLevel() == Level.WARN)
                    .map(ILoggingEvent::getFormattedMessage).toList();
            assertThat(said).hasSize(1);
            assertThat(said.get(0)).contains("root and keyring").contains("expired").contains("policy tool");
        } finally {
            clientLog.detachAppender(warnings);
            clientLog.setLevel(null);
        }
    }

    @Test
    void otherRefusalKeepsSession() throws Exception {
        partner.answerNext(403, "{\"reason\":\"INFLUENCE_DENIED\"}");

        verified("rid-1", this::charge);
        verified("rid-2", this::charge);
        assertEquals(1, partner.handshakes().size());
    }

    @Test
    void replyIsLocalUntrusted() throws Exception {
        List<InfluenceEntry> after = verified("rid-1", () -> {
            BoundaryClient.Response r = charge();
            List<InfluenceEntry> all = RequestContext.influence();
            assertEquals(HttpV3.resultHash(r.status(), r.body()), all.get(all.size() - 1).h());
            return all;
        });

        assertEquals(INFLUENCE.size() + 1, after.size());
        List<InfluenceEntry> added = after.subList(INFLUENCE.size(), after.size());
        assertEquals(1, added.size());
        assertEquals(InfluenceClass.LOCAL_UNTRUSTED, added.get(0).cls());
        assertEquals("http:psp", added.get(0).src());
        assertNull(added.get(0).owner());
    }

    // Payment relays the partner's answer as its own response, so the response is labelled untrusted too: else
    // its filter would attest the partner's words with no labels, and the caller would take them as clean.
    @Test
    void replyLabelsTheRelayUntrusted() throws Exception {
        List<ContentLabel> labels = verified("rid-1", () -> {
            charge();
            return RequestContext.labels();
        });

        assertEquals(1, labels.size());
        assertEquals(InfluenceClass.LOCAL_UNTRUSTED, labels.get(0).cls());
        assertNull(labels.get(0).owner());
    }

    // A partner that was briefly down must not leave this side unsafe for the life of the process.
    @Test
    void fallbackSessionIsRetriedAfterItsPeriod() throws Exception {
        partner.failNextHandshake(503);

        assertFalse(verified("rid-1", this::charge).attested(), "the replacement gives an unsafe session");
        assertEquals(2, partner.handshakes().size());

        nanos.addAndGet(BoundaryHooks.FALLBACK_PERIOD.toNanos() - 1);
        assertFalse(verified("rid-2", this::charge).attested());
        assertEquals(2, partner.handshakes().size(), "no new handshake within the period");

        nanos.addAndGet(1);
        assertTrue(verified("rid-3", this::charge).attested(), "the full handshake is tried again");
        assertEquals(3, partner.handshakes().size());
        assertTrue(JSON.readTree(partner.handshakes().get(2).body()).get("clientRoot").isObject());
        assertEquals(partner.issued().get(1), partner.calls().get(2).header(PaztportHeaders.SESSION));
        assertEquals(List.of("PAZTPORT_TRACE session partner=psp check=- status=unsafe",
                "PAZTPORT_TRACE session partner=psp check=ATTESTED status=attested"),
                lines("PAZTPORT_TRACE session "));
    }

    // A genuine unsafe answer is the partner's decision (it does not pin us), not a failure, so it is kept.
    @Test
    void genuineUnsafeSessionIsKept() throws Exception {
        partner.status("unsafe");

        verified("rid-1", this::charge);
        nanos.addAndGet(BoundaryHooks.FALLBACK_PERIOD.toNanos() * 10);
        verified("rid-2", this::charge);

        assertEquals(1, partner.handshakes().size());
    }

    // The partner forgets a session left idle, and a refused call is not retried, so this side must drop it first.
    @Test
    void idleSessionIsReopened() throws Exception {
        verified("rid-1", this::charge);

        nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(IDLE_MS) - 1);
        assertEquals(200, verified("rid-2", this::charge).status());
        assertEquals(1, partner.handshakes().size(), "no new handshake just under the period");

        // That call renewed it, so a whole period must pass again from there.
        nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(IDLE_MS) - 1);
        assertEquals(200, verified("rid-3", this::charge).status());
        assertEquals(1, partner.handshakes().size());

        nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(IDLE_MS));
        BoundaryClient.Response after = verified("rid-4", this::charge);
        assertEquals(200, after.status());
        assertTrue(after.attested());
        assertEquals(2, partner.handshakes().size(), "the idle session is dropped and a new one opened");
        assertEquals(partner.issued().get(1), partner.calls().get(3).header(PaztportHeaders.SESSION));
    }

    // A replacement's session goes idle like any other, before its own period is up.
    @Test
    void idleFallbackSessionIsReopened() throws Exception {
        try (BoundaryClient shortIdle = egress(partner, tls()).listener(null).sessionIdleMs(1_000).build()) {
            partner.failNextHandshake(503);
            assertFalse(verified("rid-1", () -> shortIdle.post("/charge", CHARGE)).attested());
            assertEquals(2, partner.handshakes().size());

            nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(1_000));
            assertTrue(verified("rid-2", () -> shortIdle.post("/charge", CHARGE)).attested());
            assertEquals(3, partner.handshakes().size());
        }
    }

    /** The builder with these as the egress's own root and keyring, judged at {@link #millis}. */
    private void egressWith(SignedRoot root, KeyringFile ring) {
        try (HttpClient tls = tls()) {
            egress(partner, tls).ownRoot(root).ownKeyring(ring).listener(null).build().close();
        }
    }

    // A root or keyring past its notAfter would open only unsafe sessions, so the egress will not start with one.
    @Test
    void egressRefusesExpiredOwnRoot() {
        SignedRoot expired = PolicyBuilder.build(List.of(List.of("gateway", "payment")), 4, millis.get() - 1,
                policy.getPrivate()).signedRoot();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> egressWith(expired, keyring));
        assertTrue(e.getMessage().contains("root has expired"), e.getMessage());

        KeyringFile lapsed = KeyringFile.sign(Map.of("payment", pub(payment)), policyPub, millis.get() - 1,
                policy.getPrivate());
        e = assertThrows(IllegalArgumentException.class, () -> egressWith(built.signedRoot(), lapsed));
        assertTrue(e.getMessage().contains("keyring has expired"), e.getMessage());
    }

    @Test
    void idlePeriodMustBePositive() {
        try (HttpClient tls = tls()) {
            assertThrows(IllegalArgumentException.class,
                    () -> egress(partner, tls).listener(null).sessionIdleMs(0).build());
        }
    }

    // The salts are HMAC outputs under this key: a short one would be stretched or padded by the MAC, so it is
    // refused rather than used.
    @Test
    void blindingKeyMustBe32Bytes() {
        try (HttpClient tls = tls()) {
            for (byte[] key : new byte[][] {null, new byte[31], new byte[33]}) {
                assertThrows(RuntimeException.class,
                        () -> egress(partner, tls).blindingKey(key).listener(null).build());
            }
        }
    }

    @Test
    void concurrentFirstCallsOneHandshake() throws Exception {
        partner.handshakeDelayMs(200);
        int threads = 8;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<BoundaryClient.Response>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                String rid = "rid-" + i;
                results.add(pool.submit(() -> verified(rid, () -> {
                    ready.countDown();
                    go.await();
                    return charge();
                })));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();
            for (Future<BoundaryClient.Response> f : results) {
                assertEquals(200, f.get(10, TimeUnit.SECONDS).status());
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, partner.handshakes().size());
        assertEquals(threads, partner.calls().size());
        String sess = partner.issued().get(0);
        partner.calls().forEach(c -> assertEquals(sess, c.header(PaztportHeaders.SESSION)));
    }

    @Test
    void noScopeOrUnverifiedSendsNothing() throws Exception {
        IllegalStateException outside = assertThrows(IllegalStateException.class, this::charge);
        assertEquals("no verified chain: nothing is signed at the boundary", outside.getMessage());

        try (RequestContext.Scope scope = RequestContext.open()) {
            // The chain arrived but did not verify here: it is inbound, never marked.
            RequestContext.setInboundChain(gatewayChain("rid-1"));
            RequestContext.addInfluence(INFLUENCE.toArray(InfluenceEntry[]::new));
            IllegalStateException unverified = assertThrows(IllegalStateException.class, this::charge);
            assertEquals("no verified chain: nothing is signed at the boundary", unverified.getMessage());
        }

        assertEquals(List.of(), partner.received(), "not even the handshake is sent");
        assertEquals(List.of(), lines("PAZTPORT_TRACE "));
    }

    @Test
    void emptyVerifiedChainSendsNothing() throws Exception {
        try (RequestContext.Scope scope = RequestContext.open()) {
            RequestContext.markVerified(List.of());
            assertThrows(IllegalStateException.class, this::charge);
        }
        assertEquals(List.of(), partner.received());
    }

    @Test
    void pathMustStayOnThePartner() throws Exception {
        verified("rid-1", () -> {
            assertThrows(IllegalArgumentException.class, () -> client.post("//elsewhere.example/charge", CHARGE));
            assertThrows(IllegalArgumentException.class, () -> client.post("charge", CHARGE));
            return null;
        });
        assertEquals(List.of(), partner.received());
    }

    @Test
    void failedReplacementThrows() throws Exception {
        partner.close();

        assertThrows(IllegalStateException.class, () -> verified("rid-1", this::charge));
    }

    /**
     * A partner that takes a call and never finishes answering it, either before its headers or part way through
     * the body: the call fails at the read timeout, as the {@code UncheckedIOException} a failed call always is, on
     * any JDK, and the session is kept as after any failed call, so the next call goes out in it with no handshake.
     * On JDK 27 the JDK's own request timeout also ends a stalled body, so there the body case passes even without
     * the client's whole-exchange bound; on JDK 25, which applies a request's timeout only to the headers, it shows
     * that bound.
     */
    @Test
    void aCallThePartnerNeverFinishesFailsAtTheReadTimeoutAndKeepsTheSession() throws Exception {
        for (SilentPeer.Stall stall : SilentPeer.Stall.values()) {
            try (StubPartner stalling = new StubPartner();
                    BoundaryClient bounded = egress(stalling, tls()).listener(null)
                            .readTimeout(Duration.ofMillis(300)).build()) {
                stalling.stallNextCall(stall);

                long start = System.nanoTime();
                UncheckedIOException e = assertThrows(UncheckedIOException.class,
                        () -> verified("rid-1", () -> bounded.post("/charge", CHARGE)), stall.name());
                Duration took = Duration.ofNanos(System.nanoTime() - start);

                assertTrue(e.getCause() instanceof HttpTimeoutException, stall + ": " + e.getCause());
                assertTrue(took.compareTo(Duration.ofMillis(250)) >= 0 && took.compareTo(Duration.ofSeconds(3)) < 0,
                        stall + " took " + took);
                assertEquals(1, stalling.handshakes().size());

                BoundaryClient.Response next = verified("rid-2", () -> bounded.post("/charge", CHARGE));
                assertEquals(200, next.status(), stall.name());
                assertTrue(next.attested());
                assertEquals(1, stalling.handshakes().size(), stall + ": the session is kept");
                assertEquals(stalling.issued().get(0), stalling.calls().get(1).header(PaztportHeaders.SESSION));
            }
        }
    }

    /**
     * A handshake the partner takes and never finishes answering, before its headers or part way through the body,
     * counts as no answer once the handshake's timeout has passed: the replacement with no root follows, and its
     * session is unsafe even when its reply says attested, so the call carries the session id and nothing else.
     */
    @Test
    void aHandshakeThePartnerNeverFinishesIsReplacedAtItsTimeout() throws Exception {
        for (SilentPeer.Stall stall : SilentPeer.Stall.values()) {
            try (StubPartner stalling = new StubPartner();
                    BoundaryClient bounded = BoundaryHooks.handshakeTimeout(
                            egress(stalling, tls()).listener(null), Duration.ofMillis(300)).build()) {
                stalling.stallNextHandshake(stall);
                stalling.replacementStatus("attested");

                long start = System.nanoTime();
                BoundaryClient.Response response = verified("rid-1", () -> bounded.post("/charge", CHARGE));
                Duration took = Duration.ofNanos(System.nanoTime() - start);

                assertEquals(200, response.status(), stall.name());
                assertFalse(response.attested(), stall + ": the replacement's session is unsafe");
                assertTrue(took.compareTo(Duration.ofMillis(250)) >= 0 && took.compareTo(Duration.ofSeconds(3)) < 0,
                        stall + " took " + took);
                List<StubPartner.Received> handshakes = stalling.handshakes();
                assertEquals(2, handshakes.size(), stall.name());
                assertTrue(JSON.readTree(handshakes.get(1).body()).get("clientRoot").isNull(),
                        stall + ": the replacement asks with no root");
                StubPartner.Received call = stalling.calls().get(0);
                assertEquals(stalling.issued().get(0), call.header(PaztportHeaders.SESSION));
                assertNull(call.header(PaztportHeaders.CHAIN), stall + ": no stamp in an unsafe session");
                assertNull(call.header(PaztportHeaders.INFLUENCE), stall + ": no influence in an unsafe session");
            }
        }
    }

    @Test
    void anEgressBuiltWithNoReadTimeoutHasTheDefault() {
        assertEquals(BoundaryClient.DEFAULT_READ_TIMEOUT, BoundaryAccess.readTimeout(client));
    }
}
