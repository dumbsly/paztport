// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.session.ReplyCheck;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifyResult;

/**
 * The partner's session registry on its own: which handshakes it attests, that a reply is signed by its entry key,
 * certified under its pin, and binds both sides' inputs, and that a session belongs to the peer that opened it, by
 * certificate issuer and name, until it is evicted for a newer one of that peer's or has been idle too long. A
 * handshake adds a session and replaces none.
 */
class PartnerSessionsTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final List<String> DISABLED = List.of("POST /refund");
    private static final String SHOP_CA = "CN=shop CA";
    private static final String FOREIGN_CA = "CN=foreign CA";
    private static final long IDLE_MS = 900_000;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /**
     * One organisation's trust material: a policy key, a keyring naming one service, that service's key and a
     * week's reply certificate for it, and a root over its mesh.
     */
    private record Org(KeyPair policy, KeyringFile keyring, KeyPair key, ReplyCert cert, SignedRoot root) {
        static Org of(String service, KeyPair policy) {
            return of(service, policy, NOT_AFTER, NOT_AFTER);
        }

        /** The same, its root signed until {@code rootNotAfter} and its keyring until {@code ringNotAfter}. */
        static Org of(String service, KeyPair policy, long rootNotAfter, long ringNotAfter) {
            KeyPair key = Crypto.generateEd25519KeyPair();
            return new Org(policy,
                    KeyringFile.sign(Map.of(service, pub(key)), pub(policy), ringNotAfter, policy.getPrivate()),
                    key,
                    ReplyCert.issue(pub(policy), service, pub(key), System.currentTimeMillis() + 7 * 86_400_000L,
                            policy.getPrivate()),
                    PolicyBuilder.build(List.of(List.of(service, "x")), 4,
                            rootNotAfter, policy.getPrivate()).signedRoot());
        }

        String pin() {
            return pub(policy);
        }
    }

    private final Org shop = Org.of("payment", Crypto.generateEd25519KeyPair());
    private final Org psp = Org.of("psp", Crypto.generateEd25519KeyPair());
    /** The partner's clock, in milliseconds, which a test moves on by hand. */
    private final AtomicLong now = new AtomicLong(System.currentTimeMillis());
    private final PartnerSessions partner = partner(16);

    private PartnerSessions partner(int maxPerPeer) {
        return new PartnerSessions(psp.root(), psp.keyring(), psp.pin(), "psp", psp.key().getPrivate(), psp.cert(),
                Set.of(shop.pin()), Set.of("payment"), DISABLED, new InMemoryNonceCache(15_000), now::get, 5000, 5000,
                maxPerPeer, IDLE_MS);
    }

    /** Opens an attested session for the peer {@code issuer}, {@code svc} and returns its id. */
    private String open(PartnerSessions sessions, String issuer, String svc) {
        return sessions.open(request(shop, shop.root()), issuer, svc).sess();
    }

    private static SessionRequest request(Org client, SignedRoot root) {
        return SessionRequest.of(root, client.pin(), client.keyring(), Sessions.newNonce());
    }

    private ReplyCheck check(SessionReply reply, SessionRequest req) {
        return Sessions.checkReply(reply.toJson(), req, psp.pin(), "psp", System.currentTimeMillis());
    }

    @Test
    void pinnedClientAttested() {
        SessionRequest req = request(shop, shop.root());
        SessionReply reply = partner.open(req, SHOP_CA, "orders");

        assertEquals(ReplyCheck.ATTESTED, check(reply, req));
        assertEquals(List.of(), reply.disabled());
        PartnerSessions.Session session = partner.find(SHOP_CA, "orders", reply.sess());
        assertTrue(session.attested());
        assertNotNull(session.verifier());
    }

    // Forged: the same reply passed off as the policy-key form, its keyring signature and certificate stripped.
    // It is the entry key's signature, so it fails under the pin.
    @Test
    void replyIsSignedByTheEntryKey() throws Exception {
        SessionRequest req = request(shop, shop.root());
        SessionReply reply = partner.open(req, SHOP_CA, "orders");

        assertEquals(psp.keyring().sig(), reply.serverKeyringSig());
        assertEquals(psp.cert(), reply.serverReplyCert());
        assertEquals(ReplyCheck.ATTESTED, check(reply, req));
        ObjectNode stripped = (ObjectNode) new ObjectMapper().readTree(reply.toJson());
        stripped.remove("serverKeyringSig");
        stripped.remove("serverReplyCert");
        assertEquals(ReplyCheck.BAD_SIGNATURE,
                Sessions.checkReply(stripped.toString(), req, psp.pin(), "psp", System.currentTimeMillis()));
    }

    // A certificate for another service, or for a key the keyring does not hold for this one, would sign replies
    // no client accepts, so no registry is built with one.
    @Test
    void certificateMustBeForThisServicesKey() {
        long later = System.currentTimeMillis() + 86_400_000L;
        ReplyCert otherService = ReplyCert.issue(psp.pin(), "ledger", pub(psp.key()), later, psp.policy().getPrivate());
        ReplyCert otherKey = ReplyCert.issue(psp.pin(), "psp", pub(Crypto.generateEd25519KeyPair()), later,
                psp.policy().getPrivate());
        for (ReplyCert cert : List.of(otherService, otherKey)) {
            assertThrows(IllegalArgumentException.class, () -> new PartnerSessions(psp.root(), psp.keyring(),
                    psp.pin(), "psp", psp.key().getPrivate(), cert, Set.of(shop.pin()), Set.of("payment"), DISABLED,
                    new InMemoryNonceCache(15_000), now::get, 5000, 5000, 16, IDLE_MS));
        }
    }

    /**
     * As with an unpinned key: client material past its window at the handshake opens an unsafe session with no
     * verifier, so no call is ever checked against material its owner no longer vouches for.
     */
    @Test
    void expiredClientMaterialIsUnsafe() {
        Org expiredRoot = Org.of("payment", shop.policy(), now.get() - 1, NOT_AFTER);
        Org expiredRing = Org.of("payment", shop.policy(), NOT_AFTER, now.get() - 1);
        for (Org client : List.of(expiredRoot, expiredRing)) {
            SessionRequest req = request(client, client.root());
            SessionReply reply = partner.open(req, SHOP_CA, "orders");
            assertEquals("unsafe", reply.status());
            assertEquals(DISABLED, reply.disabled());
            assertNull(partner.find(SHOP_CA, "orders", reply.sess()).verifier());
        }
    }

    /**
     * A partner whose own root or keyring expires while it runs degrades rather than stops: every new session is
     * unsafe, and the client, judging the reply at that time, refuses it and takes its replacement path. A session
     * attested before is still verified against the client's material, which is current.
     */
    @Test
    void aPartnerWhoseOwnRootOrKeyringExpiredOpensEverySessionUnsafe() {
        long expiry = now.get() + 1000;
        for (Org own : List.of(Org.of("psp", psp.policy(), expiry, NOT_AFTER),
                Org.of("psp", psp.policy(), NOT_AFTER, expiry))) {
            now.set(expiry - 1000);
            PartnerSessions degrading = new PartnerSessions(own.root(), own.keyring(), own.pin(), "psp",
                    own.key().getPrivate(), own.cert(), Set.of(shop.pin()), Set.of("payment"), DISABLED,
                    new InMemoryNonceCache(15_000), now::get, 5000, 5000, 16, IDLE_MS);
            String earlier = open(degrading, SHOP_CA, "orders");
            assertTrue(degrading.find(SHOP_CA, "orders", earlier).attested());

            now.set(expiry + 1);
            SessionRequest req = request(shop, shop.root());
            SessionReply reply = degrading.open(req, SHOP_CA, "orders");
            assertEquals("unsafe", reply.status());
            assertEquals(DISABLED, reply.disabled());
            assertEquals(ReplyCheck.BAD_SIGNATURE,
                    Sessions.checkReply(reply.toJson(), req, own.pin(), "psp", now.get()));
            assertEquals(ReplyCheck.UNSAFE,
                    Sessions.checkReply(reply.toJson(), req, own.pin(), "psp", expiry - 1000));
            assertEquals(ReasonCode.CHAIN_MISSING,
                    degrading.find(SHOP_CA, "orders", earlier).verifier().verify(null).reason());
        }
    }

    /**
     * An attested session's verifier carries the client's keyring and root windows: once either passes, every call
     * in the session is POLICY_EXPIRED, naming no one, and the client opens a new session on its next handshake.
     */
    @Test
    void callsArePolicyExpiredOnceTheClientsKeyringOrRootExpires() {
        long expiry = now.get() + 1000;
        for (Org client : List.of(Org.of("payment", shop.policy(), NOT_AFTER, expiry),
                Org.of("payment", shop.policy(), expiry, NOT_AFTER))) {
            now.set(expiry - 1000);
            SessionReply reply = partner.open(request(client, client.root()), SHOP_CA, "orders");
            assertEquals("attested", reply.status());
            now.set(expiry);
            PartnerSessions.Session session = partner.find(SHOP_CA, "orders", reply.sess());
            assertEquals(ReasonCode.CHAIN_MISSING, session.verifier().verify(null).reason(), "at notAfter");
            now.set(expiry + 1);
            assertEquals(new VerifyResult(ReasonCode.POLICY_EXPIRED, "", ""),
                    partner.find(SHOP_CA, "orders", reply.sess()).verifier().verify(null), "one ms past");
        }
    }

    @Test
    void unpinnedOrNoRootUnsafe() {
        Org stranger = Org.of("payment", Crypto.generateEd25519KeyPair());
        SessionRequest unpinned = request(stranger, stranger.root());
        SessionReply unpinnedReply = partner.open(unpinned, SHOP_CA, "orders");
        assertEquals(ReplyCheck.UNSAFE, check(unpinnedReply, unpinned));
        assertEquals(DISABLED, unpinnedReply.disabled());

        SessionRequest noRoot = request(shop, null);
        SessionReply noRootReply = partner.open(noRoot, SHOP_CA, "gateway");
        assertEquals(ReplyCheck.UNSAFE, check(noRootReply, noRoot));
        assertEquals(DISABLED, noRootReply.disabled());

        PartnerSessions.Session session = partner.find(SHOP_CA, "gateway", noRootReply.sess());
        assertNotNull(session);
        assertNull(session.verifier(), "an unsafe session verifies nothing");
        assertEquals(DISABLED, partner.unsafeDisabled());
    }

    @Test
    void twoHandshakesFromOnePeerBothUsable() {
        String first = open(partner, SHOP_CA, "orders");
        String second = open(partner, SHOP_CA, "orders");

        assertNotNull(partner.find(SHOP_CA, "orders", first), "a handshake replaces nothing");
        assertNotNull(partner.find(SHOP_CA, "orders", second));
    }

    // Forged: an id another service opened, presented by a service the same CA vouched for.
    @Test
    void otherPeerCannotUseSession() {
        String ordersSess = open(partner, SHOP_CA, "orders");

        assertNull(partner.find(SHOP_CA, "gateway", ordersSess));
        assertNotNull(partner.find(SHOP_CA, "orders", ordersSess));
    }

    // Forged: the same common name under a CA that is not the one the session was opened under.
    @Test
    void sameNameOtherIssuerCannotUseSession() {
        String ordersSess = open(partner, SHOP_CA, "orders");

        assertNull(partner.find(FOREIGN_CA, "orders", ordersSess));
        assertNotNull(partner.find(SHOP_CA, "orders", ordersSess));
    }

    // Forged: no certificate, or one that names no issuer or no single service, never matches a session.
    @Test
    void missingIssuerOrNameNeverMatches() {
        String ordersSess = open(partner, SHOP_CA, "orders");

        assertNull(partner.find(null, "orders", ordersSess));
        assertNull(partner.find("", "orders", ordersSess));
        assertNull(partner.find(SHOP_CA, null, ordersSess));
        assertNull(partner.find(SHOP_CA, "", ordersSess));
        assertNull(partner.find(null, null, ordersSess));
        assertNull(partner.find(SHOP_CA, "orders", null));

        // Nor can such a peer open one, so there is never a session under a missing name to find.
        SessionRequest req = request(shop, shop.root());
        assertThrows(IllegalArgumentException.class, () -> partner.open(req, null, "orders"));
        assertThrows(IllegalArgumentException.class, () -> partner.open(req, "", "orders"));
        assertThrows(IllegalArgumentException.class, () -> partner.open(req, SHOP_CA, null));
        assertThrows(IllegalArgumentException.class, () -> partner.open(req, SHOP_CA, ""));
    }

    // Forged: an id the peer itself opened, presented after a newer handshake of its own evicted it.
    @Test
    void capEvictsLeastRecentlyUsed() {
        PartnerSessions two = partner(2);
        String a = open(two, SHOP_CA, "orders");
        String b = open(two, SHOP_CA, "orders");
        String other = open(two, SHOP_CA, "gateway");
        assertNotNull(two.find(SHOP_CA, "orders", a));

        String c = open(two, SHOP_CA, "orders");

        assertNull(two.find(SHOP_CA, "orders", b), "b was used least recently");
        assertNotNull(two.find(SHOP_CA, "orders", a));
        assertNotNull(two.find(SHOP_CA, "orders", c));
        assertNotNull(two.find(SHOP_CA, "gateway", other), "a peer evicts only its own sessions");
    }

    // Forged: an id presented after it has been idle for the partner's whole period.
    @Test
    void idleSessionExpires() {
        String kept = open(partner, SHOP_CA, "orders");
        String idle = open(partner, SHOP_CA, "orders");

        now.addAndGet(IDLE_MS - 1);
        assertNotNull(partner.find(SHOP_CA, "orders", kept), "just under the period, and this use renews it");

        now.addAndGet(1);
        assertNull(partner.find(SHOP_CA, "orders", idle));
        assertNotNull(partner.find(SHOP_CA, "orders", kept));

        now.addAndGet(IDLE_MS);
        assertNull(partner.find(SHOP_CA, "orders", kept));
    }

    @Test
    void failedOpenChangesNothing() {
        PartnerSessions one = partner(1);
        String sess = open(one, SHOP_CA, "orders");
        // A nonce of the wrong length derives no session id.
        SessionRequest bad = SessionRequest.of(shop.root(), shop.pin(), shop.keyring(), "short");

        assertThrows(IllegalArgumentException.class, () -> one.open(bad, SHOP_CA, "orders"));
        assertNotNull(one.find(SHOP_CA, "orders", sess));
    }

    @Test
    void limitsMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> partner(0));
        assertThrows(IllegalArgumentException.class, () -> new PartnerSessions(psp.root(), psp.keyring(), psp.pin(),
                "psp", psp.key().getPrivate(), psp.cert(), Set.of(shop.pin()), Set.of("payment"), DISABLED,
                new InMemoryNonceCache(15_000), now::get, 5000, 5000, 16, 0));
    }

    @Test
    void concurrentOpensRespectCap() throws Exception {
        PartnerSessions four = partner(4);
        String other = open(four, SHOP_CA, "gateway");
        int threads = 8;
        int perThread = 10;
        List<String> opened = new CopyOnWriteArrayList<>();
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<?>> done = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                done.add(pool.submit(() -> {
                    go.await();
                    for (int i = 0; i < perThread; i++) {
                        opened.add(open(four, SHOP_CA, "orders"));
                    }
                    return null;
                }));
            }
            go.countDown();
            for (Future<?> f : done) {
                f.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(threads * perThread, Set.copyOf(opened).size());
        long live = opened.stream().filter(sess -> four.find(SHOP_CA, "orders", sess) != null).count();
        assertEquals(4, live, "the peer holds exactly its cap");
        assertNotNull(four.find(SHOP_CA, "gateway", other), "another peer's session survives");
    }

    /**
     * Only the partner's receiver looks a session up for a call, and a lookup keeps a session alive as a call would,
     * so neither the lookup nor the record it returns is public.
     */
    @Test
    void findAndSessionAreNotPublic() throws Exception {
        Method find = PartnerSessions.class.getDeclaredMethod("find", String.class, String.class, String.class);
        assertFalse(Modifier.isPublic(find.getModifiers()), "find must not be public");
        assertFalse(Modifier.isProtected(find.getModifiers()), "find must not be protected");
        int session = PartnerSessions.Session.class.getModifiers();
        assertFalse(Modifier.isPublic(session), "Session must not be public");
        assertFalse(Modifier.isProtected(session), "Session must not be protected");
    }
}
