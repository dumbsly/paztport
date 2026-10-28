// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.KeyringFile;
import org.paztport.core.PolicyBuilder;
import org.paztport.core.ReplyCheck;
import org.paztport.core.SessionReply;
import org.paztport.core.SessionRequest;
import org.paztport.core.Sessions;
import org.paztport.core.SignedRoot;

/**
 * The partner's session registry on its own: which handshakes it attests, that a reply is signed under its pin and
 * binds both sides' inputs, and that a session belongs to the peer that opened it, by certificate issuer and name,
 * until it is evicted for a newer one of that peer's or has been idle too long. A handshake adds a session and
 * replaces none.
 */
class PartnerSessionsTest {

    private static final List<String> DISABLED = List.of("POST /refund");
    private static final String SHOP_CA = "CN=shop CA";
    private static final String FOREIGN_CA = "CN=foreign CA";
    private static final long IDLE_MS = 900_000;

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /** One organisation's trust material: a policy key, a keyring naming one service, and a root over its mesh. */
    private record Org(KeyPair policy, KeyringFile keyring, SignedRoot root) {
        static Org of(String service, KeyPair policy) {
            KeyPair key = Crypto.generateEd25519KeyPair();
            return new Org(policy,
                    KeyringFile.sign(Map.of(service, pub(key)), pub(policy), policy.getPrivate()),
                    PolicyBuilder.build(List.of(List.of(service, "x")), 4, policy.getPrivate()).signedRoot());
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
        return new PartnerSessions(psp.root(), psp.keyring(), psp.pin(), psp.policy().getPrivate(),
                Set.of(shop.pin()), Set.of("payment"), DISABLED, new InMemoryNonceCache(15_000), now::get, 5000, 5000,
                maxPerPeer, IDLE_MS);
    }

    /** Opens an attested session for the peer {@code issuer}, {@code svc} and returns its id. */
    private String open(PartnerSessions sessions, String issuer, String svc) {
        return sessions.open(request(shop, shop.root()), issuer, svc).sess();
    }

    private static SessionRequest request(Org client, SignedRoot root) {
        return new SessionRequest(root, client.pin(), client.keyring().services(), client.keyring().sig(),
                Sessions.newNonce());
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
        SessionRequest bad = new SessionRequest(shop.root(), shop.pin(), shop.keyring().services(),
                shop.keyring().sig(), "short");

        assertThrows(IllegalArgumentException.class, () -> one.open(bad, SHOP_CA, "orders"));
        assertNotNull(one.find(SHOP_CA, "orders", sess));
    }

    @Test
    void limitsMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> partner(0));
        assertThrows(IllegalArgumentException.class, () -> new PartnerSessions(psp.root(), psp.keyring(), psp.pin(),
                psp.policy().getPrivate(), Set.of(shop.pin()), Set.of("payment"), DISABLED,
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
}
