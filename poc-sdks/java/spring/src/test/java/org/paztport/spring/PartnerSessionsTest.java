// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * binds both sides' inputs, and that a session belongs to the peer that opened it, until that peer opens another.
 */
class PartnerSessionsTest {

    private static final List<String> DISABLED = List.of("POST /refund");

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
    private final PartnerSessions partner = new PartnerSessions(psp.root(), psp.keyring(), psp.pin(),
            psp.policy().getPrivate(), Set.of(shop.pin()), Set.of("payment"), DISABLED,
            new InMemoryNonceCache(15_000), System::currentTimeMillis, 5000, 5000);

    private static SessionRequest request(Org client, SignedRoot root) {
        return new SessionRequest(root, client.pin(), client.keyring().services(), client.keyring().sig(),
                Sessions.newNonce());
    }

    private ReplyCheck check(SessionReply reply, SessionRequest req) {
        return Sessions.checkReply(reply.toJson(), req, psp.pin());
    }

    @Test
    void pinnedClientAttested() {
        SessionRequest req = request(shop, shop.root());
        SessionReply reply = partner.open(req, "orders");

        assertEquals(ReplyCheck.ATTESTED, check(reply, req));
        assertEquals(List.of(), reply.disabled());
        PartnerSessions.Session session = partner.find("orders", reply.sess());
        assertTrue(session.attested());
        assertNotNull(session.verifier());
    }

    @Test
    void unpinnedOrNoRootUnsafe() {
        Org stranger = Org.of("payment", Crypto.generateEd25519KeyPair());
        SessionRequest unpinned = request(stranger, stranger.root());
        SessionReply unpinnedReply = partner.open(unpinned, "orders");
        assertEquals(ReplyCheck.UNSAFE, check(unpinnedReply, unpinned));
        assertEquals(DISABLED, unpinnedReply.disabled());

        SessionRequest noRoot = request(shop, null);
        SessionReply noRootReply = partner.open(noRoot, "gateway");
        assertEquals(ReplyCheck.UNSAFE, check(noRootReply, noRoot));
        assertEquals(DISABLED, noRootReply.disabled());

        PartnerSessions.Session session = partner.find("gateway", noRootReply.sess());
        assertNotNull(session);
        assertNull(session.verifier(), "an unsafe session verifies nothing");
        assertEquals(DISABLED, partner.unsafeDisabled());
    }

    @Test
    void newHandshakeReplaces() {
        String first = partner.open(request(shop, shop.root()), "orders").sess();
        String second = partner.open(request(shop, shop.root()), "orders").sess();

        assertNull(partner.find("orders", first));
        assertNotNull(partner.find("orders", second));
    }

    @Test
    void boundToPeer() {
        String ordersSess = partner.open(request(shop, shop.root()), "orders").sess();

        assertNull(partner.find("gateway", ordersSess));
        assertNull(partner.find(null, ordersSess));
        assertNotNull(partner.find("orders", ordersSess));
    }
}
