// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.paztport.core.Vectors;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.Keyring;

/**
 * Builds {@code spec/vectors/events.json} and replays it. It is deterministic: the times and ids are fixed, the
 * keys are derived by {@code v3.json}'s rule, and Ed25519 signs deterministically, so {@link #build} reproduces the
 * committed bytes and {@code EventVectorsTest} pins them. The writer is opt-in, and this class is not matched by
 * Surefire's default includes, so name it: {@code (cd poc-sdks/java && mvn -q -pl core test
 * -Dtest=EventVectorsExport -Dpaztport.exportEventVectors=true
 * -Dvectors.out=<repo>/poc-sdks/spec/vectors/events.json -Dsurefire.failIfNoSpecifiedTests=false)}. Each recorded
 * answer is the verifier's own, and {@link #build} replays every case read back from the text it is written as, so
 * the recorded answer always matches a replay of the written text.
 */
class EventVectorsExport {

    private static final String ABOUT = "Paztport event conformance vectors: the signed events a verifying service"
            + " sends its responder. Each key's private key is the PKCS#8 DER 302e020100300506032b657004220420 ||"
            + " seed, where seed = SHA-256(utf8(\"paztport-v3-vector-key:\" + name)), and its public key is the SPKI"
            + " DER export, both base64url: v3.json's rule, so `payment` is the key http-v3.json names `payment`."
            + " An envelope case signs `eventJson`, the text a sender writes for `event`, as `signer` with that"
            + " signer's key: `payload` is the base64url of its UTF-8 bytes, `signingBytes` (base64url) the bytes"
            + " signed and `sig` the signature. Each verify case runs against a fresh `responder`, with its `keyring`"
            + " (service to public key), its `allowedSigners` and an empty memory of event ids: each `earlier` body"
            + " is offered at its `now`, in order, then `body` is offered `uses` times at the case's `now`, and the"
            + " last result is the one expected: an accepted event has a null `refusal` and the `event` read, and a"
            + " refused one the refusal's name and a null `event`. Bodies are the exact text received, and the"
            + " envelope and the event are read strictly, so a replay hands each body over unchanged. The window is"
            + " 30000 ms either way, and an accepted id is remembered for 60000 ms. Ed25519 is deterministic, so the"
            + " file is reproduced byte for byte. Cases may be added; a recorded answer changes only with a protocol"
            + " change.";

    private static final long NOW = 1_767_225_600_000L;
    private static final long WINDOW_MS = 30_000;
    private static final String KEY_PREFIX = "302e020100300506032b657004220420";
    private static final String DOMAIN = "paztport-event\n";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The key v3.json's rule gives {@code name}: the seed is a hash of the name, the public key follows from it. */
    static KeyPair derive(String name) {
        byte[] seed = Crypto.sha256(("paztport-v3-vector-key:" + name).getBytes(StandardCharsets.UTF_8));
        SecureRandom fixed = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                System.arraycopy(seed, 0, bytes, 0, bytes.length);
            }
        };
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
            gen.initialize(NamedParameterSpec.ED25519, fixed);
            KeyPair pair = gen.generateKeyPair();
            assertEquals(KEY_PREFIX + HexFormat.of().formatHex(seed),
                    HexFormat.of().formatHex(Crypto.encodePrivateKey(pair.getPrivate())), "derived key " + name);
            return pair;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The event a verifier sends for a refusal it attributes, at {@code ts} with id {@code eventId}. */
    private static ResponderEvent event(long ts, String eventId) {
        return new ResponderEvent("PATH_NOT_ALLOWED", "search", "search-1", "rid-event-1", false, ts, eventId);
    }

    private static String signed(String signer, PrivateKey key, String eventJson) {
        return EventEnvelope.sign(signer, eventJson.getBytes(StandardCharsets.UTF_8), key).toJson();
    }

    private static String signed(String signer, PrivateKey key, ResponderEvent event) {
        return signed(signer, key, event.toJson());
    }

    /** An envelope over {@code payload} as given, signed with the prefix, whatever the payload decodes to. */
    private static String overPayload(String signer, PrivateKey key, String payload) {
        String sig = Base64Url.encode(Crypto.sign(key, EventEnvelope.signingBytes(payload)));
        return new EventEnvelope(signer, payload, sig).toJson();
    }

    private static String b64(String text) {
        return Base64Url.encode(text.getBytes(StandardCharsets.UTF_8));
    }

    private static JsonNode tree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static ObjectNode build() throws IOException {
        KeyPair payment = derive("payment");
        KeyPair search = derive("search");
        PrivateKey pay = payment.getPrivate();

        ObjectNode out = JsonNodeFactory.instance.objectNode();
        out.put("about", ABOUT);
        ObjectNode keys = out.putObject("keys");
        Map<String, KeyPair> pairs = new LinkedHashMap<>();
        pairs.put("payment", payment);
        pairs.put("search", search);
        for (Map.Entry<String, KeyPair> k : pairs.entrySet()) {
            ObjectNode o = keys.putObject(k.getKey());
            o.put("pub", Base64Url.encode(Crypto.encodePublicKey(k.getValue().getPublic())));
            o.put("priv", Base64Url.encode(Crypto.encodePrivateKey(k.getValue().getPrivate())));
        }

        ArrayNode envelopes = out.putArray("envelope");
        envelopes.add(envelopeCase("attributed refusal", "payment", pay, event(NOW, "event-1")));
        envelopes.add(envelopeCase("audit event naming no one", "payment", pay,
                new ResponderEvent("EXPIRED", "", "", "", true, NOW, "event-2")));
        envelopes.add(envelopeCase("non-ASCII text", "payment", pay,
                new ResponderEvent("PEER_MISMATCH", "search", "10.0.0.7:41000", "rid-é-😀", false, NOW,
                        "event-3")));

        ObjectNode responder = out.putObject("responder");
        ObjectNode keyring = responder.putObject("keyring");
        keyring.put("payment", keys.get("payment").get("pub").asText());
        keyring.put("search", keys.get("search").get("pub").asText());
        responder.putArray("allowedSigners").add("orders").add("payment");

        String good = signed("payment", pay, event(NOW, "event-1"));
        ResponderEvent prefixless = event(NOW, "event-1");
        String prefixlessPayload = b64(prefixless.toJson());
        String bare = new EventEnvelope("payment", prefixlessPayload,
                Base64Url.encode(Crypto.sign(pay, prefixlessPayload.getBytes(StandardCharsets.UTF_8)))).toJson();
        EventEnvelope a = EventEnvelope.sign("payment", event(NOW, "event-1").toJson()
                .getBytes(StandardCharsets.UTF_8), pay);
        EventEnvelope b = EventEnvelope.sign("payment", event(NOW, "event-2").toJson()
                .getBytes(StandardCharsets.UTF_8), pay);
        String tampered = new EventEnvelope("payment", b.payload(), a.sig()).toJson();
        String noId = "{\"reason\":\"PATH_NOT_ALLOWED\",\"suspectSvc\":\"search\",\"suspectInst\":\"search-1\","
                + "\"rid\":\"rid-event-1\",\"audit\":false,\"ts\":" + NOW + "}";

        ArrayNode verify = out.putArray("verify");
        verify.add(verifyCase("accepted", responder, List.of(), good, NOW, 1));
        verify.add(verifyCase("audit event accepted", responder, List.of(),
                signed("payment", pay, new ResponderEvent("EXPIRED", "", "", "", true, NOW, "event-2")), NOW, 1));
        verify.add(verifyCase("at the window, in the past", responder, List.of(),
                signed("payment", pay, event(NOW - WINDOW_MS, "event-1")), NOW, 1));
        verify.add(verifyCase("at the window, in the future", responder, List.of(),
                signed("payment", pay, event(NOW + WINDOW_MS, "event-1")), NOW, 1));
        verify.add(verifyCase("1 ms past the window, in the past", responder, List.of(),
                signed("payment", pay, event(NOW - WINDOW_MS - 1, "event-1")), NOW, 1));
        verify.add(verifyCase("1 ms past the window, in the future", responder, List.of(),
                signed("payment", pay, event(NOW + WINDOW_MS + 1, "event-1")), NOW, 1));
        verify.add(verifyCase("replayed", responder, List.of(), good, NOW, 2));
        verify.add(verifyCase("same id, new payload", responder, List.of(new Earlier(good, NOW)),
                signed("payment", pay, event(NOW + 1, "event-1")), NOW, 1));
        String future = signed("payment", pay, event(NOW + WINDOW_MS, "event-1"));
        verify.add(verifyCase("id remembered while its ts is in the window", responder,
                List.of(new Earlier(future, NOW)), future, NOW + 2 * WINDOW_MS, 1));
        verify.add(verifyCase("replay after the window", responder, List.of(new Earlier(good, NOW)), good,
                NOW + WINDOW_MS + 1, 1));
        verify.add(verifyCase("a bad signature spends no id", responder,
                List.of(new Earlier(new EventEnvelope("payment", a.payload(), "AAAA").toJson(), NOW)), good, NOW, 1));
        String early = signed("payment", pay, event(NOW + WINDOW_MS + 1, "event-1"));
        verify.add(verifyCase("an event outside the window spends no id", responder,
                List.of(new Earlier(early, NOW)), early, NOW + 1, 1));
        verify.add(verifyCase("not JSON", responder, List.of(), "not json", NOW, 1));
        verify.add(verifyCase("empty body", responder, List.of(), "", NOW, 1));
        verify.add(verifyCase("a JSON array", responder, List.of(), "[]", NOW, 1));
        verify.add(verifyCase("JSON null", responder, List.of(), "null", NOW, 1));
        verify.add(verifyCase("the event unwrapped", responder, List.of(), event(NOW, "event-1").toJson(), NOW, 1));
        verify.add(verifyCase("no sig", responder, List.of(),
                "{\"signer\":\"payment\",\"payload\":\"" + a.payload() + "\"}", NOW, 1));
        verify.add(verifyCase("null signer", responder, List.of(),
                "{\"signer\":null,\"payload\":\"" + a.payload() + "\",\"sig\":\"" + a.sig() + "\"}", NOW, 1));
        verify.add(verifyCase("signer not allowed", responder, List.of(),
                signed("search", search.getPrivate(), event(NOW, "event-1")), NOW, 1));
        verify.add(verifyCase("signer not allowed, before its signature", responder, List.of(),
                new EventEnvelope("search", a.payload(), "AAAA").toJson(), NOW, 1));
        verify.add(verifyCase("allowed signer with no key", responder, List.of(),
                signed("orders", pay, event(NOW, "event-1")), NOW, 1));
        verify.add(verifyCase("wrong signer", responder, List.of(),
                signed("payment", search.getPrivate(), event(NOW, "event-1")), NOW, 1));
        verify.add(verifyCase("tampered payload", responder, List.of(), tampered, NOW, 1));
        verify.add(verifyCase("signed without the prefix", responder, List.of(), bare, NOW, 1));
        verify.add(verifyCase("sig not base64url", responder, List.of(),
                new EventEnvelope("payment", a.payload(), "!!").toJson(), NOW, 1));
        verify.add(verifyCase("bad signature, before the window", responder, List.of(),
                signed("payment", search.getPrivate(), event(NOW - WINDOW_MS - 1, "event-1")), NOW, 1));
        verify.add(verifyCase("payload not base64url", responder, List.of(), overPayload("payment", pay, "!!"),
                NOW, 1));
        verify.add(verifyCase("payload not JSON", responder, List.of(),
                overPayload("payment", pay, b64("not json")), NOW, 1));
        verify.add(verifyCase("payload a JSON array", responder, List.of(),
                overPayload("payment", pay, b64("[]")), NOW, 1));
        verify.add(verifyCase("no eventId", responder, List.of(), signed("payment", pay, noId), NOW, 1));
        verify.add(verifyCase("empty eventId", responder, List.of(),
                signed("payment", pay, event(NOW, "")), NOW, 1));
        verify.add(verifyCase("no eventId, outside the window", responder, List.of(),
                signed("payment", pay, noId.replace(Long.toString(NOW), Long.toString(NOW - WINDOW_MS - 1))),
                NOW, 1));

        // Read strictly: nothing coerced, filled in or left trailing, in the envelope or the event.
        String base = event(NOW, "event-1").toJson();
        String sigOk = "\"sig\":\"" + a.sig() + "\"";
        verify.add(verifyCase("envelope with trailing text", responder, List.of(), good + " x", NOW, 1));
        verify.add(verifyCase("envelope with a second value", responder, List.of(), good + "{}", NOW, 1));
        verify.add(verifyCase("signer as a number", responder, List.of(),
                "{\"signer\":1,\"payload\":\"" + a.payload() + "\"," + sigOk + "}", NOW, 1));
        verify.add(verifyCase("envelope with another member", responder, List.of(),
                "{\"signer\":\"payment\",\"payload\":\"" + a.payload() + "\"," + sigOk + ",\"kid\":\"k\"}",
                NOW, 1));
        verify.add(verifyCase("event with trailing text", responder, List.of(),
                signed("payment", pay, base + " x"), NOW, 1));
        verify.add(verifyCase("ts as a string", responder, List.of(), signed("payment", pay,
                base.replace("\"ts\":" + NOW, "\"ts\":\"" + NOW + "\"")), NOW, 1));
        verify.add(verifyCase("audit as a number", responder, List.of(), signed("payment", pay,
                base.replace("\"audit\":false", "\"audit\":0")), NOW, 1));
        verify.add(verifyCase("reason as a number", responder, List.of(), signed("payment", pay,
                base.replace("\"reason\":\"PATH_NOT_ALLOWED\"", "\"reason\":3")), NOW, 1));
        verify.add(verifyCase("no reason", responder, List.of(), signed("payment", pay,
                base.replace("\"reason\":\"PATH_NOT_ALLOWED\",", "")), NOW, 1));
        verify.add(verifyCase("no ts", responder, List.of(), signed("payment", pay,
                base.replace(",\"ts\":" + NOW, "")), NOW, 1));
        verify.add(verifyCase("null reason", responder, List.of(), signed("payment", pay,
                base.replace("\"reason\":\"PATH_NOT_ALLOWED\"", "\"reason\":null")), NOW, 1));
        verify.add(verifyCase("null eventId", responder, List.of(), signed("payment", pay,
                base.replace("\"eventId\":\"event-1\"", "\"eventId\":null")), NOW, 1));
        verify.add(verifyCase("eventId as a number", responder, List.of(), signed("payment", pay,
                base.replace("\"eventId\":\"event-1\"", "\"eventId\":1")), NOW, 1));
        verify.add(verifyCase("whitespace eventId", responder, List.of(),
                signed("payment", pay, event(NOW, " ")), NOW, 1));
        verify.add(verifyCase("event with another member", responder, List.of(), signed("payment", pay,
                base.replace("}", ",\"peer\":\"search\"}")), NOW, 1));
        for (String[] ts : new String[][] {
                {"ts with a fraction", NOW + ".5"},
                {"ts written with .0, read by value", NOW + ".0"},
                {"ts written with an exponent, read by value", "1.7672256E12"},
                {"ts of 2^53", "9007199254740992"},
                {"ts of -(2^53)", "-9007199254740992"},
                {"ts of -(2^63)", "-9223372036854775808"},
                {"ts of 2^53 - 1, in range", "9007199254740991"},
                {"ts of -(2^53 - 1), in range", "-9007199254740991"},
                {"null ts", "null"}}) {
            verify.add(verifyCase(ts[0], responder, List.of(), signed("payment", pay,
                    base.replace("\"ts\":" + NOW, "\"ts\":" + ts[1])), NOW, 1));
        }
        byte[] invalid = base.replace("search-1", "search-\u0001").getBytes(StandardCharsets.UTF_8);
        invalid[base.indexOf("search-1") + "search-".length()] = (byte) 0xFF;
        verify.add(verifyCase("payload not UTF-8", responder, List.of(),
                overPayload("payment", pay, Base64Url.encode(invalid)), NOW, 1));
        byte[] json = base.getBytes(StandardCharsets.UTF_8);
        byte[] bom = new byte[json.length + 3];
        bom[0] = (byte) 0xEF;
        bom[1] = (byte) 0xBB;
        bom[2] = (byte) 0xBF;
        System.arraycopy(json, 0, bom, 3, json.length);
        verify.add(verifyCase("payload with a byte order mark", responder, List.of(),
                overPayload("payment", pay, Base64Url.encode(bom)), NOW, 1));

        // JSON whitespace around a value is part of RFC 8259's grammar; a byte order mark is not.
        verify.add(verifyCase("whitespace around the body", responder, List.of(), " \n\t" + good + "\r\n ", NOW, 1));
        verify.add(verifyCase("whitespace around the payload", responder, List.of(),
                signed("payment", pay, " \n" + base + "\n"), NOW, 1));
        verify.add(verifyCase("body with a byte order mark", responder, List.of(), "\uFEFF" + good, NOW, 1));
        // The signature is checked before the payload is read, and the event's members before its id.
        verify.add(verifyCase("bad signature, payload not base64url", responder, List.of(),
                new EventEnvelope("payment", "!!", a.sig()).toJson(), NOW, 1));
        verify.add(verifyCase("bad signature, payload not JSON", responder, List.of(),
                new EventEnvelope("payment", b64("not json"), a.sig()).toJson(), NOW, 1));
        verify.add(verifyCase("no eventId and no reason", responder, List.of(), signed("payment", pay,
                noId.replace("\"reason\":\"PATH_NOT_ALLOWED\",", "")), NOW, 1));
        // RFC 3629 UTF-8: "-" written in two bytes, and U+D800 encoded as if it were a character.
        verify.add(verifyCase("payload with an overlong form", responder, List.of(), overPayload("payment", pay,
                Base64Url.encode(splice(base, "search-1", new byte[] {'s', 'e', 'a', 'r', 'c', 'h', (byte) 0xC0,
                        (byte) 0xAD, '1'}))), NOW, 1));
        verify.add(verifyCase("payload with an encoded surrogate", responder, List.of(), overPayload("payment", pay,
                Base64Url.encode(splice(base, "search-1", new byte[] {'s', (byte) 0xED, (byte) 0xA0, (byte) 0x80}))),
                NOW, 1));
        // Each member's type, one at a time.
        for (String[] t : new String[][] {
                {"null suspectSvc", "\"suspectSvc\":\"search\"", "\"suspectSvc\":null"},
                {"suspectSvc as a number", "\"suspectSvc\":\"search\"", "\"suspectSvc\":1"},
                {"null suspectInst", "\"suspectInst\":\"search-1\"", "\"suspectInst\":null"},
                {"suspectInst as a number", "\"suspectInst\":\"search-1\"", "\"suspectInst\":1"},
                {"null rid", "\"rid\":\"rid-event-1\"", "\"rid\":null"},
                {"rid as a number", "\"rid\":\"rid-event-1\"", "\"rid\":1"},
                {"audit as a string", "\"audit\":false", "\"audit\":\"true\""},
                {"no audit", "\"audit\":false,", ""}}) {
            verify.add(verifyCase(t[0], responder, List.of(), signed("payment", pay, base.replace(t[1], t[2])),
                    NOW, 1));
        }
        verify.add(verifyCase("payload as a number", responder, List.of(),
                "{\"signer\":\"payment\",\"payload\":1," + sigOk + "}", NOW, 1));
        verify.add(verifyCase("sig as a number", responder, List.of(),
                "{\"signer\":\"payment\",\"payload\":\"" + a.payload() + "\",\"sig\":1}", NOW, 1));

        // Replay what was just built, read back from the text it is written as.
        assertAll(Vectors.read(new String(render(out), StandardCharsets.UTF_8)));
        return out;
    }

    private record Earlier(String body, long now) {
    }

    /** {@code text}'s UTF-8 bytes with the first {@code target} replaced by raw {@code bytes}, valid or not. */
    private static byte[] splice(String text, String target, byte[] bytes) {
        byte[] before = text.substring(0, text.indexOf(target)).getBytes(StandardCharsets.UTF_8);
        byte[] after = text.substring(text.indexOf(target) + target.length()).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[before.length + bytes.length + after.length];
        System.arraycopy(before, 0, out, 0, before.length);
        System.arraycopy(bytes, 0, out, before.length, bytes.length);
        System.arraycopy(after, 0, out, before.length + bytes.length, after.length);
        return out;
    }

    private static ObjectNode envelopeCase(String name, String signer, PrivateKey key, ResponderEvent event) {
        String eventJson = event.toJson();
        EventEnvelope env = EventEnvelope.sign(signer, eventJson.getBytes(StandardCharsets.UTF_8), key);
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        c.put("signer", signer);
        c.set("event", tree(eventJson));
        c.put("eventJson", eventJson);
        c.put("payload", env.payload());
        c.put("signingBytes", Base64Url.encode(EventEnvelope.signingBytes(env.payload())));
        c.put("sig", env.sig());
        return c;
    }

    /** A verify case, its expected result found by running it, so the file records what the verifier does. */
    private static ObjectNode verifyCase(String name, ObjectNode responder, List<Earlier> earlier, String body,
            long now, int uses) {
        ObjectNode c = JsonNodeFactory.instance.objectNode();
        c.put("name", name);
        ArrayNode e = c.putArray("earlier");
        for (Earlier x : earlier) {
            e.addObject().put("body", x.body()).put("now", x.now());
        }
        c.put("body", body);
        c.put("now", now);
        c.put("uses", uses);
        EventVerifier.Outcome got = run(responder, c);
        ObjectNode want = c.putObject("expected");
        if (got.accepted()) {
            want.putNull("refusal");
            want.set("event", tree(got.event().toJson()));
        } else {
            want.put("refusal", got.refusal().name());
            want.putNull("event");
        }
        return c;
    }

    /** Runs a verify case as its fields say, against a fresh {@code responder}: the earlier bodies, then the body. */
    static EventVerifier.Outcome run(JsonNode responder, JsonNode c) {
        Map<String, PublicKey> keys = new TreeMap<>();
        responder.get("keyring").fields().forEachRemaining(
                f -> keys.put(f.getKey(), Crypto.decodePublicKey(Base64Url.decode(f.getValue().asText()))));
        Set<String> allowed = new LinkedHashSet<>();
        responder.get("allowedSigners").forEach(s -> allowed.add(s.asText()));
        AtomicLong clock = new AtomicLong();
        EventVerifier verifier = new EventVerifier(Keyring.of(keys), allowed, clock::get);
        for (JsonNode x : c.get("earlier")) {
            clock.set(x.get("now").asLong());
            verifier.accept(x.get("body").asText());
        }
        clock.set(c.get("now").asLong());
        EventVerifier.Outcome got = null;
        for (int i = 0; i < c.get("uses").asInt(); i++) {
            got = verifier.accept(c.get("body").asText());
        }
        return got;
    }

    /** Checks every case in {@code vectors}, a tree {@link Vectors#read} built, so each text is the file's own. */
    static void assertAll(JsonNode vectors) {
        for (JsonNode c : vectors.get("envelope")) {
            String name = c.get("name").asText();
            PrivateKey key = Crypto.decodePrivateKey(
                    Base64Url.decode(vectors.get("keys").get(c.get("signer").asText()).get("priv").asText()));
            String eventJson = c.get("eventJson").asText();
            JsonNode e = c.get("event");
            ResponderEvent fields = new ResponderEvent(e.get("reason").asText(), e.get("suspectSvc").asText(),
                    e.get("suspectInst").asText(), e.get("rid").asText(), e.get("audit").asBoolean(),
                    e.get("ts").asLong(), e.get("eventId").asText());
            assertEquals(eventJson, fields.toJson(), name + ": the event as a sender writes it");
            EventEnvelope env = EventEnvelope.sign(c.get("signer").asText(),
                    eventJson.getBytes(StandardCharsets.UTF_8), key);
            assertEquals(c.get("payload").asText(), env.payload(), name);
            byte[] signing = EventEnvelope.signingBytes(env.payload());
            assertEquals(c.get("signingBytes").asText(), Base64Url.encode(signing), name);
            assertEquals(DOMAIN + env.payload(), new String(signing, StandardCharsets.UTF_8), name);
            assertEquals(c.get("sig").asText(), env.sig(), name);
        }
        for (JsonNode c : vectors.get("verify")) {
            String name = c.get("name").asText();
            EventVerifier.Outcome got = run(vectors.get("responder"), c);
            JsonNode want = c.get("expected");
            if (want.get("refusal").isNull()) {
                assertNull(got.refusal(), name);
                assertEquals(want.get("event"), tree(got.event().toJson()), name);
            } else {
                assertEquals(want.get("refusal").asText(), got.refusal() == null ? null : got.refusal().name(),
                        name);
                assertNull(got.event(), name);
            }
        }
    }

    /** The exact bytes the writer puts in the file: indented JSON and a final newline. */
    static byte[] render(JsonNode built) throws IOException {
        byte[] json = MAPPER.copy().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsBytes(built);
        byte[] out = Arrays.copyOf(json, json.length + 1);
        out[json.length] = '\n';
        return out;
    }

    /** The committed file's bytes, found by walking up from the working directory as {@link Vectors} does. */
    static byte[] loadBytes(String name) throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/" + name);
            if (Files.isRegularFile(candidate)) {
                return Files.readAllBytes(candidate);
            }
        }
        throw new IllegalStateException("spec/vectors/" + name + " not found above " + dir);
    }

    @Test
    @EnabledIfSystemProperty(named = "paztport.exportEventVectors", matches = "true")
    void export() throws IOException {
        Path file = Path.of(System.getProperty("vectors.out", "target/events.json"));
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, render(build()));
    }
}
