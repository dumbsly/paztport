// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The byte forms on the wire: base64url, RFC 8785 canonical JSON, and the check that keeps a lone surrogate out
 * of anything signed. Each refuses what it cannot represent exactly, so every SDK signs and hashes the same bytes.
 *
 * <p>JSON crosses the SDK's public API by one rule, so that no public signature names a JSON library and an
 * application keeps whichever one its framework brings:
 * <ul>
 * <li>A value type writes its wire form with {@code String toJson()} and reads it with
 * {@code static T parse(String json)} on the type itself, for example {@code KeyringFile.parse},
 * {@code SessionRequest.parse} and {@code SessionReply.parse}. A reader throws {@link IllegalArgumentException}
 * for anything malformed, text that is not exactly one JSON value included.
 * <li>Where a reader takes a whole HTTP body, it also takes the body's bytes as they arrived: {@code parse(byte[])},
 * which reads them as the message's wire bytes, exactly its JCS bytes in UTF-8, so UTF-16, a byte order mark or a
 * newline after them is refused. The SDK reads two such bodies: the session request, with
 * {@code SessionRequest.parse(byte[])}, and the session reply, with {@code SessionReply.parse(byte[])}, which
 * {@code Sessions.checkReply(byte[], ...)} reads it with before checking it.
 * <li>A list carried on the wire is read and written by the class that owns it, named for what it reads:
 * {@code Influence.parse} and {@code Influence.toJson}, {@code ContentLabel.parseAll} and
 * {@code ContentLabel.toJson(List)}, {@code Chains.parse} and {@code Chains.toJson}. {@code Chains.parse} returns
 * its failure as a reason rather than throwing, since reading a chain is the verifier's first check.
 * <li>A message judged as received has no reader of its own. A responder event is one:
 * {@code EventVerifier.accept} takes the body's text, and a sender writes it with {@code ResponderEvent.toJson} and
 * {@code EventEnvelope.toJson}.
 * <li>The verifiers take the stamps, influence and proof as the JSON text received, and read each from its bytes
 * at the check that needs it, so text that is not the JCS text of what it holds is a rejection there like any
 * other malformed input.
 * <li>{@link Jcs} canonicalises JSON text.
 * </ul>
 */
package org.paztport.core.encoding;
