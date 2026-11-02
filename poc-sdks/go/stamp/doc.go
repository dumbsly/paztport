// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package stamp makes and reads stamps: each hop's signed statement that it handled a request, and for
// whom.
//
// A [Stamp] names its signer, the request (rid), the session, the receiver it was handed to (rcv), what
// was sent (bind, a binding such as [PromptBinding] or [ResponseBinding]) and the influence that shaped
// it (infl). [Sign] signs its fields with the signer's Ed25519 key, over the bytes
//
//	utf8("3|" svc "|" inst "|" rid "|" ts "|" sess "|" rcv "|" bind "|" infl "|" prev)
//
// that [Stamp.SigningBytes] returns. A field holding "|" would let two stamps share those bytes, so
// nothing signs one, and a reader reports one as BAD_SIGNATURE.
//
// A [Chain] is the stamps of one request, origin first: each stamp's prev is the sig of the one before,
// so no stamp can be dropped, reordered or inserted without breaking a signature or a link. A chain
// travels as its canonical (JCS) bytes, or as a token, their base64url. [ParseChain] and [ReadChain] read
// it strictly, as the first two checks of a verifier, and answer with a [reason.Code], never an error:
// CHAIN_MISSING for anything that is not a non-empty array of well-formed stamps, then BAD_SIGNATURE for
// a delimiter in a signed field. Whether the stamps are genuine is the verifier's to check.
//
// A [Stamper] makes one service's stamps: it starts a chain at an origin and appends to the one it
// received elsewhere, stamps the call that leaves the organisation for a partner, and stamps responses.
// It takes its clock and its source of request ids as functions, so that a caller decides both.
package stamp
