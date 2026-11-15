// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package stamp makes and reads stamps: each hop's signed statement that it handled a request, and for
// whom, at protocol version [Version].
//
// A [Stamp] names its signer, the request (rid), the session, the receiver it was handed to (rcv), what
// was sent (bind, a binding such as [PromptBinding] or [ResponseBinding]) and the block of claims its signer
// attaches (ext, the block's commitment). [Sign] signs it with the signer's Ed25519 key, over the bytes
//
//	utf8("paztport-stamp\n") || utf8(JCS(the stamp without sig))
//
// that [Stamp.SigningBytes] returns. JCS escapes every string, so no field needs a rule against a delimiter,
// and two different stamps never share signed bytes.
//
// A [Block] is what one signer attaches: items under extension names, each item the JCS text of one JSON value,
// and the extensions it requires of the next hop. The core never reads an item. The empty block, the zero Block,
// commits to "". A chain's blocks, one per stamp, travel as [Blocks] beside it.
//
// A [Chain] is the stamps of one request, origin first: each stamp's prev is the sig of the one before,
// so no stamp can be dropped, reordered or inserted without breaking a signature or a link. A chain
// travels as its canonical (JCS) bytes, or as a token, their base64url. [ParseChain] and [ReadChain] read
// it strictly, as a verifier's check 1, and answer with a [reason.Code], never an error: CHAIN_MISSING for
// anything that is not a non-empty array of well-formed version 4 stamps. Whether the stamps are genuine, and
// whether the blocks match them, is the verifier's to check.
//
// A [Stamper] makes one service's stamps, each committing to the block it is given: it starts a chain at an
// origin and appends to the one it received elsewhere, stamps the call that leaves the organisation for a
// partner, and stamps responses. It takes its clock and its source of request ids as functions, so that a
// caller decides both.
package stamp
