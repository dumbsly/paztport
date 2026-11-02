// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package json reads and writes the protocol's own objects: stamps and chains, proofs, influence entries,
// keyrings, roots, reply certificates, session requests and replies, events and the rest. Content the
// protocol only hashes is not read here.
//
// A reader takes bytes through the spec's reading steps and refuses them at the first step that fails:
//
//  1. size: the bytes are within their limit, checked before anything is parsed;
//  2. parse: the bytes are one JSON value under RFC 8259's grammar, within I-JSON (RFC 7493), in strict
//     UTF-8 (RFC 3629), nested no deeper than [MaxDepth], with no repeated member name, no lone surrogate,
//     no noncharacter and no number but a protocol integer;
//  3. canonical: wire bytes are exactly the canonical bytes of the value parsed (RFC 8785, JCS);
//  4. schema: the value is the object its section defines.
//
// [ReadWire] and [ReadToken] take steps 1 to 3, [ReadFile] steps 1 and 2. Step 4 is each object's own, and
// its readers build it from the helpers [Exactly], [Field], [String], [Integer], [Bool] and [StringMap].
//
// A writer writes a [Value] as its canonical bytes ([Wire], [Token]) or in the one file form ([File]), and
// refuses, whole, any value a reader would refuse.
//
// Every refusal is an [*Error] naming its step, the rule that refused and, where there is one, the byte
// offset. No error quotes the input, and nothing here panics, whatever the input.
package json
