// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package b64 is the protocol's base64url: the url-safe alphabet of RFC 4648 §5, unpadded, read strictly.
//
// Every value the protocol carries as base64url (tokens, signatures, nonces, keys, salts, roots, siblings,
// payloads) has exactly one accepted text, the canonical encoding of RFC 4648 §3.5, so a value can be
// compared as text and no two texts decode to the same bytes.
package b64
