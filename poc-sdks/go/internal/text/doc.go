// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package text holds the checks the protocol makes of its strings, and the trim its key files take.
//
// The spec refuses text with no UTF-8 form, such as a lone surrogate, wherever a string is hashed, signed or
// written. A Go string is bytes, so its form of that rule is that the bytes are valid UTF-8, which a
// surrogate's three-byte encoding is not. Noncharacters are valid UTF-8 and are checked separately.
package text
