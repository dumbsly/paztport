// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package exact compares differences of protocol times and limits exactly. Go's int64 subtraction wraps,
// so a clock, a ts or a window at either end of int64 could make a difference past every limit look
// within one. Every check on the difference of two times goes through AtMost, which never wraps.
package exact
