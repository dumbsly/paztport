// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import "github.com/dumbsly/paztport/poc-sdks/go/verify"

// RequestNonceKey returns a request's key in the receiver's replay cache (verification.md, Freshness and
// replay): the JCS text of [rid, lastSvc, lastRcv, "req"], or of [rid, lastSvc, lastRcv, keyValue, "req"] when
// keyValue is not "". rid is the origin's, lastSvc the chain's last signer and lastRcv the receiver its last
// stamp names, with the operation when it names one; keyValue is the call's key value where that operation
// declares a key. A service so calls a receiver, or an operation of it, once per request tree, and a keyed
// operation once for each key value.
//
// It panics on a part that is not valid UTF-8, which has no text to key: a program fault, since every part is a
// field of a stamp the chain reader admitted, which is valid UTF-8, or a key value, which is unreserved ASCII.
func RequestNonceKey(rid, lastSvc, lastRcv, keyValue string) string {
	return must(requestNonceKey(rid, lastSvc, lastRcv, keyValue))
}

// ResponseNonceKey returns a response's key in the caller's replay cache (verification.md, Freshness and
// replay): the JCS text of [rid, lastRcv, "resp"], or of [rid, lastRcv, keyValue, "resp"] when keyValue is not
// "", lastRcv being the receiver the sent chain's last stamp names, with the operation when it names one. It
// panics as [RequestNonceKey] does.
func ResponseNonceKey(rid, lastRcv, keyValue string) string {
	return must(responseNonceKey(rid, lastRcv, keyValue))
}

func requestNonceKey(rid, lastSvc, lastRcv, keyValue string) (string, error) {
	if keyValue == "" {
		return verify.NonceKey(rid, lastSvc, lastRcv, "req")
	}
	return verify.NonceKey(rid, lastSvc, lastRcv, keyValue, "req")
}

func responseNonceKey(rid, lastRcv, keyValue string) (string, error) {
	if keyValue == "" {
		return verify.NonceKey(rid, lastRcv, "resp")
	}
	return verify.NonceKey(rid, lastRcv, keyValue, "resp")
}

// must returns key, and panics on err: see RequestNonceKey for why only a program fault reaches it.
func must(key string, err error) string {
	if err != nil {
		panic("paztport wire: no nonce key: " + err.Error())
	}
	return key
}
