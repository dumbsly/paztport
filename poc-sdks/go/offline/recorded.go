// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline

import (
	"maps"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
)

// RecordedSession is a handshake read back from a record set, and what it gives the records that rely on
// it: whether it opened an attested session at a given time and at all, the session id its calls carry,
// and the limit on a response recorded in it. Use Record to read one. The zero RecordedSession is a
// handshake of which nothing was recorded, as Record(nil, nil, "", "") reads, and opened no attested
// session.
//
// Its limits are the certificate's notAfter, in the entry-key form, and the notAfter of each root and
// keyring, the client's and the server's. The reply's windows are read before the signatures over them are
// checked, but none counts unless the session is attested at it, which checks each signature. A response
// is limited only by the server's root and, in the entry-key form, its keyring: the client's windows and
// the certificate do not limit it.
type RecordedSession struct {
	reply            []byte
	request          session.Request
	requestRead      bool
	pin, serverEntry string
	sess             string
	attested         bool
	responseLimit    *int64 // the earliest response window the reply holds, or nil for none
}

// Record reads a recorded handshake: request and reply, the wire bytes of each message as recorded, pin,
// the server policy key the client pinned, as base64url SubjectPublicKeyInfo, and serverEntry, the server's
// entry service from the verifier's own configuration, never from the record. A request or reply that does
// not read is a handshake that opened no attested session. Record keeps its own copy of reply, and never
// panics.
//
// It reads the reply's windows and session id from its value whenever the reply reads as wire bytes,
// whether or not it is a well-formed reply. Each counts only for a session that is attested, which
// AttestedAt judges from the reply whole: a reader gives a record relying on a session that is not
// attested no result.
func Record(request, reply []byte, pin, serverEntry string) RecordedSession {
	s := RecordedSession{reply: slices.Clone(reply), pin: pin, serverEntry: serverEntry}
	req, err := session.ParseRequest(request)
	if err == nil {
		s.request, s.requestRead = req, true
	}

	var tree json.Value
	if v, err := json.ReadWire(reply); err == nil {
		tree = v
	}
	id, _ := json.Field(tree, "sess")
	s.sess = id.Str()
	serverRoot := window(tree, "serverRoot", "notAfter")
	serverKeyring := window(tree, "serverKeyringNotAfter")
	cert := window(tree, "serverReplyCert", "notAfter")

	limits := []*int64{cert, serverRoot, serverKeyring}
	if s.requestRead {
		limits = append(limits, &s.request.ClientKeyringNotAfter)
		if s.request.ClientRoot != nil {
			limits = append(limits, &s.request.ClientRoot.NotAfter)
		}
	}
	// With no limit at all the request did not read, so the session is attested at no time.
	at, _ := earliest(limits...)
	s.attested = s.AttestedAt(at)

	responseLimits := []*int64{serverRoot}
	if _, entryKeyForm := json.Field(tree, "serverKeyringSig"); entryKeyForm {
		responseLimits = append(responseLimits, serverKeyring)
	}
	if least, ok := earliest(responseLimits...); ok {
		s.responseLimit = &least
	}
	return s
}

// Attested reports whether the handshake opened an attested session at all, judged at the earliest of its
// limits, since each is an upper bound. A handshake with no limit at all has a request that does not
// read, so it is attested at no time.
func (s RecordedSession) Attested() bool {
	return s.attested
}

// AttestedAt reports whether the handshake opened an attested session judged at t: a time the client
// signed, a call's last stamp's ts, never one read from the handshake record. See session.AttestedOffline,
// which judges it.
func (s RecordedSession) AttestedAt(t int64) bool {
	return s.requestRead && session.AttestedOffline(s.reply, s.request, s.pin, s.serverEntry, t)
}

// Sess returns the session id the reply names, which the calls recorded in the session are checked
// against (Config.Sess), so it is the id of the reply this session judged. It is "" when the reply holds no
// string there. A reader relies on it only for a session that is Attested.
func (s RecordedSession) Sess() string {
	return s.sess
}

// ResponseNotAfter returns the policyNotAfter a response recorded in the session is checked with: the
// earlier of the server root's notAfter and, in the entry-key form, the server keyring's. It is read from
// the reply's windows whether or not the session is attested. When the reply holds neither window, as a
// reply with no server root does, it is 2^53 - 1; such a reply opens no attested session. The spec leaves
// that case open, and this is the Java SDK's choice.
func (s RecordedSession) ResponseNotAfter() int64 {
	if s.responseLimit == nil {
		return json.MaxSafe
	}
	return *s.responseLimit
}

// Request returns the handshake's request, and whether it read. The calls recorded in the session are
// checked against its client keyring and root. The request returned is a copy, so changing it changes
// nothing here.
func (s RecordedSession) Request() (session.Request, bool) {
	if !s.requestRead {
		return session.Request{}, false
	}
	r := s.request
	r.ClientKeyring = maps.Clone(r.ClientKeyring)
	if r.ClientRoot != nil {
		root := *r.ClientRoot
		r.ClientRoot = &root
	}
	return r, true
}

// window returns the integer at path in o, each name in it a member of the object before, or nil, a limit
// the record lacks. A value that is not an object has no members.
func window(o json.Value, path ...string) *int64 {
	for _, name := range path {
		var ok bool
		if o, ok = json.Field(o, name); !ok {
			return nil
		}
	}
	if o.Kind() != json.KindInt {
		return nil
	}
	n := o.Int()
	return &n
}

// earliest returns the least of the limits that are set, and whether any is.
func earliest(limits ...*int64) (int64, bool) {
	var least int64
	found := false
	for _, l := range limits {
		if l != nil && (!found || *l < least) {
			least, found = *l, true
		}
	}
	return least, found
}
