// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"bytes"
	"errors"
	"slices"
	"sync"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// ErrNotVerified is Begin's refusal of a request whose chain did not pass the live order at this hop: an
// origin's, one served by a hop that is off or has no verifier, one that failed in audit mode, and work
// outside any request. Nothing is signed or sent for it, the handshake included.
var ErrNotVerified = errors.New("paztport boundary: the request's chain did not pass the live order here, " +
	"so nothing is signed or sent")

var (
	errFinished = errors.New("paztport boundary: the exchange has ended")
	errNotBegun = errors.New("paztport boundary: the exchange was not begun by Egress.Begin")
	errCall     = errors.New("paztport boundary: a call with no answer is not retried, so it has no NoAnswer")
)

// contentType is the header every step is sent with: a handshake's request and a call are both JSON.
var contentType = wire.Header{Name: "Content-Type", Value: wire.ContentType}

// idLength is the length of a session id's bytes: it is the base64url of a SHA-256.
const idLength = 32

// Config is an egress's configuration: its own stamper, proof bundle and policy material, the partner it
// calls and the partner's pinned policy key, its boundary key, how long it keeps a session no call uses,
// and its clock. Every member is required. New refuses a configuration that lacks one of the settings it
// names; the material is the partner's to judge, in the handshake and on each call.
type Config struct {
	// Stamper is the egress service's stamper. Its Svc and Inst are the boundary stamp's, its key signs
	// it, a key the egress's signed keyring holds for Svc, and its clock dates it.
	Stamper *stamp.Stamper
	// Bundle is the egress's proof bundle, which must hold the proof for the route <Svc>/<Partner>: a
	// call in an attested session sends it, and a partner refuses a call without it.
	Bundle policy.ProofBundle
	// Root and Keyring are the egress's own signed root and keyring, which every handshake presents.
	Root    policy.Root
	Keyring policy.KeyringFile
	// PolicyKey is the egress's own policy public key, as base64url SubjectPublicKeyInfo: the key the
	// partner pinned.
	PolicyKey string
	// Partner is the partner's entry service, from this side's configuration: the receiver of every
	// boundary stamp, the service whose key a handshake's reply must be signed by, and the source,
	// "http:<Partner>", of every answer the partner gives.
	Partner string
	// PartnerPolicyKey is the partner's policy public key, as base64url SubjectPublicKeyInfo, pinned out of
	// band: a reply is checked against it.
	PartnerPolicyKey string
	// BoundaryKey is the egress's boundary key, influence.KeyLength bytes, which salts the commitments it
	// sends and never leaves the sender (see influence.LoadBoundaryKey). New keeps its own copy.
	BoundaryKey []byte
	// IdleMs is how long, in milliseconds, a session no call has used is kept: the next call after it opens
	// a new one. It must be positive. The spec does not set it; it should be below the partner's own.
	IdleMs int64
	// Now is the egress's clock, in milliseconds since the Unix epoch: it ages a session and is the time a
	// handshake's reply is judged at. It must be safe for concurrent use.
	Now func() int64
}

// Egress is an organisation's way out to one partner: it keeps the session open with that partner, which
// every call shares, and makes each call's exchange. It sends nothing itself.
//
// An Egress is safe for concurrent use: one mutex guards its session, and it is never held while the
// embedder sends. Exchanges that find no session open each run their own handshake, and the session that
// lands last is the one kept; each such exchange still makes its call in the session its own handshake
// opened, which the partner keeps alongside the others.
type Egress struct {
	cfg Config

	mu      sync.Mutex
	current *partnerSession
}

// partnerSession is a session open with the partner: its id and whether it is attested, both fixed once
// it is opened, and when a call last took it, which only the Egress's mutex guards.
type partnerSession struct {
	id       string
	attested bool
	lastUsed int64
}

// New returns an egress, with no session open yet, configured by its own copy of cfg. It refuses a
// configuration with no stamper or one whose Svc is empty, no partner, no partner policy key or own policy
// key, a boundary key that is not influence.KeyLength bytes, an IdleMs that is not positive, or no clock.
func New(cfg Config) (*Egress, error) {
	switch {
	case cfg.Stamper == nil || cfg.Stamper.Svc == "":
		return nil, errors.New("paztport boundary: Config.Stamper must name the egress service")
	case cfg.Partner == "":
		return nil, errors.New("paztport boundary: Config.Partner must name the partner's entry service")
	case cfg.PartnerPolicyKey == "":
		return nil, errors.New("paztport boundary: Config.PartnerPolicyKey must be the partner's pinned policy key")
	case cfg.PolicyKey == "":
		return nil, errors.New("paztport boundary: Config.PolicyKey must be the egress's own policy key")
	case len(cfg.BoundaryKey) != influence.KeyLength:
		return nil, errors.New("paztport boundary: Config.BoundaryKey must be 32 bytes")
	case cfg.IdleMs < 1:
		return nil, errors.New("paztport boundary: Config.IdleMs must be positive")
	case cfg.Now == nil:
		return nil, errors.New("paztport boundary: Config.Now must be a clock")
	}
	cfg.BoundaryKey = bytes.Clone(cfg.BoundaryKey)
	return &Egress{cfg: cfg}, nil
}

// Step is one POST the embedder sends to the partner, then feeds the answer back to its Exchange: a
// handshake's request, to wire.SessionPath, or the call itself.
type Step struct {
	// Path is the request target, exactly as it is to be sent: wire.SessionPath for a handshake, and the
	// path Begin was given for the call.
	Path string
	// Body is the request's body, whole.
	Body []byte
	// Headers are the headers to send, in order: Content-Type, then for the call X-Path-Session, and in an
	// attested session X-Path-Chain, X-Path-Proof when the bundle holds the route's proof, and
	// X-Path-Influence when the call carries influence.
	Headers []wire.Header
	// Originals are the call's influence, normalised, and Sent the blinded entries it carries in their
	// place, in an attested session's call only; both are nil otherwise. The embedder keeps them under the
	// request's rid and the partner's entry service before it sends the call, so that it can later open
	// any entry it sent (see influence.Opening and influence.Salt); if it cannot keep them, it must not
	// send the call.
	Originals, Sent []influence.Entry
}

// Outcome is how an exchange ended.
type Outcome struct {
	// Status and Body are the partner's answer to the call; both are zero when the exchange Failed.
	Status int
	Body   []byte
	// Attested reports whether the call went out in an attested session, stamped and carrying the blinded
	// influence; an unsafe session's call carries only the session id.
	Attested bool
	// Influence is the request's influence after the exchange: the influence Begin was given, then one
	// local-untrusted entry for the partner's answer, its src "http:<Partner>" and its h the answer's
	// wire.ResultHash. The partner does not attest what it answers, so its answer counts as untrusted
	// content. When the exchange Failed, it is the influence Begin was given.
	Influence []influence.Entry
	// Failed reports that no session could be opened, so nothing of the call was sent.
	Failed bool
}

// The phases of an exchange: which step it is waiting for the answer to.
type phase int

const (
	phaseFull phase = iota
	phaseReplacement
	phaseCall
	phaseDone
)

// Exchange is one call through the egress: the handshake when no session is open, then the call itself.
// The embedder sends each Step it is given and passes the answer to Answer, until Answer reports that the
// exchange has ended; Result then gives its Outcome. An Exchange is driven by one goroutine at a time.
type Exchange struct {
	e       *Egress
	inbound stamp.Chain
	infl    []influence.Entry
	path    string
	body    []byte
	bind    string
	phase   phase
	req     session.Request
	sess    *partnerSession
	outcome Outcome
}

// Begin begins the call that POSTs body to path at the partner, for the request a accepted, whose
// influence so far is infl, and returns its exchange and the first step to send: the call itself, in the
// session open with the partner, or, when none is, the handshake that opens one. path is the request
// target exactly as it is to be sent, the raw path and query, which the call's binding covers. Neither infl
// nor body is changed or kept by reference.
//
// Begin refuses, with ErrNotVerified, a request whose chain did not pass the live order at this hop: the
// boundary stamp vouches for the request that led to it, so a hop that did not verify it signs nothing,
// and sends nothing, the handshake included. It also refuses a path that is not valid UTF-8, which has no
// binding, and a call it cannot stamp, such as one whose influence the boundary key cannot blind. A
// refusal comes with no exchange and nothing to send.
//
// A session no call has used for Config.IdleMs is dropped here, and the call opens a new one.
func (e *Egress) Begin(
	a paztporthttp.Accepted, infl []influence.Entry, path string, body []byte,
) (*Exchange, Step, error) {
	if !a.Verified || len(a.Inbound) == 0 {
		return nil, Step{}, ErrNotVerified
	}
	bind, err := wire.Bind("POST", path, body)
	if err != nil {
		return nil, Step{}, err
	}
	x := &Exchange{
		e: e, inbound: slices.Clone(a.Inbound), infl: slices.Clone(infl), path: path, body: bytes.Clone(body),
		bind: bind,
	}
	if s := e.take(); s != nil {
		x.sess = s
		step, err := x.call()
		if err != nil {
			return nil, Step{}, err
		}
		x.phase = phaseCall
		return x, step, nil
	}
	step, err := x.handshake(&e.cfg.Root)
	if err != nil {
		return nil, Step{}, err
	}
	return x, step, nil
}

// Answer takes the partner's answer, its status and body whole, to the step last given, and returns the
// next step to send and true, or false when the exchange has ended and Result gives its outcome. In order:
//
//   - the full handshake's answer opens the session when it is a 200 whose body the client's check
//     (session.CheckReply, against Config.PartnerPolicyKey and Config.Partner, at Config.Now) finds
//     genuine, attested or unsafe as it says; any other answer may mean the partner opened a session this
//     side cannot use, so the next step is the replacement, the same request with no root and a fresh
//     nonce;
//   - the replacement's answer opens an unsafe session when it is a 200 whose body reads as a reply,
//     whatever status the reply gives, since nothing is signed or carried in it; any other answer ends
//     the exchange Failed, with nothing of the call sent;
//   - a reply's sess becomes the call's X-Path-Session only when it has the form every session id has,
//     canonical base64url of 32 bytes; any other ends the exchange Failed;
//   - the call's answer ends the exchange. A 403 whose body is exactly the wire bytes of the refusal
//     {"reason":"SESSION_UNKNOWN"} means the partner no longer knows the session, so the session the call
//     was made in is dropped, and the next call opens a new one; the refused call is not retried, since it
//     may have changed something. Any other answer keeps the session.
//
// Answer never panics on any status or body. Its error is for an exchange that has ended or was not
// begun by Begin, and for a handshake or call that cannot be built once the partner has answered, such as
// a call that cannot be stamped in the session just opened, which ends the exchange Failed.
func (x *Exchange) Answer(status int, body []byte) (Step, bool, error) {
	if x.e == nil {
		return Step{}, false, errNotBegun
	}
	switch x.phase {
	case phaseFull:
		if status == 200 {
			switch session.CheckReply(body, x.req, x.e.cfg.PartnerPolicyKey, x.e.cfg.Partner, x.e.cfg.Now()) {
			case session.Attested:
				return x.open(body, true)
			case session.Unsafe:
				return x.open(body, false)
			}
		}
		return x.next(x.handshake(nil))
	case phaseReplacement:
		if status != 200 {
			return x.fail()
		}
		return x.open(body, false)
	case phaseCall:
		return x.finish(status, body)
	default:
		return Step{}, false, errFinished
	}
}

// NoAnswer says the step last given had no answer: it was not sent, or nothing came back within the
// embedder's timeout. A handshake with no answer is taken as one whose reply this side cannot use: the
// full handshake is followed by the replacement, and the replacement ends the exchange Failed.
//
// A call with no answer is not the egress's to settle: the partner may have taken it, so it is not
// retried, and NoAnswer refuses it and leaves the exchange as it is. The embedder then fails the request,
// whose influence is still the one it passed to Begin, and the session is kept.
func (x *Exchange) NoAnswer() (Step, bool, error) {
	if x.e == nil {
		return Step{}, false, errNotBegun
	}
	switch x.phase {
	case phaseFull:
		return x.next(x.handshake(nil))
	case phaseReplacement:
		return x.fail()
	case phaseCall:
		return Step{}, false, errCall
	default:
		return Step{}, false, errFinished
	}
}

// Result returns the exchange's outcome, and true once it has ended; until then, the zero Outcome and
// false.
func (x *Exchange) Result() (Outcome, bool) {
	if x.phase != phaseDone {
		return Outcome{}, false
	}
	return x.outcome, true
}

// handshake returns the step that sends a handshake presenting root, the egress's own or nil for the
// replacement, with the egress's policy key, its keyring and a fresh nonce.
func (x *Exchange) handshake(root *policy.Root) (Step, error) {
	cfg := &x.e.cfg
	req := session.NewRequest(root, cfg.PolicyKey, cfg.Keyring, session.NewNonce())
	b, err := req.Wire()
	if err != nil {
		return Step{}, err
	}
	x.req = req
	if root == nil {
		x.phase = phaseReplacement
	}
	return Step{Path: wire.SessionPath, Body: b, Headers: []wire.Header{contentType}}, nil
}

// next returns the step a phase change gave, or ends the exchange Failed on its error.
func (x *Exchange) next(step Step, err error) (Step, bool, error) {
	if err != nil {
		_, _, _ = x.fail()
		return Step{}, false, err
	}
	return step, true, nil
}

// open opens the session the reply body issues, attested or unsafe, and returns the call. A body that is
// not a reply, or whose sess is not in a session id's form, ends the exchange Failed.
func (x *Exchange) open(body []byte, attested bool) (Step, bool, error) {
	reply, err := session.ParseReply(body)
	if err != nil || !isSessionID(reply.Sess) {
		return x.fail()
	}
	x.sess = x.e.install(reply.Sess, attested)
	x.phase = phaseCall
	return x.next(x.call())
}

// call returns the call's step in the exchange's session. In an attested session it blinds the influence,
// signs the boundary stamp over the request and the entries sent, and carries both with the route's proof;
// in an unsafe one it carries the session id alone.
func (x *Exchange) call() (Step, error) {
	cfg := &x.e.cfg
	step := Step{
		Path: x.path, Body: x.body,
		Headers: []wire.Header{contentType, {Name: wire.Session, Value: x.sess.id}},
	}
	if !x.sess.attested {
		return step, nil
	}
	sent, err := influence.Reduce(x.infl, cfg.BoundaryKey, x.inbound[0].RID, cfg.Partner, cfg.Stamper.Svc)
	if err != nil {
		return Step{}, err
	}
	chain, proof, err := cfg.Stamper.Boundary(x.inbound, x.sess.id, cfg.Partner, x.bind, sent, cfg.Bundle)
	if err != nil {
		return Step{}, err
	}
	tok, err := wire.EncodeChain(chain)
	if err != nil {
		return Step{}, err
	}
	step.Headers = append(step.Headers, wire.Header{Name: wire.Chain, Value: tok})
	if proof != nil {
		if tok, err = wire.EncodeProof(*proof); err != nil {
			return Step{}, err
		}
		step.Headers = append(step.Headers, wire.Header{Name: wire.Proof, Value: tok})
	}
	tok, ok, err := wire.EncodeInfluence(sent)
	if err != nil {
		return Step{}, err
	}
	if ok {
		step.Headers = append(step.Headers, wire.Header{Name: wire.Influence, Value: tok})
	}
	step.Originals, step.Sent = influence.Normalise(x.infl), sent
	return step, nil
}

// finish ends the exchange with the partner's answer to the call, and drops the call's session when the
// answer is the refusal SESSION_UNKNOWN.
func (x *Exchange) finish(status int, body []byte) (Step, bool, error) {
	answer := influence.Entry{
		Class: influence.LocalUntrusted, Src: "http:" + x.e.cfg.Partner, H: wire.ResultHash(status, body),
	}
	x.outcome = Outcome{
		Status: status, Body: bytes.Clone(body), Attested: x.sess.attested,
		Influence: slices.Concat(x.infl, []influence.Entry{answer}),
	}
	x.phase = phaseDone
	if status == 403 && refusalReason(body) == reason.SessionUnknown {
		x.e.drop(x.sess)
	}
	return Step{}, false, nil
}

// fail ends the exchange Failed: no session was opened, and nothing of the call was sent.
func (x *Exchange) fail() (Step, bool, error) {
	x.outcome = Outcome{Influence: slices.Clone(x.infl), Failed: true}
	x.phase = phaseDone
	return Step{}, false, nil
}

// take returns the session open with the partner, marked as used now, or nil when none is; a session no
// call has used for IdleMs is dropped first.
func (e *Egress) take() *partnerSession {
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.current
	if s == nil {
		return nil
	}
	if !exact.AtMost(now, s.lastUsed, e.cfg.IdleMs-1) {
		e.current = nil
		return nil
	}
	// A clock read earlier, by a call that took the lock later, never moves the time back.
	s.lastUsed = max(s.lastUsed, now)
	return s
}

// install makes the session id, attested or not, the one open with the partner, used now, and returns it.
func (e *Egress) install(id string, attested bool) *partnerSession {
	s := &partnerSession{id: id, attested: attested, lastUsed: e.cfg.Now()}
	e.mu.Lock()
	e.current = s
	e.mu.Unlock()
	return s
}

// drop drops s when it is still the session open with the partner, and leaves alone one opened since.
func (e *Egress) drop(s *partnerSession) {
	e.mu.Lock()
	if e.current == s {
		e.current = nil
	}
	e.mu.Unlock()
}

// isSessionID reports whether id has a session id's form: canonical base64url of 32 bytes.
func isSessionID(id string) bool {
	b, err := b64.Decode(id)
	return err == nil && len(b) == idLength
}

// refusalReason returns the code of a refusal body, read as wire bytes as {"reason":"<code>"} and nothing
// more, or "" for any other body, which gives no reason.
func refusalReason(body []byte) reason.Code {
	v, err := json.ReadWire(body)
	if err != nil || json.Exactly(v, []string{"reason"}, nil) != nil {
		return ""
	}
	s, err := json.String(v, "reason")
	if err != nil {
		return ""
	}
	return reason.Code(s)
}
