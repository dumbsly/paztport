// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package boundary_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/boundary"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestEgressVectors replays the rules' egress cases: each enters its inbound request at the egress's
// receiver, then sends each of its posts through the egress to a scripted partner, feeding the partner's
// answers back until the exchange ends. It compares each post's outcome, everything the partner received,
// in order, and the request's influence afterwards, normalised; and every stamp the partner received must
// verify under the key the egress's keyring holds for its signer.
func TestEgressVectors(t *testing.T) {
	cases := vectors.Rules(t).Get("egress")
	if cases.Len() != 12 {
		t.Fatalf("the rules have %d egress cases, want 12", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			e, a, partner := egressCase(t, c)
			infl := a.Influence
			var posts []string
			c.Get("posts").Each(func(_ string, p vectors.Node) {
				var out string
				out, infl = post(t, e, a, infl, p.Get("path").Str(), unhex(t, p.Get("body")), partner)
				posts = append(posts, out)
			})
			e2 := c.Get("expected")
			var wantPosts []string
			e2.Get("posts").Each(func(_ string, p vectors.Node) { wantPosts = append(wantPosts, expectedPost(p)) })
			if !slices.Equal(posts, wantPosts) {
				t.Errorf("posts:\ngot  %q\nwant %q", posts, wantPosts)
			}
			got := partner.render(t)
			var want []string
			e2.Get("received").Each(func(_ string, r vectors.Node) { want = append(want, expectedReceived(t, r)) })
			if !slices.Equal(got, want) {
				t.Errorf("received:\ngot  %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
			}
			if got, want := influence.Normalise(infl), entries(e2.Get("influence")); !slices.Equal(got, want) {
				t.Errorf("influence:\ngot  %+v\nwant %+v", got, want)
			}
		})
	})
}

// post sends one post through e for the request a accepted, under its influence infl so far, answering
// each step from partner, and returns the outcome, as an egress case writes it, and the influence after.
func post(t testing.TB, e *boundary.Egress, a paztporthttp.Accepted, infl []influence.Entry, path string,
	body []byte, partner *scriptedPartner,
) (string, []influence.Entry) {
	t.Helper()
	x, step, err := e.Begin(a, infl, path, body)
	if err != nil {
		if !errors.Is(err, boundary.ErrNotVerified) || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Fatalf("Begin = %v, %+v, %v; want ErrNotVerified and nothing to send, or no error", x, step, err)
		}
		return "refused", infl
	}
	for more := true; more; {
		status, answer := partner.serve(t, step)
		step, more, err = x.Answer(status, answer)
		if err != nil {
			t.Fatalf("Answer: %v", err)
		}
	}
	out, ok := x.Result()
	if !ok {
		t.Fatal("Result: the exchange has not ended")
	}
	if out.Failed {
		if !slices.Equal(out.Influence, infl) {
			t.Fatalf("a failed exchange changed the influence to %+v", out.Influence)
		}
		return "failed", out.Influence
	}
	return fmt.Sprintf("answered %d attested=%v", out.Status, out.Attested), out.Influence
}

// expectedPost writes an expected post as post does.
func expectedPost(p vectors.Node) string {
	switch o := p.Get("outcome").Str(); o {
	case "answered":
		return fmt.Sprintf("answered %d attested=%v", p.Get("status").Int(), p.Get("attested").Bool())
	default:
		return o
	}
}

// egressCase returns case c's egress, configured from its egress member, the request its inbound
// member enters at the egress's receiver (the zero Accepted when it is null: no request at all), and its
// scripted partner.
func egressCase(t *testing.T, c vectors.Node) (*boundary.Egress, paztporthttp.Accepted, *scriptedPartner) {
	t.Helper()
	g := c.Get("egress")
	in := c.Get("inbound")
	// With no inbound, nothing is signed: the time is a fixed one, as any would do.
	now := int64(1767225600000)
	var a paztporthttp.Accepted
	if !in.IsNull() {
		now = in.Get("now").Int()
		a = acceptInbound(t, in)
	}
	e, err := boundary.New(egressConfig(t, g, func() int64 { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	script := c.Get("partnerScript")
	var calls []scriptedAnswer
	script.Get("calls").Each(func(_ string, a vectors.Node) {
		calls = append(calls, scriptedAnswer{status: int(a.Get("status").Int()), body: unhex(t, a.Get("body"))})
	})
	p := newScriptedPartner(t, g.Get("material").Str(), now,
		strs(script.Get("handshakes")), script.Get("replacement").Str(), calls...)
	return e, a, p
}

// egressConfig returns the configuration egress member g describes, its material read from its files'
// text by the SDK's own readers, its stamper and its own clock at now.
func egressConfig(t testing.TB, g vectors.Node, now func() int64) boundary.Config {
	t.Helper()
	svc := g.Get("svc").Str()
	priv, _ := vectors.RulesKey(t, svc)
	m := vectors.RulesMaterial(t, g.Get("material").Str())
	_, policyPub := vectors.RulesKey(t, m.PolicyKey)
	_, partnerPub := vectors.RulesKey(t, g.Get("partnerPolicyKey").Str())
	key, err := b64.Decode(g.Get("boundaryKey").Str())
	if err != nil {
		t.Fatalf("boundaryKey: %v", err)
	}
	return boundary.Config{
		Stamper: &stamp.Stamper{
			Svc: svc, Inst: g.Get("inst").Str(), Key: priv,
			NewRID: func() string { return "unused" }, Now: now,
		},
		Bundle:           bundleOf(t, g.Get("material").Str(), svc),
		Root:             rootOf(t, m),
		Keyring:          keyringOf(t, m),
		PolicyKey:        keys.EncodePublic(policyPub),
		Partner:          g.Get("partner").Str(),
		PartnerPolicyKey: keys.EncodePublic(partnerPub),
		BoundaryKey:      key,
		IdleMs:           g.Get("sessionIdleMs").Int(),
		Now:              now,
	}
}

// acceptInbound enters receiver case in's request at its service once, as the egress's own receiver,
// and returns what it accepted. The egress cases' requests are all served, never refused.
func acceptInbound(t testing.TB, in vectors.Node) paztporthttp.Accepted {
	t.Helper()
	s := in.Get("service")
	svc := s.Get("svc").Str()
	origin := s.Get("origin").Bool()
	now := in.Get("now").Int()
	priv, _ := vectors.RulesKey(t, svc)
	r := &paztporthttp.Receiver{
		Name: svc, Origin: origin,
		Stamper: &stamp.Stamper{
			Svc: svc, Inst: s.Get("inst").Str(), Key: priv, Origin: origin,
			NewRID: func() string { return "unused" }, Now: func() int64 { return now },
		},
	}
	if s.Get("verifier").Bool() {
		m := vectors.RulesMaterial(t, in.Get("material").Str())
		_, pub := vectors.RulesKey(t, m.PolicyKey)
		cfg, err := verify.Pinned(keyringOf(t, m), rootOf(t, m), keys.EncodePublic(pub), verify.Config{
			AllowedOrigins: strs(in.Get("allowedOrigins")),
			Nonces:         verify.NewMemoryNonceCache(in.Get("nonceTtlMs").Int()),
			Now:            func() int64 { return now },
			CallMaxAgeMs:   in.Get("callMaxAgeMs").Int(),
			RunMaxAgeMs:    in.Get("runMaxAgeMs").Int(),
		})
		if err != nil {
			t.Fatalf("Pinned: %v", err)
		}
		r.Verifier = verify.New(cfg)
	}
	if in.Get("spent").Len() != 0 || !in.Get("peer").IsNull() {
		t.Fatal("an egress case's inbound with spent nonces or a peer: the runner does not enter those")
	}
	req := in.Get("request")
	headers := req.Get("headers")
	lookup := func(name string) []string {
		var vs []string
		for _, h := range headers.Names() {
			if strings.EqualFold(h, name) {
				vs = append(vs, headers.Get(h).Str())
			}
		}
		return vs
	}
	inbound := paztporthttp.NewInboundRequest(req.Get("method").Str(), req.Get("target").Str(),
		unhex(t, req.Get("body")), lookup)
	a, err := r.Accept(t.Context(), inbound, nil, mode(t, in.Get("mode")))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if a.Refusal != nil {
		t.Fatalf("the egress's receiver refused the request: %d %s", a.Refusal.Status, a.Refusal.Body)
	}
	return a
}

// mode returns the mode n names: enforce, audit, off, or null for a service that verifies no requests.
func mode(t testing.TB, n vectors.Node) paztporthttp.Mode {
	t.Helper()
	if n.IsNull() {
		return paztporthttp.ModeNone
	}
	switch s := n.Str(); s {
	case "enforce", "audit", "off":
		return paztporthttp.ParseMode(s)
	default:
		t.Fatalf("the case's mode %q is none the rules name", s)
		return 0
	}
}

// The operations the scripted partner's unsafe replies list as switched off.
var unsafeDisabled = []string{"POST /refund", "GET /statements/{id}"}

// scriptedPartner is a partner reduced to a script, answering the steps an egress hands its embedder.
// Each handshake with a client root takes the next of handshakes: attested or unsafe, a genuine reply in
// the entry-key form from the psp material, whose status the partner's own session.Status gives with the
// shop's policy key pinned or not; notFound, a 404; wrongKey, a reply in the policy-key form signed by and
// naming stranger-policy. One with no client root is answered as replacement says, signed genuinely, its
// status as the script says whatever session.Status would give. Each call takes the next of calls. It
// records everything it receives and the session id each reply issued; anything the script has no answer
// for is answered 500 and fails the case. It is safe for concurrent use.
type scriptedPartner struct {
	mu          sync.Mutex
	handshakes  []string
	replacement string
	calls       []scriptedAnswer
	received    []receivedStep
	beyond      []string

	now        int64
	root       policy.Root
	keyring    policy.KeyringFile
	cert       policy.ReplyCert
	policyKey  string
	entryKey   ed25519.PrivateKey
	stranger   ed25519.PrivateKey
	strangerPK string
	clientPin  string
	// egressKeys are the egress material's service keys, under which each received stamp must verify.
	egressKeys map[string]string
	// sessFor, when set, gives the id a reply issues in place of the one the handshake derives.
	sessFor func(derived string) string
}

// scriptedAnswer is an answer to a call.
type scriptedAnswer struct {
	status int
	body   []byte
}

// receivedStep is one step the partner received: a handshake, with whether it carried a client root and
// the id its reply issued, or a call.
type receivedStep struct {
	step       boundary.Step
	handshake  bool
	clientRoot bool
	issued     string
}

// newScriptedPartner returns the partner whose script is handshakes, replacement and calls, at now, for
// an egress whose material is egressMaterial.
func newScriptedPartner(t testing.TB, egressMaterial string, now int64, handshakes []string, replacement string,
	calls ...scriptedAnswer,
) *scriptedPartner {
	t.Helper()
	psp := vectors.RulesMaterial(t, "psp")
	cert, err := policy.ParseReplyCertFile(psp.ReplyCert)
	if err != nil {
		t.Fatalf("ParseReplyCertFile: %v", err)
	}
	_, pspPub := vectors.RulesKey(t, psp.PolicyKey)
	entryKey, _ := vectors.RulesKey(t, psp.Entry)
	stranger, strangerPub := vectors.RulesKey(t, "stranger-policy")
	egress := vectors.RulesMaterial(t, egressMaterial)
	_, clientPub := vectors.RulesKey(t, egress.PolicyKey)
	p := &scriptedPartner{
		handshakes:  handshakes,
		replacement: replacement,
		calls:       calls,
		now:         now,
		root:        rootOf(t, psp),
		keyring:     keyringOf(t, psp),
		cert:        cert,
		policyKey:   keys.EncodePublic(pspPub),
		entryKey:    entryKey,
		stranger:    stranger,
		strangerPK:  keys.EncodePublic(strangerPub),
		clientPin:   keys.EncodePublic(clientPub),
		egressKeys:  keyringOf(t, egress).Services,
	}
	return p
}

// serve answers step s as the script says and records it.
func (p *scriptedPartner) serve(t testing.TB, s boundary.Step) (int, []byte) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.Path != wire.SessionPath {
		p.received = append(p.received, receivedStep{step: s})
		if len(p.calls) == 0 {
			p.beyond = append(p.beyond, "a call to "+s.Path)
			return 500, nil
		}
		a := p.calls[0]
		p.calls = p.calls[1:]
		return a.status, a.body
	}
	req, err := session.ParseRequest(s.Body)
	if err != nil {
		t.Errorf("a handshake's body is not a request's wire bytes: %v", err)
		return 400, nil
	}
	r := receivedStep{step: s, handshake: true, clientRoot: req.ClientRoot != nil}
	var answer string
	if r.clientRoot {
		if len(p.handshakes) > 0 {
			answer, p.handshakes = p.handshakes[0], p.handshakes[1:]
		}
	} else {
		answer = p.replacement
	}
	switch answer {
	case "":
		p.received = append(p.received, r)
		p.beyond = append(p.beyond, "a handshake")
		return 500, nil
	case "notFound":
		p.received = append(p.received, r)
		return 404, nil
	}
	reply, sess := p.reply(t, req, answer)
	r.issued = sess
	p.received = append(p.received, r)
	return 200, reply
}

// reply returns the partner's reply's wire bytes to req, as answer says, and the id it issues.
func (p *scriptedPartner) reply(t testing.TB, req session.Request, answer string) ([]byte, string) {
	t.Helper()
	nonce := session.NewNonce()
	sess, ok := session.ID(req, &p.root, nonce)
	if !ok {
		t.Fatal("the handshake has no session id")
	}
	if p.sessFor != nil {
		sess = p.sessFor(sess)
	}
	r := session.Reply{
		ServerRoot: &p.root, ServerPolicyKey: p.policyKey, ServerKeyring: p.keyring.Services,
		ServerKeyringSig: &p.keyring.Sig, ServerKeyringNotAfter: &p.keyring.NotAfter, ServerReplyCert: &p.cert,
		Nonce: nonce, Sess: sess, Status: answer, Disabled: []string{},
	}
	key := p.entryKey
	switch answer {
	case "wrongKey":
		r = session.Reply{
			ServerRoot: &p.root, ServerPolicyKey: p.strangerPK, ServerKeyring: p.keyring.Services,
			Nonce: nonce, Sess: sess, Status: session.StatusAttested, Disabled: []string{},
		}
		key = p.stranger
	case session.StatusAttested, session.StatusUnsafe:
		if req.ClientRoot != nil {
			// The status the partner's own decision gives, with the egress's key pinned for an attested one.
			var pinned []string
			if answer == session.StatusAttested {
				pinned = []string{p.clientPin}
			}
			if got := session.Status(req, &p.root, p.keyring, p.policyKey, pinned, p.now); got != answer {
				t.Fatalf("session.Status gives %q where the script answers %q", got, answer)
			}
		}
		if answer == session.StatusUnsafe {
			r.Disabled = unsafeDisabled
		}
	default:
		t.Fatalf("the script's answer %q is none the rules name", answer)
	}
	signed, err := session.SignReply(r, key)
	if err != nil {
		t.Fatalf("SignReply: %v", err)
	}
	b, err := signed.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b, sess
}

// render returns what the partner received, in order, as expectedReceived writes the case's, each call's
// session named by the position of the handshake whose reply issued it. It fails t when anything came
// that the script had no answer for, when a step's headers are not those an egress sends, or when a
// stamp's signature does not verify under its signer's key in the egress's keyring.
func (p *scriptedPartner) render(t testing.TB) []string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.beyond) != 0 {
		t.Errorf("received beyond the partner's script: %q", p.beyond)
	}
	var out []string
	for _, r := range p.received {
		h := headerMap(t, r.step.Headers)
		if h["Content-Type"] != wire.ContentType {
			t.Errorf("a step to %s has Content-Type %q", r.step.Path, h["Content-Type"])
		}
		if r.handshake {
			if len(h) != 1 {
				t.Errorf("a handshake has headers %q", r.step.Headers)
			}
			out = append(out, fmt.Sprintf("handshake clientRoot=%v", r.clientRoot))
			continue
		}
		stamps, stampSession := "null", "null"
		if tok, ok := h[wire.Chain]; ok {
			chain, code := stamp.ReadChain(tok)
			if code != "" && code != "OK" {
				t.Fatalf("a call's chain does not read: %s", code)
			}
			for _, s := range chain {
				if !p.signedBySvc(s) {
					t.Errorf("a boundary stamp's signature does not verify under %s's key", s.Svc)
				}
			}
			stampSession = p.index(chain[0].Sess)
			stamps = renderStamps(chain)
		}
		proof := "null"
		if tok, ok := h[wire.Proof]; ok {
			pr, err := policy.ReadProof(tok)
			if err != nil {
				t.Fatalf("a call's proof does not read: %v", err)
			}
			proof = renderProof(pr)
		}
		infl := "null"
		if tok, ok := h[wire.Influence]; ok {
			es, err := influence.ReadEntries(tok)
			if err != nil {
				t.Fatalf("a call's influence does not read: %v", err)
			}
			infl = fmt.Sprintf("%+v", es)
		}
		session := "null"
		if id, ok := h[wire.Session]; ok {
			session = p.index(id)
		}
		out = append(out, renderCall("POST", r.step.Path, r.step.Body, session, stamps, stampSession, proof, infl))
	}
	return out
}

// headerMap returns hs by name, failing t on a header an egress never sends or on one sent twice.
func headerMap(t testing.TB, hs []wire.Header) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, h := range hs {
		switch h.Name {
		case "Content-Type", wire.Session, wire.Chain, wire.Proof, wire.Influence:
		default:
			t.Errorf("a step has the header %q", h.Name)
		}
		if _, ok := m[h.Name]; ok {
			t.Errorf("a step has the header %q twice", h.Name)
		}
		m[h.Name] = h.Value
	}
	return m
}

// index returns the position, in what the partner received, of the handshake whose reply issued sess, or
// "null" when none did.
func (p *scriptedPartner) index(sess string) string {
	for i, r := range p.received {
		if r.issued != "" && r.issued == sess {
			return fmt.Sprint(i)
		}
	}
	return "null"
}

// signedBySvc reports whether s's signature, over its fields as received, verifies under the key the
// egress's keyring holds for its signer.
func (p *scriptedPartner) signedBySvc(s stamp.Stamp) bool {
	text, ok := p.egressKeys[s.Svc]
	if !ok {
		return false
	}
	pub, err := keys.ParsePublic(text)
	if err != nil {
		return false
	}
	msg, err := s.SigningBytes()
	if err != nil {
		return false
	}
	sig, err := b64.Decode(s.Sig)
	return err == nil && keys.Verify(pub, msg, sig)
}

// expectedReceived writes one of a case's expected received steps as render writes them.
func expectedReceived(t testing.TB, r vectors.Node) string {
	t.Helper()
	if r.Has("handshake") {
		return fmt.Sprintf("handshake clientRoot=%v", r.Get("handshake").Get("clientRoot").Bool())
	}
	c := r.Get("call")
	nullOr := func(n vectors.Node, f func(vectors.Node) string) string {
		if n.IsNull() {
			return "null"
		}
		return f(n)
	}
	index := func(n vectors.Node) string { return fmt.Sprint(n.Int()) }
	stamps := nullOr(c.Get("stamps"), func(n vectors.Node) string {
		chain := make(stamp.Chain, n.Len())
		for i := range chain {
			s := n.Index(i)
			if s.Get("v").Int() != 3 {
				t.Fatalf("an expected stamp has v %d", s.Get("v").Int())
			}
			chain[i] = stamp.Stamp{
				Svc: s.Get("svc").Str(), Inst: s.Get("inst").Str(), RID: s.Get("rid").Str(), TS: s.Get("ts").Int(),
				Rcv: s.Get("rcv").Str(), Bind: s.Get("bind").Str(), Infl: s.Get("infl").Str(), Prev: s.Get("prev").Str(),
			}
		}
		return renderStamps(chain)
	})
	proof := nullOr(c.Get("proof"), func(n vectors.Node) string {
		pr := policy.Proof{LeafSalt: unb64(t, n.Get("leafSalt")), Dirs: n.Get("dirs").Str(), RootID: n.Get("rootId").Str()}
		n.Get("siblings").Each(func(_ string, s vectors.Node) { pr.Siblings = append(pr.Siblings, unb64(t, s)) })
		return renderProof(pr)
	})
	infl := nullOr(c.Get("influence"), func(n vectors.Node) string { return fmt.Sprintf("%+v", entries(n)) })
	return renderCall(c.Get("method").Str(), c.Get("path").Str(), unhex(t, c.Get("body")),
		nullOr(c.Get("session"), index), stamps, nullOr(c.Get("stampSession"), index), proof, infl)
}

// renderCall writes one received call.
func renderCall(method, path string, body []byte, session, stamps, stampSession, proof, infl string) string {
	return fmt.Sprintf("call %s %s body=%x session=%s stamps=%s stampSession=%s proof=%s influence=%s",
		method, path, body, session, stamps, stampSession, proof, infl)
}

// renderStamps writes stamps with their sess and sig left out: the partner chose the id, and sig covers
// it.
func renderStamps(c stamp.Chain) string {
	var parts []string
	for _, s := range c {
		s.Sess, s.Sig = "", ""
		parts = append(parts, fmt.Sprintf("%+v", s))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// renderProof writes a proof.
func renderProof(p policy.Proof) string {
	var sib []string
	for _, s := range p.Siblings {
		sib = append(sib, b64.Encode(s))
	}
	return fmt.Sprintf("{leafSalt:%s siblings:%v dirs:%s rootId:%s}", b64.Encode(p.LeafSalt), sib, p.Dirs, p.RootID)
}

// bundleOf returns svc's proof bundle: every route proof material holds, read by the SDK's own bundle
// reader from a file made of the vector's own JSON text.
func bundleOf(t testing.TB, material, svc string) policy.ProofBundle {
	t.Helper()
	m := vectors.Rules(t).Get("material").Get(material)
	file := bytes.Join([][]byte{
		[]byte(`{"service":"` + svc + `","rootId":`), m.Get("root").Get("rootId").Raw(),
		[]byte(`,"proofs":`), m.Get("proofs").Raw(),
		[]byte(`}`),
	}, nil)
	b, err := policy.ParseProofBundleFile(file)
	if err != nil {
		t.Fatalf("ParseProofBundleFile: %v", err)
	}
	return b
}

// rootOf and keyringOf read material m's signed root and keyring from their files' text.
func rootOf(t testing.TB, m vectors.Material) policy.Root {
	t.Helper()
	r, err := policy.ParseRootFile(m.Root)
	if err != nil {
		t.Fatalf("ParseRootFile: %v", err)
	}
	return r
}

func keyringOf(t testing.TB, m vectors.Material) policy.KeyringFile {
	t.Helper()
	kf, err := policy.ParseKeyringFile(m.Keyring)
	if err != nil {
		t.Fatalf("ParseKeyringFile: %v", err)
	}
	return kf
}

// entries returns the entries array n describes.
func entries(n vectors.Node) []influence.Entry {
	es := make([]influence.Entry, n.Len())
	for i := range es {
		e := n.Index(i)
		es[i] = influence.Entry{Class: influence.Class(e.Get("cls").Str()), Src: e.Get("src").Str(), H: e.Get("h").Str()}
		if e.Has("cid") {
			es[i].CID, es[i].HasCID = e.Get("cid").Str(), true
		}
		if e.Has("owner") {
			es[i].Owner = e.Get("owner").Str()
		}
	}
	return es
}

// strs returns the strings array n holds.
func strs(n vectors.Node) []string {
	out := make([]string, n.Len())
	for i := range out {
		out[i] = n.Index(i).Str()
	}
	return out
}

// unhex returns the bytes hex string n holds.
func unhex(t testing.TB, n vectors.Node) []byte {
	t.Helper()
	b, err := hex.DecodeString(n.Str())
	if err != nil {
		t.Fatalf("not hex: %v", err)
	}
	return b
}

// unb64 returns the bytes base64url string n holds.
func unb64(t testing.TB, n vectors.Node) []byte {
	t.Helper()
	b, err := b64.Decode(n.Str())
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	return b
}
