// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

func TestValidNode(t *testing.T) {
	for _, node := range []string{
		"pi",
		"gateway",
		"mcp:github.create_pull_request",
		"local:read",
		"...",
		".a",
		"a.",
		"\xc3\xa9",         // U+00E9
		"\xf0\x9f\x98\x80", // U+1F600, a surrogate pair in UTF-16
	} {
		if err := policy.ValidNode(node); err != nil {
			t.Errorf("ValidNode(%+q) = %v, want nil", node, err)
		}
	}
	for _, node := range []string{
		"",
		".",
		"..",
		"a/b",
		"/",
		"a\\b",
		"a|b",
		"\xed\xa0\x80",     // the WTF-8 bytes of U+D800, a lone surrogate
		"a\xed\xb0\x80",    // U+DC00
		"\xed\xa0\xbd\xed", // a high surrogate and a cut-short sequence
		"\xff",
	} {
		err := policy.ValidNode(node)
		if err == nil {
			t.Errorf("ValidNode(%+q) = nil, want an error", node)
		} else if len(node) > 2 && strings.Contains(err.Error(), node) {
			t.Errorf("ValidNode(%+q) = %v, which quotes the node", node, err)
		}
	}
}

func TestJoinRoute(t *testing.T) {
	if got := policy.JoinRoute("gateway", "orders", "payment"); got != "gateway/orders/payment" {
		t.Errorf("JoinRoute = %q", got)
	}
	if got := policy.JoinRoute(); got != "" {
		t.Errorf("JoinRoute() = %q, want empty", got)
	}
}

// signedKeyring returns the text of v3.json's signed keyring file.
func signedKeyring(t *testing.T) string {
	t.Helper()
	return vectors.Load(t, "v3.json").Get("keyring").Index(0).Get("file").Str()
}

// keyringText returns a keyring file whose members hold the JSON texts given, then extra.
func keyringText(notAfter, policyKey, services, sig, extra string) string {
	return `{"notAfter": ` + notAfter + `, "policy": ` + policyKey + `, "services": ` + services +
		`, "sig": ` + sig + extra + "}\n"
}

// TestKeyringFileRefuses reads keyrings the schema refuses, each for one fault. A refusal quotes nothing.
func TestKeyringFileRefuses(t *testing.T) {
	_, pub := vectors.V3Key(t, "pi")
	key := `"` + keys.EncodePublic(pub) + `"`
	const notAfter, sig = "1798761600000", `"secretsig"`
	services := `{"pi": ` + key + `}`
	if _, err := policy.ParseKeyringFile([]byte(keyringText(notAfter, key, services, sig, ""))); err != nil {
		t.Fatalf("the keyring the cases edit does not read: %v", err)
	}
	for name, text := range map[string]string{
		"a service name holding |":           keyringText(notAfter, key, `{"secret|node": `+key+`}`, sig, ""),
		"a service name of ..":               keyringText(notAfter, key, `{"..": `+key+`}`, sig, ""),
		"an empty service name":              keyringText(notAfter, key, `{"": `+key+`}`, sig, ""),
		"a service key that is not a string": keyringText(notAfter, key, `{"secretnode": 1}`, sig, ""),
		"services that are a string":         keyringText(notAfter, key, `"secretnode"`, sig, ""),
		"services that are null":             keyringText(notAfter, key, "null", sig, ""),
		"an extra member":                    keyringText(notAfter, key, services, sig, `, "secret": 1`),
		"a sig that is not a string":         keyringText(notAfter, key, services, "1", ""),
		"a null sig":                         keyringText(notAfter, key, services, "null", ""),
		"a policy that is not a string":      keyringText(notAfter, "true", services, sig, ""),
		"a notAfter that is a string":        keyringText(`"1798761600000"`, key, services, sig, ""),
		"a null notAfter":                    keyringText("null", key, services, sig, ""),
		"a negative notAfter":                keyringText("-1", key, services, sig, ""),
		"a second value":                     keyringText(notAfter, key, services, sig, "") + "{}",
		"an array":                           "[]",
	} {
		if kf, err := policy.ParseKeyringFile([]byte(text)); err == nil {
			t.Errorf("%s: ParseKeyringFile kept %+v", name, kf)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "MCow") {
			t.Errorf("%s: the refusal quotes the file: %v", name, err)
		}
	}
}

// TestKeyringKeys decodes the keyring's service keys.
func TestKeyringKeys(t *testing.T) {
	kf, err := policy.ParseKeyringFile([]byte(signedKeyring(t)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := kf.Keyring()
	if err != nil {
		t.Fatalf("Keyring: %v", err)
	}
	if len(k) != 2 {
		t.Fatalf("Keyring holds %d keys, want 2", len(k))
	}
	for _, svc := range []string{"pi", "session"} {
		_, pub := vectors.V3Key(t, svc)
		if !bytes.Equal(k[svc], pub) {
			t.Errorf("Keyring()[%q] = %x, want %x", svc, k[svc], pub)
		}
	}

	kf.Services = map[string]string{"pi": kf.Services["pi"] + "AA"}
	if k, err := kf.Keyring(); err == nil {
		t.Fatalf("Keyring decoded a key that is not one: %v", k)
	} else if strings.Contains(err.Error(), "MCow") {
		t.Fatalf("the refusal quotes the key: %v", err)
	}
}

func TestSignRefuses(t *testing.T) {
	priv, _ := vectors.V3Key(t, "client-policy")
	pin := keys.EncodePublic(priv.Public().(ed25519.PublicKey))
	services := map[string]string{"pi": pin}

	if _, err := policy.SignKeyring(map[string]string{"a/b": pin}, pin, 1, priv); err == nil {
		t.Error("SignKeyring signed a keyring that names a service a/b")
	}
	if _, err := policy.SignKeyring(map[string]string{"\xed\xa0\x80": pin}, pin, 1, priv); err == nil {
		t.Error("SignKeyring signed a service name that is not UTF-8")
	}
	for _, notAfter := range []int64{-1, json.MaxSafe + 1} {
		if _, err := policy.SignKeyring(services, pin, notAfter, priv); err == nil {
			t.Errorf("SignKeyring signed a notAfter of %d", notAfter)
		}
		if _, err := policy.KeyringSigningBytes(pin, services, notAfter); err == nil {
			t.Errorf("KeyringSigningBytes wrote a notAfter of %d", notAfter)
		} else if !strings.Contains(err.Error(), "notAfter") {
			t.Errorf("the refusal of a notAfter of %d does not name it: %v", notAfter, err)
		}
		if _, err := policy.SignRoot(make([]byte, 32), "v1", notAfter, priv); err == nil {
			t.Errorf("SignRoot signed a notAfter of %d", notAfter)
		}
		if _, err := policy.RootSigningBytes("v1", "AA", notAfter); err == nil {
			t.Errorf("RootSigningBytes wrote a notAfter of %d", notAfter)
		}
		if _, err := policy.IssueReplyCert(pin, "pi", pin, notAfter, priv); err == nil {
			t.Errorf("IssueReplyCert signed a notAfter of %d", notAfter)
		}
		if _, err := policy.ReplyCertSigningBytes(pin, "pi", pin, notAfter); err == nil {
			t.Errorf("ReplyCertSigningBytes wrote a notAfter of %d", notAfter)
		}
	}
	if _, err := policy.SignRoot(make([]byte, 31), "v1", 1, priv); err == nil {
		t.Error("SignRoot signed a 31-byte root")
	}
	if _, err := policy.SignRoot(make([]byte, 32), "\xed\xa0\x80", 1, priv); err == nil {
		t.Error("SignRoot signed a root id that is not UTF-8")
	}
	if _, err := policy.IssueReplyCert(pin, "pi\xed\xa0\x80", pin, 1, priv); err == nil {
		t.Error("IssueReplyCert signed a service that is not UTF-8")
	}

	// A key of the wrong length is refused, where ed25519.Sign would panic.
	short := priv[:63]
	if _, err := policy.SignKeyring(services, pin, 1, short); err == nil {
		t.Error("SignKeyring signed with a 63-byte key")
	}
	if _, err := policy.SignRoot(make([]byte, 32), "v1", 1, short); err == nil {
		t.Error("SignRoot signed with a 63-byte key")
	}
	if _, err := policy.IssueReplyCert(pin, "pi", pin, 1, nil); err == nil {
		t.Error("IssueReplyCert signed with no key")
	}
}

// TestRefusalText pins the words of three refusals: a reader's names the policy package once and no
// internal one, SignKeyring refuses a service name as Keyring does, and a signing key's refusal is wrapped
// in the statement's name.
func TestRefusalText(t *testing.T) {
	_, err := policy.ParseKeyringFile([]byte(`{"policy": "p", "services": {}, "sig": "s"}`))
	if want := `paztport policy: malformed keyring file: schema: the member "notAfter" is missing`; err == nil ||
		err.Error() != want {
		t.Errorf("ParseKeyringFile error = %v, want %s", err, want)
	}

	priv, _ := vectors.V3Key(t, "client-policy")
	pin := keys.EncodePublic(priv.Public().(ed25519.PublicKey))
	_, signErr := policy.SignKeyring(map[string]string{"": pin}, pin, 1, priv)
	_, keysErr := policy.KeyringFile{Services: map[string]string{"": pin}}.Keyring()
	if signErr == nil || keysErr == nil || signErr.Error() != keysErr.Error() {
		t.Errorf("SignKeyring error = %v, want Keyring's: %v", signErr, keysErr)
	}

	_, err = policy.SignRoot(make([]byte, 32), "v1", 1, priv[:63])
	if want := "paztport policy: can't sign the root: paztport keys: "; err == nil ||
		!strings.HasPrefix(err.Error(), want) {
		t.Errorf("SignRoot error = %v, want one starting %q", err, want)
	}
}

// TestVerifiesNeverPanics hands the verifiers keys and signatures of the wrong length, where ed25519.Verify
// would panic or a decoder fail: each says false.
func TestVerifiesNeverPanics(t *testing.T) {
	priv, pub := vectors.V3Key(t, "client-policy")
	pin := keys.EncodePublic(pub)
	root, err := policy.SignRoot(make([]byte, 32), "v1", 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !root.Verifies(pin) {
		t.Fatal("a root signed here does not verify")
	}
	for _, p := range []string{"", "AA", pin + "AA", b64.Encode(pub)} {
		if root.Verifies(p) {
			t.Errorf("Root.Verifies accepted the pin %q", p)
		}
	}
	if _, other := vectors.V3Key(t, "server-policy"); root.Verifies(keys.EncodePublic(other)) {
		t.Error("Root.Verifies accepted another policy key")
	}
	sig := decode(t, root.Sig)
	for _, s := range []string{"", b64.Encode(sig[:63]), b64.Encode(append(bytes.Clone(sig), 0)), root.Sig + "=", root.Sig[:85] + "B"} {
		r := root
		r.Sig = s
		if r.Verifies(pin) {
			t.Errorf("Root.Verifies accepted a sig of %d characters", len(s))
		}
	}
	r := root
	r.NotAfter = -1
	if r.Verifies(pin) {
		t.Error("Root.Verifies accepted a notAfter of -1")
	}

	kf, err := policy.SignKeyring(map[string]string{"pi": pin}, pin, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !kf.Verifies(pin) {
		t.Fatal("a keyring signed here does not verify")
	}
	for _, p := range []string{"", "AA", pin + "AA", b64.Encode(pub)} {
		k := kf
		k.Policy = p
		if k.Verifies(p) {
			t.Errorf("KeyringFile.Verifies accepted the pin %q", p)
		}
	}
	k := kf
	k.Sig = b64.Encode(decode(t, kf.Sig)[:63])
	if k.Verifies(pin) {
		t.Error("KeyringFile.Verifies accepted a 63-byte sig")
	}
	k = kf
	k.Services = map[string]string{"pi": pin + "\xed\xa0\x80"}
	if k.Verifies(pin) {
		t.Error("KeyringFile.Verifies accepted a keyring with no signing bytes")
	}

	cert, err := policy.IssueReplyCert(pin, "pi", pin, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Verifies(pin) {
		t.Fatal("a certificate issued here does not verify")
	}
	c := cert
	c.Policy, c.Sig = "AA", ""
	if c.Verifies("AA") || cert.Verifies("") {
		t.Error("ReplyCert.Verifies accepted a pin that is not a key")
	}
}

// TestVerifiesUnderPinOnly checks that a keyring or certificate verifies only under the policy key it names:
// one signed by the pinned key but naming another policy key fails, though its signature is good.
func TestVerifiesUnderPinOnly(t *testing.T) {
	priv, pub := vectors.V3Key(t, "server-policy")
	_, other := vectors.V3Key(t, "client-policy")
	pin, named := keys.EncodePublic(pub), keys.EncodePublic(other)

	kf, err := policy.SignKeyring(map[string]string{"pi": pin}, named, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if kf.Verifies(pin) || kf.Verifies(named) {
		t.Error("a keyring naming another policy key verifies")
	}
	cert, err := policy.IssueReplyCert(named, "pi", pin, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Verifies(pin) || cert.Verifies(named) {
		t.Error("a certificate naming another policy key verifies")
	}
}

// TestKeyringBuiltInCode holds a keyring built in code to the route-node rule the reader applies: one that
// names a service a/b, though the policy key signed it, neither verifies nor decodes.
func TestKeyringBuiltInCode(t *testing.T) {
	priv, pub := vectors.V3Key(t, "client-policy")
	pin := keys.EncodePublic(pub)
	for _, name := range []string{"a/b", "..", "", "a|b", "\xed\xa0\x80"} {
		services := map[string]string{"pi": pin, name: pin}
		msg, err := policy.KeyringSigningBytes(pin, services, 1)
		if err != nil {
			if name == "\xed\xa0\x80" {
				continue // no signing bytes, so nothing to sign
			}
			t.Fatal(err)
		}
		sig, err := keys.Sign(priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		kf := policy.KeyringFile{Services: services, Policy: pin, Sig: b64.Encode(sig), NotAfter: 1}
		if kf.Verifies(pin) {
			t.Errorf("a keyring naming the service %+q verifies", name)
		}
		if k, err := kf.Keyring(); err == nil {
			t.Errorf("a keyring naming the service %+q decodes to %v", name, k)
		}
	}
	// The same keyring with valid names, signed the same way, verifies and decodes.
	services := map[string]string{"pi": pin, "gateway": pin}
	msg, err := policy.KeyringSigningBytes(pin, services, 1)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keys.Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	kf := policy.KeyringFile{Services: services, Policy: pin, Sig: b64.Encode(sig), NotAfter: 1}
	if !kf.Verifies(pin) {
		t.Fatal("a keyring signed here does not verify")
	}
	if _, err := kf.Keyring(); err != nil {
		t.Fatalf("Keyring: %v", err)
	}
}

func TestCurrent(t *testing.T) {
	for _, c := range []struct {
		now, notAfter int64
		current       bool
	}{
		{0, 0, true},
		{-1 << 63, 0, true},
		{1, 0, false},
		{json.MaxSafe, json.MaxSafe, true},
		{1<<63 - 1, json.MaxSafe, false},
	} {
		root := policy.Root{NotAfter: c.notAfter}
		kf := policy.KeyringFile{NotAfter: c.notAfter}
		cert := policy.ReplyCert{NotAfter: c.notAfter}
		if root.Current(c.now) != c.current || kf.Current(c.now) != c.current || cert.Current(c.now) != c.current {
			t.Errorf("Current(%d) with notAfter %d is not %v", c.now, c.notAfter, c.current)
		}
	}
}

// TestRootReads reads a root as a file and from a value, as a session message holds one, and refuses one
// with any member but its four or bytes that are not canonical.
func TestRootReads(t *testing.T) {
	c := vectors.Load(t, "v3.json").Get("root").Index(0)
	file := c.Get("file").Str()
	root, err := policy.ParseRootFile([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := root.Wire()
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"notAfter":1798761600000,"root":"` + root.Root + `","rootId":"` + root.RootID + `","sig":"` + root.Sig + `"}`; string(wire) != want {
		t.Fatalf("Wire = %s, want %s", wire, want)
	}
	read, err := policy.ParseRoot(wire)
	if err != nil || read != root {
		t.Fatalf("ParseRoot(Wire()) = %+v, %v; want %+v", read, err, root)
	}
	if r, err := policy.ParseRoot([]byte(file)); err == nil {
		t.Errorf("ParseRoot read the file form, which is not canonical, as %+v", r)
	}
	b, err := root.Bytes()
	if err != nil || len(b) != 32 {
		t.Fatalf("Bytes = %x, %v; want 32 bytes", b, err)
	}
	r := root
	r.Root += "="
	if _, err := r.Bytes(); err == nil {
		t.Error("Bytes decoded a root that is not canonical base64url")
	}

	good := readBack(t)(wire, nil)
	for _, v := range []json.Value{
		json.Null(),
		json.S(file),
		json.Obj(),
		withMember(good, "extra", json.S("x")),
		withMember(good, "rootId", json.Null()),
		withMember(good, "notAfter", json.S("1798761600000")),
		withMember(good, "root", json.I(1)),
		withMember(good, "sig", json.Arr()),
	} {
		if r, err := policy.ParseRoot(canonical(t, v)); err == nil {
			t.Errorf("ParseRoot kept %+v", r)
		}
	}
}

// TestReplyCertReads reads a certificate from its wire bytes, as a session reply carries one.
func TestReplyCertReads(t *testing.T) {
	cert, err := policy.ParseReplyCertFile([]byte(vectors.Load(t, "v3.json").Get("replyCert").Index(0).Get("file").Str()))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cert.Wire()
	if err != nil {
		t.Fatal(err)
	}
	read, err := policy.ParseReplyCert(wire)
	if err != nil || read != cert {
		t.Fatalf("ParseReplyCert(Wire()) = %+v, %v; want %+v", read, err, cert)
	}
	good := readBack(t)(wire, nil)
	for _, name := range []string{"key", "notAfter", "policy", "sig", "svc"} {
		if _, err := policy.ParseReplyCert(canonical(t, withMember(good, name, json.Null()))); err == nil {
			t.Errorf("ParseReplyCert kept a null %s", name)
		} else if !strings.Contains(err.Error(), `"`+name+`"`) {
			t.Errorf("the refusal of a null %s does not name it: %v", name, err)
		}
	}
	if _, err := policy.ParseReplyCert(canonical(t, withMember(good, "note", json.S("x")))); err == nil {
		t.Error("ParseReplyCert kept an extra member")
	}
	if _, err := policy.ParseReplyCert(append(wire, ' ')); err == nil {
		t.Error("ParseReplyCert read bytes that are not canonical")
	}
}

// withMember returns object o with member name set to v, added if o lacks it.
func withMember(o json.Value, name string, v json.Value) json.Value {
	members := o.Members()
	for i, m := range members {
		if m.Name == name {
			members[i].Value = v
			return json.Obj(members...)
		}
	}
	return json.Obj(append(members, json.Member{Name: name, Value: v})...)
}

// proof returns the merkle vectors' proof for route, and their root.
func proof(t *testing.T, route string) (policy.Proof, []byte) {
	t.Helper()
	m := vectors.Load(t, "v3.json").Get("merkle")
	p, err := policy.ReadProof(m.Get("proofHeaders").Get(route).Str())
	if err != nil {
		t.Fatal(err)
	}
	return p, decode(t, m.Get("root").Str())
}

func mustProof(t *testing.T, v json.Value) policy.Proof {
	t.Helper()
	p, err := policy.ParseProof(canonical(t, v))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	return p
}

// TestProofVerifyRefuses checks that a proof proves only its own route, and that Verify says false for a
// proof the reader would have refused, built by hand.
func TestProofVerifyRefuses(t *testing.T) {
	const route = "gateway/orders"
	p, root := proof(t, route)
	if !p.Verify(route, root) {
		t.Fatal("the proof does not prove its route")
	}
	for _, other := range []string{"gateway/search", "gateway/orders/payment", "gateway/orders ", "gateway/order", "", "gateway/orders\xed\xa0\x80"} {
		if p.Verify(other, root) {
			t.Errorf("the proof proves %+q", other)
		}
	}
	otherRoot := bytes.Clone(root)
	otherRoot[0] ^= 1
	for _, r := range [][]byte{otherRoot, root[:31], nil} {
		if p.Verify(route, r) {
			t.Errorf("the proof proves its route against %x", r)
		}
	}

	// A leaf hashes salt || route with no separator, so a salt that took in the route's first byte would prove
	// the rest of the route, were the salt's length not held to 16 bytes.
	absorbing := p
	absorbing.LeafSalt = append(bytes.Clone(p.LeafSalt), route[0])
	if absorbing.Verify(route[1:], root) {
		t.Error("a 17-byte salt holding the route's first byte proves the rest of the route")
	}

	edits := map[string]func(*policy.Proof){
		"a 15-byte salt":            func(p *policy.Proof) { p.LeafSalt = p.LeafSalt[:15] },
		"a 17-byte salt":            func(p *policy.Proof) { p.LeafSalt = append(p.LeafSalt, 0) },
		"a 31-byte sibling":         func(p *policy.Proof) { p.Siblings[3] = p.Siblings[3][:31] },
		"a dirs letter not L or R":  func(p *policy.Proof) { p.Dirs = "X" + p.Dirs[1:] },
		"dirs one short":            func(p *policy.Proof) { p.Dirs = p.Dirs[1:] },
		"one sibling too many":      func(p *policy.Proof) { p.Siblings = append(p.Siblings, p.Siblings[0]) },
		"dirs flipped":              func(p *policy.Proof) { p.Dirs = "L" + p.Dirs[1:] },
		"no siblings and no dirs":   func(p *policy.Proof) { p.Siblings, p.Dirs = nil, "" },
		"a lower-case dirs letter":  func(p *policy.Proof) { p.Dirs = "r" + p.Dirs[1:] },
		"dirs in a multibyte form":  func(p *policy.Proof) { p.Dirs = "\xef\xbc\xb2" + p.Dirs[3:] }, // U+FF32, a fullwidth R
		"the last sibling replaced": func(p *policy.Proof) { p.Siblings[7] = make([]byte, 32) },
	}
	for name, edit := range edits {
		q, _ := proof(t, route)
		edit(&q)
		if q.Verify(route, root) {
			t.Errorf("a proof with %s proves its route", name)
		}
	}
}

// TestReadProofRefuses reads proofs that break the proof object's rules. A refusal quotes none of it.
func TestReadProofRefuses(t *testing.T) {
	p, _ := proof(t, "gateway/orders")
	good := readBack(t)(p.Wire())
	sibling := json.S(b64.Encode(p.Siblings[0]))
	salt := b64.Encode(p.LeafSalt)
	siblings := func(items ...json.Value) json.Value { return withMember(good, "siblings", json.Arr(items...)) }
	eight := func(last json.Value) json.Value {
		return siblings(sibling, sibling, sibling, sibling, sibling, sibling, sibling, last)
	}
	for name, v := range map[string]json.Value{
		"an extra member":            withMember(good, "secret", json.S("x")),
		"a 15-byte salt":             withMember(good, "leafSalt", json.S(b64.Encode(p.LeafSalt[:15]))),
		"a 17-byte salt":             withMember(good, "leafSalt", json.S(b64.Encode(append(p.LeafSalt, 0)))),
		"a salt with unused bits":    withMember(good, "leafSalt", json.S(salt[:21]+"B")),
		"a salt that is not a str":   withMember(good, "leafSalt", json.I(1)),
		"a 31-byte sibling":          eight(json.S(b64.Encode(p.Siblings[0][:31]))),
		"a sibling that is a number": eight(json.I(1)),
		"a null sibling":             eight(json.Null()),
		"siblings that are a string": withMember(good, "siblings", sibling),
		"seven siblings":             siblings(sibling, sibling, sibling, sibling, sibling, sibling, sibling),
		"dirs not L or R":            withMember(good, "dirs", json.S("RLLLLLLX")),
		"dirs one short":             withMember(good, "dirs", json.S("RLLLLLL")),
		"dirs that are null":         withMember(good, "dirs", json.Null()),
		"a root id that is a number": withMember(good, "rootId", json.I(1)),
		"an array":                   json.Arr(good),
	} {
		tok, err := json.Token(v)
		if err != nil {
			t.Fatalf("%s: Token: %v", name, err)
		}
		if q, err := policy.ReadProof(tok); err == nil {
			t.Errorf("%s: ReadProof kept %+v", name, q)
		} else if strings.Contains(err.Error(), salt) || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the refusal quotes the proof: %v", name, err)
		}
		if _, err := policy.ParseProof(canonical(t, v)); err == nil {
			t.Errorf("%s: ParseProof kept it", name)
		}
	}

	// Wire bytes, and a token of them, are the proof's canonical bytes and nothing else.
	w, err := p.Wire()
	if err != nil {
		t.Fatal(err)
	}
	// The canonical bytes open with dirs; moved to the end, they are the same object in another order.
	const dirs = `"dirs":"RLLLLLLL"`
	if !bytes.HasPrefix(w, []byte("{"+dirs+",")) {
		t.Fatalf("the proof's bytes do not open with %s", dirs)
	}
	reordered := append([]byte("{"), w[len(dirs)+2:len(w)-1]...)
	reordered = append(reordered, ","+dirs+"}"...)
	if v, err := json.ReadFile(reordered); err != nil || !reflect.DeepEqual(mustProof(t, v), p) {
		t.Fatalf("the reordered bytes are not the same proof: %v", err)
	}
	for name, b := range map[string][]byte{
		"a space after the object": append(bytes.Clone(w), ' '),
		"members out of order":     reordered,
	} {
		if _, err := policy.ReadProof(b64.Encode(b)); err == nil {
			t.Errorf("ReadProof read a token with %s", name)
		}
		if _, err := policy.ParseProof(b); err == nil {
			t.Errorf("ParseProof read wire bytes with %s", name)
		}
	}
	if _, err := policy.ReadProof(b64.Encode(w) + "="); err == nil {
		t.Error("ReadProof read a padded token")
	}
}

// bundleFile returns the text of json.json's proof bundle file.
func bundleFile(t *testing.T) string {
	t.Helper()
	var file string
	vectors.Load(t, "json.json").Get("fileFormat").Each(func(_ string, c vectors.Node) {
		if !c.Get("kind").IsNull() && c.Get("kind").Str() == "proofs" {
			file = c.Get("file").Str()
		}
	})
	if file == "" {
		t.Fatal("json.json has no proof bundle file")
	}
	return file
}

func TestProofBundle(t *testing.T) {
	file := bundleFile(t)
	b, err := policy.ParseProofBundleFile([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	if b.Service != "gateway" || b.RootID != "merkle-vector" || len(b.Proofs) != 2 {
		t.Fatalf("read %s under %s with %d proofs", b.Service, b.RootID, len(b.Proofs))
	}
	want, root := proof(t, "gateway/orders")
	got, ok := b.ProofFor("gateway/orders")
	if !ok || !reflect.DeepEqual(got, want) || !got.Verify("gateway/orders", root) {
		t.Fatalf("ProofFor(gateway/orders) = %+v, %v; want %+v", got, ok, want)
	}
	if _, ok := b.ProofFor("gateway/orders/payment"); ok {
		t.Error("ProofFor found a route the bundle does not hold")
	}

	const route = `"gateway/search": {`
	for _, c := range []struct{ name, old, new string }{
		{"a route of one node", route, `"secretnode": {`},
		{"a route with an empty node", route, `"gateway//search": {`},
		{"a route ending in /", route, `"gateway/": {`},
		{"a route through ..", route, `"gateway/../search": {`},
		{"a route holding |", route, `"gateway/se|cret": {`},
		{"a malformed proof", `"dirs": "LRLLLLLL"`, `"dirs": "LRLLLLL"`},
		{"an extra member", `"rootId": "merkle-vector",` + "\n  \"service\"", `"rootId": "merkle-vector", "secret": 1, "service"`},
		{"a service that is not a string", `"service": "gateway"`, `"service": 1`},
		{"a root id that is not a string", `"rootId": "merkle-vector",` + "\n  \"service\"", `"rootId": null, "service"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := strings.Replace(file, c.old, c.new, 1)
			if text == file {
				t.Fatal("the edit did not apply")
			}
			if b, err := policy.ParseProofBundleFile([]byte(text)); err == nil {
				t.Fatalf("ParseProofBundleFile kept %+v", b)
			} else if strings.Contains(err.Error(), "secret") {
				t.Fatalf("the refusal quotes the file: %v", err)
			}
		})
	}
}

// TestProofsAreAnObject reads a bundle whose proofs member is each kind of value: only an object, even an
// empty one, is a map of proofs.
func TestProofsAreAnObject(t *testing.T) {
	bundle := func(proofs string) []byte {
		return []byte(`{"proofs": ` + proofs + `, "rootId": "r", "service": "s"}`)
	}
	if b, err := policy.ParseProofBundleFile(bundle("{}")); err != nil || len(b.Proofs) != 0 {
		t.Fatalf("ParseProofBundleFile(empty proofs) = %+v, %v", b, err)
	}
	for _, proofs := range []string{"[]", "null", `"x"`, "1", "true"} {
		if b, err := policy.ParseProofBundleFile(bundle(proofs)); err == nil {
			t.Errorf("ParseProofBundleFile kept proofs %s as %+v", proofs, b)
		}
	}
}

// TestLoad reads each kind of file from disk, by the rules its Parse function reads bytes, and names the file
// in a refusal.
func TestLoad(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	dir := t.TempDir()
	write := func(name, text string) string {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}

	keyringText := v3.Get("keyring").Index(0).Get("file").Str()
	kf, err := policy.LoadKeyringFile(write("keyring.json", keyringText))
	if want, _ := policy.ParseKeyringFile([]byte(keyringText)); err != nil || !reflect.DeepEqual(kf, want) {
		t.Errorf("LoadKeyringFile = %+v, %v; want %+v", kf, err, want)
	}
	rootText := v3.Get("root").Index(0).Get("file").Str()
	root, err := policy.LoadRootFile(write("root.json", rootText))
	if want, _ := policy.ParseRootFile([]byte(rootText)); err != nil || root != want {
		t.Errorf("LoadRootFile = %+v, %v; want %+v", root, err, want)
	}
	certText := v3.Get("replyCert").Index(0).Get("file").Str()
	cert, err := policy.LoadReplyCertFile(write("reply-cert.json", certText))
	if want, _ := policy.ParseReplyCertFile([]byte(certText)); err != nil || cert != want {
		t.Errorf("LoadReplyCertFile = %+v, %v; want %+v", cert, err, want)
	}
	bundleText := bundleFile(t)
	bundle, err := policy.LoadProofBundleFile(write("proofs-gateway.json", bundleText))
	if want, _ := policy.ParseProofBundleFile([]byte(bundleText)); err != nil || !reflect.DeepEqual(bundle, want) {
		t.Errorf("LoadProofBundleFile = %+v, %v; want %+v", bundle, err, want)
	}

	// A refused file is named, and a file that does not exist is fs.ErrNotExist.
	malformed := write("malformed.json", strings.Replace(keyringText, `"notAfter": 1798761600000`, `"notAfter": 1.5`, 1))
	if _, err := policy.LoadKeyringFile(malformed); err == nil || !strings.Contains(err.Error(), malformed) {
		t.Errorf("LoadKeyringFile = %v, want a refusal naming the file", err)
	}
	missing := filepath.Join(dir, "missing.json")
	for name, load := range map[string]func(string) error{
		"LoadKeyringFile":     func(f string) error { _, err := policy.LoadKeyringFile(f); return err },
		"LoadRootFile":        func(f string) error { _, err := policy.LoadRootFile(f); return err },
		"LoadReplyCertFile":   func(f string) error { _, err := policy.LoadReplyCertFile(f); return err },
		"LoadProofBundleFile": func(f string) error { _, err := policy.LoadProofBundleFile(f); return err },
	} {
		if err := load(missing); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s of a missing file = %v, want fs.ErrNotExist", name, err)
		}
	}

	// The file limit is checked before anything is parsed: a root padded with spaces to one byte past it is
	// refused at the size step, and one at the limit is read.
	at := rootText + strings.Repeat(" ", json.FileBytes-len(rootText))
	if _, err := policy.LoadRootFile(write("at.json", at)); err != nil {
		t.Errorf("LoadRootFile refused a file at the limit: %v", err)
	}
	var e *json.Error
	if _, err := policy.LoadRootFile(write("past.json", at+" ")); !errors.As(err, &e) || e.Step != json.StepSize {
		t.Errorf("LoadRootFile of a file past the limit = %v, want a refusal at the size step", err)
	}
}
