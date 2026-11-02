// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// TestKeyring replays v3.json's keyring cases. Each file is read as written; one the reader keeps is held to
// its signing bytes, its verdict under the policy key's pin and its window, and one that verifies is signed
// again, which reproduces its sig since Ed25519 is deterministic.
func TestKeyring(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	v3.Get("keyring").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			policyKey := c.Get("policyKey").Str()
			pin := v3.With(t).Get("keys").Get(policyKey).Get("pub").Str()
			kf, err := policy.ParseKeyringFile([]byte(c.Get("file").Str()))
			if refused(t, c, err) {
				return
			}
			signed := c.Get("signed")
			if kf.Policy != signed.Get("policy").Str() || kf.Sig != signed.Get("sig").Str() ||
				kf.NotAfter != signed.Get("notAfter").Int() {
				t.Fatalf("read %+v, other than the case's signed keyring", kf)
			}
			services := map[string]string{}
			signed.Get("services").Each(func(svc string, key vectors.Node) { services[svc] = key.Str() })
			if !reflect.DeepEqual(kf.Services, services) {
				t.Fatalf("read the services %v, want %v", kf.Services, services)
			}

			msg, err := policy.KeyringSigningBytes(kf.Policy, kf.Services, kf.NotAfter)
			equalText(t, "KeyringSigningBytes", msg, err, c.Get("signingBytes").Str())
			if got, want := kf.Verifies(pin), c.Get("verifies").Bool(); got != want {
				t.Fatalf("Verifies = %v, want %v", got, want)
			}
			current(t, c, kf.Current)
			if c.Get("verifies").Bool() {
				priv, _ := vectors.V3Key(t, policyKey)
				again, err := policy.SignKeyring(kf.Services, kf.Policy, kf.NotAfter, priv)
				if err != nil {
					t.Fatalf("SignKeyring: %v", err)
				}
				if again.Sig != c.Get("sig").Str() {
					t.Fatalf("SignKeyring signed %s, want %s", again.Sig, c.Get("sig").Str())
				}
			}
		})
	})
}

// TestRoot replays v3.json's root cases as TestKeyring does the keyring's. Every root that reads names its
// policy's tree.
func TestRoot(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	v3.Get("root").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			v3 := v3.With(t)
			policyKey := c.Get("policyKey").Str()
			pin, err := keys.ParsePublic(v3.Get("keys").Get(policyKey).Get("pub").Str())
			if err != nil {
				t.Fatalf("the pin: %v", err)
			}
			root, err := policy.ParseRootFile([]byte(c.Get("file").Str()))
			if refused(t, c, err) {
				return
			}
			tree := v3.Get("policies").Get(c.Get("policy").Str())
			if root.Root != tree.Get("root").Str() || root.RootID != tree.Get("rootId").Str() {
				t.Fatalf("read the root %s under %s, want the policy's %s under %s",
					root.Root, root.RootID, tree.Get("root").Str(), tree.Get("rootId").Str())
			}
			signed := c.Get("signed")
			if root.Sig != signed.Get("sig").Str() || root.NotAfter != signed.Get("notAfter").Int() {
				t.Fatalf("read %+v, other than the case's signed root", root)
			}

			msg, err := policy.RootSigningBytes(root.RootID, root.Root, root.NotAfter)
			equalText(t, "RootSigningBytes", msg, err, c.Get("signingBytes").Str())
			if got, want := root.Verifies(pin), c.Get("verifies").Bool(); got != want {
				t.Fatalf("Verifies = %v, want %v", got, want)
			}
			current(t, c, root.Current)
			if c.Get("verifies").Bool() {
				b, err := root.Bytes()
				if err != nil {
					t.Fatalf("Bytes: %v", err)
				}
				priv, _ := vectors.V3Key(t, policyKey)
				again, err := policy.SignRoot(b, root.RootID, root.NotAfter, priv)
				if err != nil {
					t.Fatalf("SignRoot: %v", err)
				}
				if again != root {
					t.Fatalf("SignRoot = %+v, want %+v", again, root)
				}
			}
		})
	})
}

// TestReplyCert replays v3.json's replyCert cases: each certificate under the pin the case names, and
// issued again by its signer when it verifies.
func TestReplyCert(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	v3.Get("replyCert").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			pin := v3.With(t).Get("keys").Get(c.Get("pin").Str()).Get("pub").Str()
			cert, err := policy.ParseReplyCertFile([]byte(c.Get("file").Str()))
			if refused(t, c, err) {
				return
			}
			want := c.Get("cert")
			if cert.Policy != want.Get("policy").Str() || cert.Svc != want.Get("svc").Str() ||
				cert.Key != want.Get("key").Str() || cert.Sig != want.Get("sig").Str() ||
				cert.NotAfter != want.Get("notAfter").Int() {
				t.Fatalf("read %+v, other than the case's certificate", cert)
			}

			msg, err := policy.ReplyCertSigningBytes(cert.Policy, cert.Svc, cert.Key, cert.NotAfter)
			equalText(t, "ReplyCertSigningBytes", msg, err, c.Get("signingBytes").Str())
			if got, want := cert.Verifies(pin), c.Get("verifies").Bool(); got != want {
				t.Fatalf("Verifies = %v, want %v", got, want)
			}
			if c.Get("verifies").Bool() {
				priv, _ := vectors.V3Key(t, c.Get("signer").Str())
				again, err := policy.IssueReplyCert(cert.Policy, cert.Svc, cert.Key, cert.NotAfter, priv)
				if err != nil {
					t.Fatalf("IssueReplyCert: %v", err)
				}
				if again != cert {
					t.Fatalf("IssueReplyCert = %+v, want %+v", again, cert)
				}
			}
		})
	})
}

// TestMerkle replays v3.json's merkle section: its leaf and node hashes, and each proof object, read as
// written, proven against the root, read again from its header, and written back as that header.
func TestMerkle(t *testing.T) {
	m := vectors.Load(t, "v3.json").Get("merkle")
	m.Get("leaves").Each(func(name string, l vectors.Node) {
		h, err := policy.LeafHash(decode(t, l.Get("salt").Str()), l.Get("path").Str())
		if err != nil {
			t.Fatalf("leaf %s: LeafHash: %v", name, err)
		}
		if got, want := b64.Encode(h), l.Get("hash").Str(); got != want {
			t.Errorf("leaf %s: LeafHash = %s, want %s", name, got, want)
		}
	})
	m.Get("nodes").Each(func(name string, n vectors.Node) {
		h := policy.NodeHash(decode(t, n.Get("left").Str()), decode(t, n.Get("right").Str()))
		if got, want := b64.Encode(h), n.Get("hash").Str(); got != want {
			t.Errorf("node %s: NodeHash = %s, want %s", name, got, want)
		}
	})

	root := decode(t, m.Get("root").Str())
	headers := m.Get("proofHeaders")
	proofs := 0
	m.Get("proofs").Each(func(route string, n vectors.Node) {
		proofs++
		t.Run(route, func(t *testing.T) {
			// The case gives the proof as an object in this file's own layout; ParseProof reads its wire
			// bytes, the canonical bytes the header's token holds.
			v, err := json.ReadFile(n.With(t).Raw())
			if err != nil {
				t.Fatalf("the proof object does not read: %v", err)
			}
			p, err := policy.ParseProof(canonical(t, v))
			if err != nil {
				t.Fatalf("ParseProof: %v", err)
			}
			if !p.Verify(route, root) {
				t.Fatal("the proof does not prove its route")
			}
			header := headers.With(t).Get(route).Str()
			read, err := policy.ReadProof(header)
			if err != nil {
				t.Fatalf("ReadProof: %v", err)
			}
			if !reflect.DeepEqual(read, p) {
				t.Fatalf("ReadProof = %+v, want %+v", read, p)
			}
			tok, err := p.Token()
			if err != nil {
				t.Fatalf("Token: %v", err)
			}
			if tok != header {
				t.Fatalf("Token = %s, want %s", tok, header)
			}
		})
	})
	if proofs == 0 || headers.Len() != proofs {
		t.Fatalf("%d proofs and %d headers, want as many of each and some", proofs, headers.Len())
	}
}

// TestMerkleLeafBinding replays json.json's merkleLeaf binding: a route holding a lone surrogate, here its
// WTF-8 bytes, has no UTF-8 form, so it has no leaf.
func TestMerkleLeafBinding(t *testing.T) {
	found := 0
	vectors.Load(t, "json.json").Get("bindings").Each(func(name string, c vectors.Node) {
		if c.Get("binding").Str() != "merkleLeaf" {
			return
		}
		found++
		t.Run(name, func(t *testing.T) {
			in := c.With(t).Get("inputs")
			salt, err := hex.DecodeString(in.Get("salt").Str())
			if err != nil {
				t.Fatalf("salt: %v", err)
			}
			if h, err := policy.LeafHash(salt, in.Get("route").Str()); err == nil {
				t.Fatalf("LeafHash hashed it as %x", h)
			}
		})
	})
	if found == 0 {
		t.Fatal("json.json has no merkleLeaf binding case")
	}
}

// TestFileFormat reads json.json's keyring, root, reply certificate and proof bundle files, and writes each
// back as the same text.
func TestFileFormat(t *testing.T) {
	kinds := map[string]bool{}
	vectors.Load(t, "json.json").Get("fileFormat").Each(func(name string, c vectors.Node) {
		if c.Get("kind").IsNull() {
			return
		}
		kind := c.Get("kind").Str()
		if kind == "rules" {
			return // the MCP profile's local rules
		}
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			file := []byte(c.Get("file").Str())
			var got []byte
			var err error
			switch kind {
			case "keyring":
				var kf policy.KeyringFile
				if kf, err = policy.ParseKeyringFile(file); err == nil {
					got, err = kf.File()
				}
			case "root":
				var r policy.Root
				if r, err = policy.ParseRootFile(file); err == nil {
					got, err = r.File()
				}
			case "replyCert":
				var cert policy.ReplyCert
				if cert, err = policy.ParseReplyCertFile(file); err == nil {
					got, err = asFile(cert.Wire())
				}
			case "proofs":
				var b policy.ProofBundle
				if b, err = policy.ParseProofBundleFile(file); err == nil {
					got, err = asFile(json.Wire(bundleValue(t, b)))
				}
			default:
				t.Fatalf("a file of kind %q", kind)
			}
			kinds[kind] = true
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, file) {
				t.Fatalf("wrote\n%s\nwant\n%s", got, file)
			}
		})
	})
	for _, kind := range []string{"keyring", "root", "replyCert", "proofs"} {
		if !kinds[kind] {
			t.Errorf("json.json has no %s file", kind)
		}
	}
}

// bundleValue returns b as its file holds it. The SDK reads bundles and never writes them, so the writer
// lives here.
func bundleValue(t *testing.T, b policy.ProofBundle) json.Value {
	t.Helper()
	var proofs []json.Member
	for route, p := range b.Proofs {
		proofs = append(proofs, json.Member{Name: route, Value: readBack(t)(p.Wire())})
	}
	return json.Obj(
		json.Member{Name: "proofs", Value: json.Obj(proofs...)},
		json.Member{Name: "rootId", Value: json.S(b.RootID)},
		json.Member{Name: "service", Value: json.S(b.Service)},
	)
}

// asFile returns wire bytes, read back, in the file form.
func asFile(wire []byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	v, err := json.ReadWire(wire)
	if err != nil {
		return nil, err
	}
	return json.File(v)
}

// readBack returns a function that reads back the wire bytes a writer gave, failing t if either refused.
func readBack(t *testing.T) func([]byte, error) json.Value {
	return func(wire []byte, err error) json.Value {
		t.Helper()
		if err != nil {
			t.Fatalf("the writer refused: %v", err)
		}
		v, err := json.ReadWire(wire)
		if err != nil {
			t.Fatalf("the wire bytes do not read: %v", err)
		}
		return v
	}
}

// canonical returns v's wire bytes, failing t if the writer refuses it.
func canonical(t *testing.T, v json.Value) []byte {
	t.Helper()
	b, err := json.Wire(v)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b
}

// refused checks a read of case c's file against the case: the reader refuses the file exactly when the case
// gives no signing bytes. It reports whether the file was refused.
func refused(t *testing.T, c vectors.Node, err error) bool {
	t.Helper()
	want := c.Get("signingBytes").IsNull()
	if err == nil {
		if want {
			t.Fatal("the reader kept a file the case refuses")
		}
		return false
	}
	if !want {
		t.Fatalf("the reader refused the file: %v", err)
	}
	return true
}

// current checks isCurrent against case c's current answers, if it gives any.
func current(t *testing.T, c vectors.Node, isCurrent func(int64) bool) {
	t.Helper()
	if !c.Has("current") {
		return
	}
	c.Get("current").Each(func(_ string, a vectors.Node) {
		at := a.Get("at").Int()
		if got, want := isCurrent(at), a.Get("current").Bool(); got != want {
			t.Errorf("Current(%d) = %v, want %v", at, got, want)
		}
	})
}

// equalText checks signing bytes against their base64url text in a case.
func equalText(t *testing.T, what string, msg []byte, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if got := b64.Encode(msg); got != want {
		t.Fatalf("%s = %s, want %s", what, got, want)
	}
}

func decode(t testing.TB, s string) []byte {
	t.Helper()
	b, err := b64.Decode(s)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	return b
}
