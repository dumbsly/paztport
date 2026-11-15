// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp_test

import (
	"encoding/hex"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// TestSigningBytes replays v3.json's signingBytes: each case's stamp signs exactly the bytes its hex gives.
func TestSigningBytes(t *testing.T) {
	cases := vectors.Load(t, "v3.json").Get("signingBytes")
	if cases.Len() == 0 {
		t.Fatal("v3.json has no signingBytes case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			n := c.Get("stamp")
			if v := n.Get("v").Int(); v != 3 {
				t.Fatalf("the case's stamp has v %d", v)
			}
			got, err := fields(n).SigningBytes()
			if err != nil {
				t.Fatalf("SigningBytes: %v", err)
			}
			if want := c.Get("hex").Str(); hex.EncodeToString(got) != want {
				t.Fatalf("SigningBytes = %x, want %s", got, want)
			}
		})
	})
}

// TestSignatures replays v3.json's signatures: each case's fields, signed with its key, give its sig, and
// the sig verifies under the key's public half over the stamp's signing bytes.
func TestSignatures(t *testing.T) {
	cases := vectors.Load(t, "v3.json").Get("signatures")
	if cases.Len() == 0 {
		t.Fatal("v3.json has no signatures case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			priv, pub := vectors.V3Key(t, c.Get("key").Str())
			f := fields(c.Get("fields"))
			s, err := stamp.Sign(f, priv)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if want := c.Get("sig").Str(); s.Sig != want {
				t.Fatalf("Sign gave sig %s, want %s", s.Sig, want)
			}
			if f.Sig = s.Sig; s != f {
				t.Fatalf("Sign changed a field: %+v, want %+v", s, f)
			}
			msg, err := s.SigningBytes()
			if err != nil {
				t.Fatalf("SigningBytes: %v", err)
			}
			sig, err := b64.Decode(s.Sig)
			if err != nil || !keys.Verify(pub, msg, sig) {
				t.Fatal("the sig does not verify over the stamp's signing bytes")
			}
		})
	})
}

// TestBindPrompt replays v3.json's bindPrompt.
func TestBindPrompt(t *testing.T) {
	c := vectors.Load(t, "v3.json").Get("bindPrompt")
	got, err := stamp.PromptBinding(c.Get("prompt").Str())
	if err != nil {
		t.Fatalf("PromptBinding: %v", err)
	}
	if want := c.Get("expected").Str(); got != want {
		t.Fatalf("PromptBinding = %s, want %s", got, want)
	}
}

// TestBindResponse replays v3.json's bindResponse, its labels read from their wire bytes.
func TestBindResponse(t *testing.T) {
	c := vectors.Load(t, "v3.json").Get("bindResponse")
	got, err := stamp.ResponseBinding(c.Get("resultHash").Str(), c.Get("callId").Str(), labels(t, c.Get("labels")))
	if err != nil {
		t.Fatalf("ResponseBinding: %v", err)
	}
	if want := c.Get("expected").Str(); got != want {
		t.Fatalf("ResponseBinding = %s, want %s", got, want)
	}
}

// TestBindingRefusals replays json.json's prompt and response bindings, each given a lone surrogate in one
// string it hashes. The harness hands it over as the Go string that stands for it, which is not valid
// UTF-8, and the binding refuses it.
func TestBindingRefusals(t *testing.T) {
	found := map[string]int{}
	vectors.Load(t, "json.json").Get("bindings").Each(func(name string, c vectors.Node) {
		kind := c.Get("binding").Str()
		if kind != "prompt" && kind != "response" {
			return
		}
		found[kind]++
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if !c.Get("expected").IsNull() {
				t.Fatal("the case expects a binding; only refusals are replayed here")
			}
			in := c.Get("inputs")
			var got string
			var err error
			if kind == "prompt" {
				got, err = stamp.PromptBinding(in.Get("text").Str())
			} else {
				got, err = stamp.ResponseBinding(in.Get("resultHash").Str(), in.Get("toolCallId").Str(),
					labels(t, in.Get("labels")))
			}
			if err == nil {
				t.Fatalf("the binding was computed as %s", got)
			}
		})
	})
	if found["prompt"] == 0 || found["response"] == 0 {
		t.Fatalf("json.json's bindings lack a prompt or a response case: %v", found)
	}
}

// fields returns the stamp vector node n describes, without a sig.
func fields(n vectors.Node) stamp.Stamp {
	return stamp.Stamp{
		Svc:  n.Get("svc").Str(),
		Inst: n.Get("inst").Str(),
		RID:  n.Get("rid").Str(),
		TS:   n.Get("ts").Int(),
		Sess: n.Get("sess").Str(),
		Rcv:  n.Get("rcv").Str(),
		Bind: n.Get("bind").Str(),
		Infl: n.Get("infl").Str(),
		Prev: n.Get("prev").Str(),
	}
}

// labels reads the labels vector node n lists from their wire bytes, failing t if ParseLabels refuses them.
func labels(t *testing.T, n vectors.Node) []influence.Label {
	t.Helper()
	var items []json.Value
	n.Each(func(_ string, l vectors.Node) {
		var members []json.Member
		l.Each(func(name string, v vectors.Node) {
			members = append(members, json.Member{Name: name, Value: json.S(v.Str())})
		})
		items = append(items, json.Obj(members...))
	})
	b, err := json.Wire(json.Arr(items...))
	if err != nil {
		t.Fatalf("the labels can't be written: %v", err)
	}
	ls, err := influence.ParseLabels(b)
	if err != nil {
		t.Fatalf("ParseLabels: %v", err)
	}
	return ls
}

// TestBlocksRead replays v4.json's blocks.read: each token reads as a request's blocks exactly when the case
// says OK, and where it does the blocks' wire bytes are the canonical bytes of the case's blocks.
func TestBlocksRead(t *testing.T) {
	cases := vectors.Load(t, "v4.json").Get("blocks").Get("read")
	if cases.Len() == 0 {
		t.Fatal("v4.json has no blocks.read case")
	}
	var read, refused int
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			got, err := stamp.ReadBlocks(c.Get("token").Str())
			switch want := c.Get("expected").Str(); want {
			case "OK":
				read++
				if err != nil {
					t.Fatalf("ReadBlocks: %v", err)
				}
				if !c.Has("blocks") {
					return
				}
				v, err := json.ReadFile(c.Get("blocks").Raw())
				if err != nil {
					t.Fatalf("the case's blocks: %v", err)
				}
				canonical, err := json.Wire(v)
				if err != nil {
					t.Fatalf("the case's blocks have no canonical bytes: %v", err)
				}
				wire, err := got.Wire()
				if err != nil || string(wire) != string(canonical) {
					t.Fatalf("Wire = %s, %v, want %s", wire, err, canonical)
				}
			case "REFUSED":
				refused++
				if err == nil {
					t.Fatalf("ReadBlocks read %v, want an error", got)
				}
			default:
				t.Fatalf("expected is %q", want)
			}
		})
	})
	if read == 0 || refused == 0 {
		t.Fatalf("the cases hold %d that read and %d that do not; each outcome must be covered", read, refused)
	}
}

// TestBlocksCommit replays v4.json's blocks.commit: each block's wire bytes are its jcs and its commitment
// is its ext.
func TestBlocksCommit(t *testing.T) {
	cases := vectors.Load(t, "v4.json").Get("blocks").Get("commit")
	if cases.Len() == 0 {
		t.Fatal("v4.json has no blocks.commit case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			// the case's block, canonicalised as TestBlocksRead does, read as the one element of an array
			v, err := json.ReadFile(c.Get("block").Raw())
			if err != nil {
				t.Fatalf("the case's block: %v", err)
			}
			canonical, err := json.Wire(v)
			if err != nil {
				t.Fatalf("the case's block has no canonical bytes: %v", err)
			}
			got, err := stamp.ParseBlocks(append(append([]byte("["), canonical...), ']'))
			if err != nil || len(got) != 1 {
				t.Fatalf("ParseBlocks: %v, %v", got, err)
			}
			if string(got[0].Wire()) != c.Get("jcs").Str() {
				t.Fatalf("Wire = %s, want %s", got[0].Wire(), c.Get("jcs").Str())
			}
			if got[0].Commit() != c.Get("ext").Str() {
				t.Fatalf("Commit = %q, want %q", got[0].Commit(), c.Get("ext").Str())
			}
		})
	})
}
