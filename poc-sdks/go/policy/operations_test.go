// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// readTable reads a table file, failing t if it is refused.
func readTable(t *testing.T, file string) policy.OperationTable {
	t.Helper()
	table, err := policy.ReadOperationTable([]byte(file))
	if err != nil {
		t.Fatalf("ReadOperationTable: %v", err)
	}
	return table
}

// TestOperationsVectors replays http-v3.json's operations cases: the tables as read, hashed and routed, the
// files refused, the operation each call matches and the key value it gives.
func TestOperationsVectors(t *testing.T) {
	ops := vectors.Load(t, "http-v3.json").Get("operations")

	for _, name := range []string{"table", "shared", "keyed"} {
		t.Run(name, func(t *testing.T) {
			c := ops.Get(name).With(t)
			table := readTable(t, c.Get("file").Str())
			if table.Service != c.Get("value").Get("service").Str() ||
				len(table.Operations) != c.Get("value").Get("operations").Len() {
				t.Errorf("read %+v, other than the case's value", table)
			}
			hash, err := table.Hash()
			if err != nil || hash != c.Get("opsHash").Str() {
				t.Errorf("Hash = %q, %v, want %s", hash, err, c.Get("opsHash").Str())
			}
			route, err := table.Route()
			if want := c.Get("route").Strs(); err != nil || !reflect.DeepEqual(route, want) {
				t.Errorf("Route = %v, %v, want %v", route, err, want)
			}
		})
	}

	ops.Get("refused").Each(func(name string, c vectors.Node) {
		t.Run("refused/"+name, func(t *testing.T) {
			c := c.With(t)
			if table, err := policy.ReadOperationTable([]byte(c.Get("file").Str())); err == nil {
				t.Fatalf("ReadOperationTable kept %+v", table)
			}
		})
	})

	query := func(c vectors.Node) string {
		if c.Get("query").IsNull() {
			return ""
		}
		return c.Get("query").Str()
	}
	ops.Get("match").Each(func(name string, c vectors.Node) {
		t.Run("match/"+name, func(t *testing.T) {
			c := c.With(t)
			table := readTable(t, c.Get("table").Str())
			got, ok := table.Match(c.Get("method").Str(), c.Get("path").Str(), query(c))
			if c.Get("expected").IsNull() {
				if ok {
					t.Fatalf("Match = %q, want none", got)
				}
				return
			}
			if !ok || got != c.Get("expected").Str() {
				t.Fatalf("Match = %q, %v, want %q", got, ok, c.Get("expected").Str())
			}
		})
	})
	ops.Get("keys").Each(func(name string, c vectors.Node) {
		t.Run("keys/"+name, func(t *testing.T) {
			c := c.With(t)
			table := readTable(t, c.Get("table").Str())
			want := c.Get("expected")
			operation, ok := table.Match(c.Get("method").Str(), c.Get("path").Str(), query(c))
			if want.Get("operation").IsNull() {
				if ok {
					t.Fatalf("Match = %q, want none", operation)
				}
				return
			}
			if !ok || operation != want.Get("operation").Str() {
				t.Fatalf("Match = %q, %v, want %q", operation, ok, want.Get("operation").Str())
			}
			key, ok := table.KeyValue(operation, c.Get("path").Str(), query(c))
			if want.Get("key").IsNull() {
				if ok {
					t.Fatalf("KeyValue = %q, want none", key)
				}
				return
			}
			if !ok || key != want.Get("key").Str() {
				t.Fatalf("KeyValue = %q, %v, want %q", key, ok, want.Get("key").Str())
			}
		})
	})
}

// TestOperationTableKeepsMaxLengthAsRead holds a table to its file: a maxLength written as the default hashes
// to its own text, and differs from the table that leaves it out.
func TestOperationTableKeepsMaxLengthAsRead(t *testing.T) {
	file := func(key string) string {
		return `{"operations":[{"key":` + key + `,"method":"GET","name":"get","template":"/r/{}"}],` +
			`"service":"s","v":1}`
	}
	left := readTable(t, file(`{"segment":1}`))
	written := readTable(t, file(`{"maxLength":128,"segment":1}`))
	if left.Operations[0].Key.MaxLength != nil || *written.Operations[0].Key.MaxLength != 128 {
		t.Fatalf("read %+v and %+v, want maxLength left out and written", left, written)
	}
	if left.Operations[0].Key.Limit() != 128 || written.Operations[0].Key.Limit() != 128 {
		t.Errorf("the limit of both is not 128")
	}
	a, _ := left.Hash()
	b, _ := written.Hash()
	if a == b {
		t.Errorf("a written default maxLength hashes as one left out: %s", a)
	}
}

// TestOperationTableRefuses reads tables the rules refuse, each for one fault; a refusal quotes nothing.
func TestOperationTableRefuses(t *testing.T) {
	op := func(extra string) string {
		return `{"operations":[{` + extra + `"method":"GET","name":"secretop","template":"/r/{}"}],"service":"s","v":1}`
	}
	for name, text := range map[string]string{
		"a segment key of 0":                op(`"key":{"segment":0},`),
		"a segment key beyond the template": op(`"key":{"segment":2},`),
		"a key of both":                     op(`"key":{"query":"a","segment":1},`),
		"a key of neither":                  op(`"key":{},`),
		"a segment given as a string":       op(`"key":{"segment":"1"},`),
		"a maxLength given as a string":     op(`"key":{"maxLength":"9","segment":1},`),
		"a maxLength of 0":                  op(`"key":{"maxLength":0,"segment":1},`),
		"a maxLength of 1025":               op(`"key":{"maxLength":1025,"segment":1},`),
		"a key query that is empty":         op(`"key":{"query":""},`),
		"a key with an extra member":        op(`"key":{"segment":1,"secret":1},`),
		"a key query named by a condition": `{"operations":[{"method":"GET","name":"a","query":{"m":"x"},` +
			`"template":"/r","key":{"query":"m"}},{"method":"GET","name":"b","template":"/r"}],"service":"s","v":1}`,
		"a version of 2":   `{"operations":[{"method":"GET","name":"a","template":"/"}],"service":"s","v":2}`,
		"a service with #": `{"operations":[{"method":"GET","name":"a","template":"/"}],"service":"s#t","v":1}`,
		"no operations":    `{"operations":[],"service":"s","v":1}`,
	} {
		if table, err := policy.ReadOperationTable([]byte(text)); err == nil {
			t.Errorf("%s: ReadOperationTable kept %+v", name, table)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the refusal quotes the file: %v", name, err)
		}
	}
}

// TestOperationTableKeyed answers whether an operation declares a key.
func TestOperationTableKeyed(t *testing.T) {
	table := readTable(t, vectors.Load(t, "http-v3.json").Get("operations").Get("keyed").Get("file").Str())
	for operation, want := range map[string]bool{"reserve": true, "getLine": true, "createOrder": false, "nope": false} {
		if got := table.Keyed(operation); got != want {
			t.Errorf("Keyed(%q) = %v, want %v", operation, got, want)
		}
	}
}

// TestOperationTableQueryKeyValue reads a query key: a server decodes parameter names, and some split a
// query at ';', so the handler could read another line than the one counted, and the key gives none then.
// Values of other parameters are not restricted.
func TestOperationTableQueryKeyValue(t *testing.T) {
	table := readTable(t, vectors.Load(t, "http-v3.json").Get("operations").Get("keyed").Get("file").Str())
	for query, want := range map[string]string{
		"line=A":            "A",
		"line=A&q=%41":      "A",
		"%6Cine=B&line=A":   "",
		"x=1;line=B&line=A": "",
		"a%5B%5D=1&line=A":  "",
	} {
		if got, ok := table.KeyValue("getLine", "/lines", query); got != want || ok != (want != "") {
			t.Errorf("KeyValue(%q) = %q, %v, want %q", query, got, ok, want)
		}
	}
	if operation, ok := table.Match("GET", "/lines", "%6Cine=B&line=A"); !ok || operation != "getLine" {
		t.Errorf("Match = %q, %v, want getLine", operation, ok)
	}
}

// TestOperationTableCoveredBy holds a table to the signed root: the bundle holds a proof of its route that
// verifies against the root with the proof's rootId.
func TestOperationTableCoveredBy(t *testing.T) {
	ops := vectors.Load(t, "http-v3.json").Get("operations")
	table := readTable(t, ops.Get("keyed").Get("file").Str())
	route := strings.Join(ops.Get("keyed").Get("route").Strs(), "/")

	m := vectors.RulesMaterial(t, "shop-keys")
	root, err := policy.ParseRootFile(m.Root)
	if err != nil {
		t.Fatal(err)
	}
	bundle := policy.ProofBundle{Service: "orders", RootID: root.RootID, Proofs: map[string]policy.Proof{}}
	for _, p := range m.Proofs {
		v, err := json.ReadFile(p.Text)
		if err != nil {
			t.Fatalf("proof %s: %v", p.Route, err)
		}
		canonical, err := json.Wire(v)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := policy.ParseProof(canonical)
		if err != nil {
			t.Fatalf("proof %s: %v", p.Route, err)
		}
		bundle.Proofs[p.Route] = proof
	}
	if _, ok := bundle.ProofFor(route); !ok {
		t.Fatalf("the material holds no proof for %s", route)
	}

	if !table.CoveredBy(bundle, []policy.Root{root}) {
		t.Error("CoveredBy = false for the table its root covers")
	}
	other := policy.Root{RootID: "another", Root: root.Root, Sig: root.Sig, NotAfter: root.NotAfter}
	if table.CoveredBy(bundle, []policy.Root{other}) {
		t.Error("CoveredBy = true against a root with another rootId")
	}
	if table.CoveredBy(bundle, nil) {
		t.Error("CoveredBy = true with no roots")
	}
	bare := policy.ProofBundle{Service: "orders", RootID: root.RootID, Proofs: map[string]policy.Proof{}}
	if table.CoveredBy(bare, []policy.Root{root}) {
		t.Error("CoveredBy = true for a bundle without the route")
	}
	bad := bundle.Proofs[route]
	bad.Dirs = "x"
	malformed := policy.ProofBundle{Proofs: map[string]policy.Proof{route: bad}}
	if table.CoveredBy(malformed, []policy.Root{root}) {
		t.Error("CoveredBy = true for a malformed proof")
	}
	shared := readTable(t, ops.Get("table").Get("file").Str())
	if shared.CoveredBy(bundle, []policy.Root{root}) {
		t.Error("CoveredBy = true for another table")
	}
}

// TestOperationTableKeySegmentRange names the range rule for a segment below 1 or beyond an int.
func TestOperationTableKeySegmentRange(t *testing.T) {
	for _, segment := range []string{"0", "2147483648"} {
		text := `{"operations":[{"key":{"segment":` + segment +
			`},"method":"GET","name":"a","template":"/r/{}"}],"service":"s","v":1}`
		_, err := policy.ReadOperationTable([]byte(text))
		if err == nil || !strings.HasSuffix(err.Error(), "a key segment must be from 1 to the number of {} segments") {
			t.Errorf("segment %s: got %v, want the range rule", segment, err)
		}
	}
}
