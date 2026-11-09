// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// OperationTable is a service's operation table, ops-<service>.json: the operations an HTTP service names,
// each a method and a path template, and where an entrance serves several, a query condition. A caller that
// holds the table names the operation each call invokes in its stamp's rcv (orders#createOrder), using
// [OperationTable.Match] to find it; the receiver confirms its operation from its own routing.
//
// The signed root covers a table as the route <service>/ops:<hash>, see [OperationTable.Route].
//
// A template is "/", or "/" and non-empty segments joined with "/", each "{}", which matches any one
// non-empty segment, or literal text, which matches itself.
type OperationTable struct {
	// Service is the service the table is for: a route node holding no '#'.
	Service string
	// Operations are the table's operations, in file order; there is at least one.
	Operations []Operation
}

// Operation is one operation of a table.
type Operation struct {
	// Name is the operation's name, a route node holding no '#'.
	Name string
	// Method is the HTTP method: one or more of the characters A to Z.
	Method string
	// Template is the path template.
	Template string
	// Query is the condition that tells the operation apart from others of its entrance, or nil for none.
	Query *Condition
	// Key is the key the operation declares, or nil for none.
	Key *Key
}

// Condition is a query condition: the call's query holds the parameter Parameter with the value Value.
type Condition struct {
	Parameter, Value string
}

// Key is the key of an operation: what names the item a call acts on. It is either the "{}" segment of the
// template at position Segment (from 1, counted over the "{}" segments) with Query empty, or the query
// parameter Query with Segment 0.
type Key struct {
	Segment int
	Query   string
	// MaxLength is the longest key value, or nil where the file leaves it out, which is [DefaultKeyLength].
	// A table is hashed as read, so a file that writes the default hashes differently from one that leaves it
	// out.
	MaxLength *int
}

const (
	// DefaultKeyLength is the longest key value when a key gives no maxLength.
	DefaultKeyLength = 128
	// MaxKeyLength is the largest maxLength a file may give.
	MaxKeyLength = 1024

	parameterSegment = "{}"
	operationsDomain = "operations\n"
)

// Limit returns the longest key value: MaxLength, or [DefaultKeyLength] where the file left it out.
func (k Key) Limit() int {
	if k.MaxLength == nil {
		return DefaultKeyLength
	}
	return *k.MaxLength
}

var (
	tableMembers      = []string{"operations", "service", "v"}
	operationRequired = []string{"method", "name", "template"}
	operationOptional = []string{"key", "query"}
	keyMembers        = []string{"maxLength", "query", "segment"}
)

// ReadOperationTable reads the text of a table file: an object of exactly v (1), service and operations, an
// array of objects of method, name and template, and optionally key and query. Every rule of a table is
// checked, and the error names the first broken, never a value.
func ReadOperationTable(b []byte) (OperationTable, error) {
	return parseFile(b, "operation table", tableFromValue)
}

// LoadOperationTable reads the table file at path, as [ReadOperationTable] reads bytes.
func LoadOperationTable(path string) (OperationTable, error) {
	return loadFile(path, "operation table", tableFromValue)
}

func tableFromValue(v json.Value) (OperationTable, error) {
	if err := json.Exactly(v, tableMembers, nil); err != nil {
		return OperationTable{}, err
	}
	version, err := json.Integer(v, "v")
	if err != nil {
		return OperationTable{}, err
	}
	if version != 1 {
		return OperationTable{}, errors.New(`the member "v" is not 1`)
	}
	service, err := json.String(v, "service")
	if err != nil {
		return OperationTable{}, err
	}
	field, _ := json.Field(v, "operations")
	if field.Kind() != json.KindArray {
		return OperationTable{}, errors.New(`the member "operations" is not an array`)
	}
	var ops []Operation
	for _, item := range field.Items() {
		op, err := operationFromValue(item)
		if err != nil {
			return OperationTable{}, err
		}
		ops = append(ops, op)
	}
	t := OperationTable{Service: service, Operations: ops}
	if err := t.validate(); err != nil {
		return OperationTable{}, err
	}
	return t, nil
}

func operationFromValue(v json.Value) (Operation, error) {
	if err := json.Exactly(v, operationRequired, operationOptional); err != nil {
		return Operation{}, err
	}
	var op Operation
	var err error
	if op.Name, err = json.String(v, "name"); err != nil {
		return Operation{}, err
	}
	if op.Method, err = json.String(v, "method"); err != nil {
		return Operation{}, err
	}
	if op.Template, err = json.String(v, "template"); err != nil {
		return Operation{}, err
	}
	if q, ok := json.Field(v, "query"); ok {
		if q.Kind() != json.KindObject || len(q.Members()) != 1 {
			return Operation{}, errors.New(`the member "query" is not an object of exactly one member`)
		}
		m := q.Members()[0]
		if m.Value.Kind() != json.KindString {
			return Operation{}, errors.New(`the member "query" does not hold a string`)
		}
		op.Query = &Condition{Parameter: m.Name, Value: m.Value.Str()}
	}
	if k, ok := json.Field(v, "key"); ok {
		key, err := keyFromValue(k)
		if err != nil {
			return Operation{}, err
		}
		op.Key = &key
	}
	return op, nil
}

func keyFromValue(v json.Value) (Key, error) {
	if err := json.Exactly(v, nil, keyMembers); err != nil {
		return Key{}, err
	}
	var k Key
	_, hasSegment := json.Field(v, "segment")
	_, hasQuery := json.Field(v, "query")
	if hasSegment == hasQuery {
		return Key{}, errors.New("a key must have exactly one of segment and query")
	}
	if hasSegment {
		n, err := json.Integer(v, "segment")
		if err != nil {
			return Key{}, err
		}
		if n < 1 || n > 1<<31-1 {
			return Key{}, errors.New("a key segment must be 1 or more")
		}
		k.Segment = int(n)
	} else {
		q, err := json.String(v, "query")
		if err != nil {
			return Key{}, err
		}
		k.Query = q
		if err := validToken(q, "a key query parameter name"); err != nil {
			return Key{}, err
		}
	}
	if _, ok := json.Field(v, "maxLength"); ok {
		n, err := json.Integer(v, "maxLength")
		if err != nil {
			return Key{}, err
		}
		if n < 1 || n > MaxKeyLength {
			return Key{}, fmt.Errorf("a key maxLength must be from 1 to %d", MaxKeyLength)
		}
		l := int(n)
		k.MaxLength = &l
	}
	return k, nil
}

// validate checks every rule of the table: a valid service, at least one operation, unique valid names,
// methods, templates, conditions, entrances and keys.
func (t OperationTable) validate() error {
	if err := ValidService(t.Service); err != nil {
		return err
	}
	if len(t.Operations) == 0 {
		return errors.New("operations must not be empty")
	}
	names := map[string]bool{}
	entrances := map[string]map[string]bool{} // entrance -> condition values seen, "" key marked by noCondition
	parameters := map[string]string{}
	const noCondition = "\x00none"
	for _, o := range t.Operations {
		if err := ValidService(o.Name); err != nil {
			return fmt.Errorf("an operation name is not valid: %w", err)
		}
		if names[o.Name] {
			return errors.New("two operations have one name")
		}
		names[o.Name] = true
		if o.Method == "" || strings.Trim(o.Method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return errors.New("method must be one or more of the characters A to Z")
		}
		if err := validTemplate(o.Template); err != nil {
			return err
		}
		entrance := o.Method + " " + o.Template
		seen := noCondition
		if q := o.Query; q != nil {
			if err := validToken(q.Parameter, "a query parameter name"); err != nil {
				return err
			}
			if err := validToken(q.Value, "a query value"); err != nil {
				return err
			}
			if p, ok := parameters[entrance]; ok && p != q.Parameter {
				return errors.New("the query conditions of one entrance name different parameters")
			}
			parameters[entrance] = q.Parameter
			seen = q.Value
		}
		if entrances[entrance] == nil {
			entrances[entrance] = map[string]bool{}
		}
		if entrances[entrance][seen] {
			if seen == noCondition {
				return errors.New("two operations of one entrance have no query condition")
			}
			return errors.New("two operations of one entrance share a query condition")
		}
		entrances[entrance][seen] = true
	}
	for _, o := range t.Operations {
		k := o.Key
		if k == nil {
			continue
		}
		if k.Query == "" {
			slots := 0
			for _, s := range strings.Split(o.Template[1:], "/") {
				if s == parameterSegment {
					slots++
				}
			}
			if k.Segment > slots {
				return errors.New("a key segment is beyond the {} segments of its template")
			}
		} else if k.Query == parameters[o.Method+" "+o.Template] {
			return errors.New("a key query parameter is named by a query condition of its entrance")
		}
	}
	return nil
}

func validTemplate(template string) error {
	if !strings.HasPrefix(template, "/") {
		return errors.New("template must start with /")
	}
	if template == "/" {
		return nil
	}
	for _, s := range strings.Split(template[1:], "/") {
		if s == "" {
			return errors.New("template has an empty segment")
		}
		if s != parameterSegment && strings.ContainsAny(s, "{}?#") {
			return errors.New("template segment must be {} or literal text without any of { } ? #")
		}
	}
	return nil
}

// isToken reports whether s is one or more of A-Z a-z 0-9 - . _ ~.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0) {
			return false
		}
	}
	return true
}

func validToken(s, what string) error {
	if !isToken(s) {
		return errors.New(what + " must be one or more of the characters A-Z a-z 0-9 - . _ ~")
	}
	return nil
}

// value returns the table as read, in the JSON form its hash covers; the writer puts members in order.
func (t OperationTable) value() json.Value {
	items := make([]json.Value, 0, len(t.Operations))
	for _, op := range t.Operations {
		var m []json.Member
		if k := op.Key; k != nil {
			var km []json.Member
			if k.MaxLength != nil {
				km = append(km, json.Member{Name: "maxLength", Value: json.I(int64(*k.MaxLength))})
			}
			if k.Query != "" {
				km = append(km, json.Member{Name: "query", Value: json.S(k.Query)})
			} else {
				km = append(km, json.Member{Name: "segment", Value: json.I(int64(k.Segment))})
			}
			m = append(m, json.Member{Name: "key", Value: json.Obj(km...)})
		}
		m = append(m, json.Member{Name: "method", Value: json.S(op.Method)}, json.Member{Name: "name", Value: json.S(op.Name)})
		if q := op.Query; q != nil {
			m = append(m, json.Member{Name: "query", Value: json.Obj(json.Member{Name: q.Parameter, Value: json.S(q.Value)})})
		}
		m = append(m, json.Member{Name: "template", Value: json.S(op.Template)})
		items = append(items, json.Obj(m...))
	}
	return json.Obj(
		json.Member{Name: "operations", Value: json.Arr(items...)},
		json.Member{Name: "service", Value: json.S(t.Service)},
		json.Member{Name: "v", Value: json.I(1)},
	)
}

// Hash returns b64url(SHA-256("operations\n" || JCS(table))), the table as read.
func (t OperationTable) Hash() (string, error) {
	body, err := wire("operation table", t.value())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(operationsDomain), body...))
	return b64.Encode(sum[:]), nil
}

// Route returns the route the signed root covers the table as: the service, then "ops:<hash>".
func (t OperationTable) Route() ([]string, error) {
	h, err := t.Hash()
	if err != nil {
		return nil, err
	}
	return []string{t.Service, "ops:" + h}, nil
}

// CoveredBy reports whether bundle holds a proof for the table's route that verifies against the root, among
// roots, with the proof's RootID. A proof that is malformed, or a table that can't be hashed, is no proof.
func (t OperationTable) CoveredBy(bundle ProofBundle, roots []Root) bool {
	route, err := t.Route()
	if err != nil {
		return false
	}
	r := JoinRoute(route...)
	p, ok := bundle.ProofFor(r)
	if !ok {
		return false
	}
	for _, root := range roots {
		if root.RootID != p.RootID {
			continue
		}
		b, err := root.Bytes()
		if err == nil && p.Verify(r, b) {
			return true
		}
	}
	return false
}

// Match returns the name of the operation a call invokes, and whether one matches. rawPath is the path as
// sent: no query and not percent-decoded; rawQuery is the query as sent, also not decoded, "" for none. A call
// that repeats a parameter an entrance's condition names matches none of that entrance's operations. Of the
// templates that match, the one with a literal segment at the first segment where they differ wins, and of one
// entrance the operation whose condition holds wins over the one with none.
func (t OperationTable) Match(method, rawPath, rawQuery string) (string, bool) {
	if !strings.HasPrefix(rawPath, "/") {
		return "", false
	}
	path := strings.Split(rawPath[1:], "/")
	var best *Operation
	var bestSegments []string
	for i := range t.Operations {
		op := &t.Operations[i]
		if op.Method != method {
			continue
		}
		segments := strings.Split(op.Template[1:], "/")
		if !segmentsMatch(segments, path) || !t.queryAllows(op, rawQuery) {
			continue
		}
		if best == nil || prefersLiteral(segments, bestSegments) ||
			(op.Template == best.Template && op.Query != nil && best.Query == nil) {
			best, bestSegments = op, segments
		}
	}
	if best == nil {
		return "", false
	}
	return best.Name, true
}

// Keyed reports whether the table has an operation of that name that declares a key.
func (t OperationTable) Keyed(operation string) bool {
	op := t.operation(operation)
	return op != nil && op.Key != nil
}

// KeyValue returns the key value of a call to operation, read from the raw target as [OperationTable.Match]
// reads it, and whether the call gives one. It gives none when the operation is unknown or declares no key; the
// path does not match the operation's template; for a query key, rawQuery ("" for none) does not hold the
// parameter exactly once with a value; or the text is not one or more of A-Z a-z 0-9 - . _ ~, is "." or "..",
// or is longer than the key's limit. Nothing is percent-decoded, so an encoded value gives none.
func (t OperationTable) KeyValue(operation, rawPath, rawQuery string) (string, bool) {
	op := t.operation(operation)
	if op == nil || op.Key == nil || !strings.HasPrefix(rawPath, "/") {
		return "", false
	}
	template := strings.Split(op.Template[1:], "/")
	path := strings.Split(rawPath[1:], "/")
	if !segmentsMatch(template, path) {
		return "", false
	}
	value := ""
	if op.Key.Query == "" {
		slot := 0
		for i, s := range template {
			if s == parameterSegment {
				if slot++; slot == op.Key.Segment {
					value = path[i]
					break
				}
			}
		}
	} else {
		count := 0
		for _, pair := range strings.Split(rawQuery, "&") {
			name, v, _ := strings.Cut(pair, "=")
			if name == op.Key.Query {
				count++
				value = v
			}
		}
		if count != 1 {
			return "", false
		}
	}
	if value == "" || len(value) > op.Key.Limit() || value == "." || value == ".." || !isToken(value) {
		return "", false
	}
	return value, true
}

func (t OperationTable) operation(name string) *Operation {
	for i := range t.Operations {
		if t.Operations[i].Name == name {
			return &t.Operations[i]
		}
	}
	return nil
}

// queryAllows reports whether the query lets op match: its condition holds, or it has none and the call does
// not repeat the parameter that the conditions of its entrance name.
func (t OperationTable) queryAllows(op *Operation, rawQuery string) bool {
	parameter := ""
	if op.Query != nil {
		parameter = op.Query.Parameter
	}
	for _, other := range t.Operations {
		if parameter == "" && other.Query != nil && other.Method == op.Method && other.Template == op.Template {
			parameter = other.Query.Parameter
		}
	}
	if parameter == "" {
		return true
	}
	count, value := 0, ""
	for _, pair := range strings.Split(rawQuery, "&") {
		name, v, _ := strings.Cut(pair, "=")
		if name == parameter {
			count++
			value = v
		}
	}
	if count > 1 {
		return false
	}
	return op.Query == nil || (count == 1 && op.Query.Value == value)
}

func segmentsMatch(template, path []string) bool {
	if len(template) != len(path) {
		return false
	}
	for i := range template {
		if template[i] == parameterSegment {
			if path[i] == "" {
				return false
			}
		} else if template[i] != path[i] {
			return false
		}
	}
	return true
}

// prefersLiteral reports whether a has a literal where it first differs from b; the two matched one path.
func prefersLiteral(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] != parameterSegment
		}
	}
	return false
}
