// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds spec/vectors/json.json, the vectors for reading and writing JSON (spec wire.md, JSON); run with `--write`
// from poc-sdks/typescript to write the file. Every expected answer and value below is worked out from the spec by
// hand (the base64url endings by the rule in base64UrlEndings), and the RFC 8785 rows are copied from the RFC, so no
// implementation confirms its own answers: this file imports nothing but node: modules.

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const JSON_JSON = new URL("../../../spec/vectors/json.json", import.meta.url);

type Build = { head: string; repeat: string; times: number; tail: string };
type Input = { utf8: string } | { hex: string } | { build: Build };
type Step = "size" | "parse" | "canonical";
type ReadCase = { name: string } & Input & ({ expected: "OK"; value?: unknown } | { expected: "REFUSED"; step: Step });
/** An object whose members are written in the order given: a plain object puts integer-like names first, in numeric order. */
class Ordered {
  readonly members: [string, unknown][];
  constructor(members: [string, unknown][]) {
    this.members = members;
  }
}

type FileFormatCase = { name: string; kind: string | null; value: unknown; file: string };
type Base64UrlCase = { name: string; text: string; expected: string | null };
type BindingCase = { name: string; binding: string; inputs: Record<string, unknown>; expected: null };
type JcsCase = { name: string } & ({ binary64: string } | { value: unknown }) & { expected: string | null };

const ABOUT =
  "Paztport's JSON vectors: how a reader reads bytes and a writer writes them (spec wire.md, JSON). " +
  "Each input is exactly one of utf8, a JSON string whose UTF-8 encoding is the bytes; hex, the bytes in hex; or build, " +
  "{head, repeat, times, tail}, the UTF-8 of head, then repeat written times times, then tail. " +
  "limits gives the limits the cases sit at and one past: wireBytes, tokenText (the base64url text of wireBytes bytes), fileBytes and depth. " +
  "A wire case is read as a token: the replay encodes the bytes as canonical base64url (RFC 4648 §5, no padding) and reads that text " +
  "by the spec's reading steps 1 to 3: the size limits, the strict parse with the depth limit, and the canonical-bytes check. " +
  "expected is OK or REFUSED, and value, given for every OK case whose input is not build, is the value read; " +
  "its members are the value's own, a name such as __proto__ among them, and an object's names are in the order the input gives them. " +
  "step, given for every REFUSED case, is the reader step the spec defines (Reading, steps 1 to 3: size, parse, canonical) at which the input is first refused. " +
  "It is not an error code: every step answers the same code for an object. " +
  "A file case reads the bytes as a file: the file size limit and the strict parse with the depth limit, with no canonical-bytes check. " +
  "A fileFormat case is one file of its kind (keyring, root, replyCert, proofs or rules; null for a value of no kind): " +
  "printing value as a file gives file exactly, and reading file gives value. " +
  "A jcs case (the MCP profile) is hashed content: binary64 is an IEEE 754 double as 16 hex digits, most significant first, or value is a JSON value; " +
  "expected is its JCS text, or null when JCS refuses it. A jcs value may hold what a strict reader refuses, such as a lone surrogate, " +
  "so a replay reads this file's own structure with any JSON reader, and only the case inputs with the reader under test. " +
  "A base64url case is a text given to the base64url decoder, not to the JSON reader, so it has no step: expected is the decoded bytes in hex, or null when the text is refused. " +
  "The decoder accepts the one canonical unpadded encoding of RFC 4648 §3.5, written with the url-safe alphabet of §5. " +
  "A binding case names one of the bindings (spec wire.md, Bindings) and gives its inputs, each a JSON value: " +
  "prompt {text}; response {resultHash, toolCallId, labels}; toolsCall {tool, toolCallId, arguments}; result {result}; " +
  "localTool {tool, input, resolved}; merkleLeaf {salt, route}, the salt in hex; http {method, target, body}, the body in hex. " +
  "Each case puts the lone surrogate U+D800, written as an escape in this file, into one string the binding hashes, " +
  "so the binding refuses it: expected is null, as for a jcs case, and a verifier that cannot compute a binding answers as it does for a mismatch. " +
  "A replay reads this file's own structure with any JSON reader, as for a jcs case. " +
  "Every answer was written by hand from the spec; the Appendix B rows and the §3.2.2 sample are copied from RFC 8785, the §3.2.3 text follows the order the RFC states; " +
  "the §3.2.2 sample's value holds its numbers as binary64 reads them (the RFC's input spellings such as 1E30 give the same doubles); none was computed by an implementation. " +
  "Cases may be added; a recorded answer changes only with a protocol change.";

const LIMITS = { wireBytes: 262144, tokenText: 349526, fileBytes: 1048576, depth: 32 };

/** Each number spelling that is not a protocol integer: refused on the wire and in a file alike. */
const NOT_PROTOCOL_INTEGERS: ({ name: string } & Input)[] = [
  { name: "the number -0", utf8: "-0" },
  { name: "the number 01, with a leading zero", utf8: "01" },
  { name: "the number 00", utf8: "00" },
  { name: "the number +1", utf8: "+1" },
  { name: "the number 1.0", utf8: "1.0" },
  { name: "the number 1e3", utf8: "1e3" },
  { name: "the number 1E3", utf8: "1E3" },
  { name: "the number 1e+3", utf8: "1e+3" },
  { name: "the number -1", utf8: "-1" },
  { name: "the number 1.5", utf8: "1.5" },
  { name: "the number -0.5", utf8: "-0.5" },
  { name: "the number 1e-7", utf8: "1e-7" },
  { name: "the number 9007199254740992, 2^53", utf8: "9007199254740992" },
  { name: "the number 10000000000000000, 17 digits", utf8: "10000000000000000" },
  { name: "a 400-digit integer", build: { head: "", repeat: "9", times: 400, tail: "" } },
  { name: "the number -9223372036854775808, -2^63", utf8: "-9223372036854775808" },
];

const WIRE: ReadCase[] = [
  { name: "an empty object", utf8: "{}", expected: "OK", value: {} },
  { name: "an empty array", utf8: "[]", expected: "OK", value: [] },
  { name: "the literal true", utf8: "true", expected: "OK", value: true },
  { name: "a string at the top level", utf8: '"paztport"', expected: "OK", value: "paztport" },
  {
    name: "an object holding a number, an array of literals and a string",
    utf8: '{"a":1,"b":[true,false,null],"c":"x"}',
    expected: "OK",
    value: { a: 1, b: [true, false, null], c: "x" },
  },
  {
    name: "names in UTF-16 code unit order, U+1F600 before U+FB33",
    utf8: '{"\u{1f600}":0,"\ufb33":1}',
    expected: "OK",
    value: { "\u{1f600}": 0, "\ufb33": 1 },
  },
  {
    name: "a string holding every escape JCS writes",
    utf8: String.raw`"\"\\\b\f\n\r\t\u0000\u001f"`,
    expected: "OK",
    value: "\"\\\b\f\n\r\t\u0000\u001f",
  },
  { name: "U+00E9, U+20AC and U+1F600 written as themselves", utf8: '"\u00e9\u20ac\u{1f600}"', expected: "OK", value: "\u00e9\u20ac\u{1f600}" },
  { name: "U+007F and U+2028 written as themselves", hex: "227fe280a822", expected: "OK", value: "\u007f\u2028" },
  { name: "the raw U+FDCF, just below the noncharacters", hex: "22efb78f22", expected: "OK", value: "\ufdcf" },
  { name: "the raw U+FDF0, just above the noncharacters", hex: "22efb7b022", expected: "OK", value: "\ufdf0" },
  {
    name: "the name __proto__, an ordinary member",
    hex: "7b225f5f70726f746f5f5f223a7b2261223a317d7d",
    expected: "OK",
    value: { ["__proto__"]: { a: 1 } },
  },
  {
    name: "integer-like names in UTF-16 code unit order, 1 before 10 before 2",
    hex: "7b2231223a332c223130223a312c2232223a327d",
    expected: "OK",
    value: new Ordered([
      ["1", 3],
      ["10", 1],
      ["2", 2],
    ]),
  },
  { name: "the integer 0", utf8: "0", expected: "OK", value: 0 },
  { name: "the integer 9007199254740991, 2^53 - 1", utf8: "9007199254740991", expected: "OK", value: 9007199254740991 },
  { name: "the integer 1000000000000000, 16 digits", utf8: "1000000000000000", expected: "OK", value: 1000000000000000 },
  { name: "a string of exactly 262144 bytes, its quotes included", build: { head: '"', repeat: "a", times: 262142, tail: '"' }, expected: "OK" },
  {
    name: "32 nested arrays",
    utf8: "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
    expected: "OK",
    value: [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]],
  },
  { name: "32 nested objects", build: { head: "", repeat: '{"a":', times: 31, tail: "{}" + "}".repeat(31) }, expected: "OK" },

  { name: "a space before the value", utf8: " {}", expected: "REFUSED", step: "canonical" },
  { name: "a newline after the value", utf8: "{}\n", expected: "REFUSED", step: "canonical" },
  { name: "a space inside an object", utf8: '{"a": 1}', expected: "REFUSED", step: "canonical" },
  { name: "members out of order", utf8: '{"b":1,"a":2}', expected: "REFUSED", step: "canonical" },
  { name: "names in code point order, U+FB33 before U+1F600", utf8: '{"\ufb33":1,"\u{1f600}":0}', expected: "REFUSED", step: "canonical" },
  { name: "a repeated name", utf8: '{"a":1,"a":2}', expected: "REFUSED", step: "parse" },
  { name: String.raw`the escape \/ for /`, utf8: String.raw`"\/"`, expected: "REFUSED", step: "canonical" },
  { name: String.raw`the escape \u0041 for A`, utf8: String.raw`"\u0041"`, expected: "REFUSED", step: "canonical" },
  { name: String.raw`the escape \u00e9 for U+00E9`, utf8: String.raw`"\u00e9"`, expected: "REFUSED", step: "canonical" },
  { name: String.raw`the escape \u001F, in uppercase hex`, utf8: String.raw`"\u001F"`, expected: "REFUSED", step: "canonical" },
  { name: String.raw`the escape \u0008 in place of \b`, utf8: String.raw`"\u0008"`, expected: "REFUSED", step: "canonical" },
  { name: String.raw`the escaped surrogate pair \ud83d\ude00 for U+1F600`, utf8: String.raw`"\ud83d\ude00"`, expected: "REFUSED", step: "canonical" },
  { name: String.raw`a lone high surrogate escaped as \ud800`, utf8: String.raw`"\ud800"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`a lone low surrogate escaped as \udc00`, utf8: String.raw`"\udc00"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`a lone surrogate escaped as \ud800, then x`, utf8: String.raw`"\ud800x"`, expected: "REFUSED", step: "parse" },
  { name: "a raw lone surrogate, ed a0 80", hex: "22eda08022", expected: "REFUSED", step: "parse" },
  { name: "the raw noncharacter U+FDD0", hex: "22efb79022", expected: "REFUSED", step: "parse" },
  { name: "the raw noncharacter U+FDEF", hex: "22efb7af22", expected: "REFUSED", step: "parse" },
  { name: "the raw noncharacter U+FFFE", hex: "22efbfbe22", expected: "REFUSED", step: "parse" },
  { name: "the raw noncharacter U+1FFFF", hex: "22f09fbfbf22", expected: "REFUSED", step: "parse" },
  { name: "the raw noncharacter U+10FFFF", hex: "22f48fbfbf22", expected: "REFUSED", step: "parse" },
  { name: "a byte order mark before {}", hex: "efbbbf7b7d", expected: "REFUSED", step: "parse" },
  { name: "{} in UTF-16LE", hex: "7b007d00", expected: "REFUSED", step: "parse" },
  { name: "{} in UTF-16BE with its byte order mark", hex: "feff007b007d", expected: "REFUSED", step: "parse" },
  { name: "{} in UTF-32BE", hex: "0000007b0000007d", expected: "REFUSED", step: "parse" },
  { name: "a lone continuation byte, 80", hex: "228022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form c0 80 of U+0000", hex: "22c08022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form c1 bf of U+007F", hex: "22c1bf22", expected: "REFUSED", step: "parse" },
  { name: "the overlong form e0 80 80 of U+0000", hex: "22e0808022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form e0 9f bf of U+07FF", hex: "22e09fbf22", expected: "REFUSED", step: "parse" },
  { name: "the overlong form f0 80 80 80 of U+0000", hex: "22f080808022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form f0 8f bf bf of U+FFFF", hex: "22f08fbfbf22", expected: "REFUSED", step: "parse" },
  { name: "f4 90 80 80, above U+10FFFF", hex: "22f490808022", expected: "REFUSED", step: "parse" },
  { name: "the byte f5", hex: "22f522", expected: "REFUSED", step: "parse" },
  { name: "the byte ff", hex: "22ff22", expected: "REFUSED", step: "parse" },
  { name: "a sequence cut short, e2 82", hex: "22e28222", expected: "REFUSED", step: "parse" },
  { name: "a raw U+0000 in a string", hex: "220022", expected: "REFUSED", step: "parse" },
  { name: "a raw U+001F in a string", hex: "221f22", expected: "REFUSED", step: "parse" },
  ...NOT_PROTOCOL_INTEGERS.map((c): ReadCase => ({ ...c, expected: "REFUSED", step: "parse" })),
  { name: "a trailing comma in an array", utf8: "[1,]", expected: "REFUSED", step: "parse" },
  { name: "a trailing comma in an object", utf8: '{"a":1,}', expected: "REFUSED", step: "parse" },
  { name: "a string in single quotes", utf8: "['a']", expected: "REFUSED", step: "parse" },
  { name: "an unquoted name", utf8: "{a:1}", expected: "REFUSED", step: "parse" },
  { name: "a comment", utf8: "[/*c*/1]", expected: "REFUSED", step: "parse" },
  { name: "NaN", utf8: "NaN", expected: "REFUSED", step: "parse" },
  { name: "Infinity", utf8: "Infinity", expected: "REFUSED", step: "parse" },
  { name: "an unterminated array", utf8: "[1", expected: "REFUSED", step: "parse" },
  { name: "an unterminated string", utf8: '"abc', expected: "REFUSED", step: "parse" },
  { name: "an empty input", utf8: "", expected: "REFUSED", step: "parse" },
  { name: "two values", utf8: "{}{}", expected: "REFUSED", step: "parse" },
  { name: String.raw`the invalid escape \x`, utf8: String.raw`"\x"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`the escape \u12, with two hex digits`, utf8: String.raw`"\u12"`, expected: "REFUSED", step: "parse" },
  { name: "tru", utf8: "tru", expected: "REFUSED", step: "parse" },
  { name: "33 nested arrays", utf8: "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]", expected: "REFUSED", step: "parse" },
  { name: "33 nested objects", build: { head: "", repeat: '{"a":', times: 32, tail: "{}" + "}".repeat(32) }, expected: "REFUSED", step: "parse" },
  { name: "a string of 262145 bytes, its quotes included", build: { head: '"', repeat: "a", times: 262143, tail: '"' }, expected: "REFUSED", step: "size" },
  { name: "262145 bytes of [", build: { head: "", repeat: "[", times: 262145, tail: "" }, expected: "REFUSED", step: "size" },
];

const FILE: ReadCase[] = [
  {
    name: "whitespace everywhere, and a final newline",
    utf8: ' \t{\r\n  "a" : [ 1 ,\ttrue ] ,\n  "b":"x"\n}\n',
    expected: "OK",
    value: { a: [1, true], b: "x" },
  },
  { name: "members in any order", utf8: '{"b":1,"a":2}', expected: "OK", value: { b: 1, a: 2 } },
  { name: String.raw`the escape \/, read as /`, utf8: String.raw`"\/"`, expected: "OK", value: "/" },
  { name: String.raw`the escape \u00e9, read as U+00E9`, utf8: String.raw`"\u00e9"`, expected: "OK", value: "\u00e9" },
  { name: String.raw`the escape \u0041, read as A`, utf8: String.raw`"\u0041"`, expected: "OK", value: "A" },
  { name: String.raw`the escape \u00E9 in uppercase hex, read as U+00E9`, utf8: String.raw`"\u00E9"`, expected: "OK", value: "\u00e9" },
  { name: String.raw`the escaped surrogate pair \ud83d\ude00, read as U+1F600`, utf8: String.raw`"\ud83d\ude00"`, expected: "OK", value: "\u{1f600}" },
  { name: "exactly 1048576 bytes", build: { head: '"', repeat: "a", times: 1048574, tail: '"' }, expected: "OK" },
  {
    name: "32 nested arrays",
    utf8: "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
    expected: "OK",
    value: [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]],
  },

  { name: "a repeated name", utf8: '{"a":1,"a":2}', expected: "REFUSED", step: "parse" },
  { name: String.raw`a name repeated through an escape, \u0061 for a`, utf8: String.raw`{"a":1,"\u0061":2}`, expected: "REFUSED", step: "parse" },
  { name: String.raw`a lone surrogate escaped as \ud800`, utf8: String.raw`"\ud800"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`the noncharacter U+FFFF escaped as \uffff`, utf8: String.raw`"\uffff"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`the noncharacter U+FDD0 escaped as \ufdd0`, utf8: String.raw`"\ufdd0"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`the noncharacter U+10FFFF escaped as the pair \udbff\udfff`, utf8: String.raw`"\udbff\udfff"`, expected: "REFUSED", step: "parse" },
  { name: String.raw`a lone low surrogate escaped as \udc00`, hex: "225c756463303022", expected: "REFUSED", step: "parse" },
  { name: String.raw`a lone surrogate escaped as \ud800, in a member name`, hex: "7b225c7564383030223a317d", expected: "REFUSED", step: "parse" },
  { name: String.raw`a high surrogate escaped as \ud800, then the escape A`, hex: "225c75643830305c753030343122", expected: "REFUSED", step: "parse" },
  { name: "a repeated name that is not adjacent", hex: "7b2261223a312c2262223a322c2261223a337d", expected: "REFUSED", step: "parse" },
  { name: "a lone continuation byte, 80", hex: "228022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form c0 80 of U+0000", hex: "22c08022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form e0 80 80 of U+0000", hex: "22e0808022", expected: "REFUSED", step: "parse" },
  { name: "the overlong form f0 80 80 80 of U+0000", hex: "22f080808022", expected: "REFUSED", step: "parse" },
  { name: "a raw lone surrogate, ed a0 80", hex: "22eda08022", expected: "REFUSED", step: "parse" },
  { name: "f4 90 80 80, above U+10FFFF", hex: "22f490808022", expected: "REFUSED", step: "parse" },
  { name: "a sequence cut short, e2 82", hex: "22e28222", expected: "REFUSED", step: "parse" },
  { name: "a raw U+0000 in a string", hex: "220022", expected: "REFUSED", step: "parse" },
  { name: "a raw U+001F in a string", hex: "221f22", expected: "REFUSED", step: "parse" },
  { name: "the raw noncharacter U+FFFE", hex: "22efbfbe22", expected: "REFUSED", step: "parse" },
  { name: "a byte order mark before {}", hex: "efbbbf7b7d", expected: "REFUSED", step: "parse" },
  ...NOT_PROTOCOL_INTEGERS.map((c): ReadCase => ({ ...c, expected: "REFUSED", step: "parse" })),
  { name: "1048577 bytes", build: { head: '"', repeat: "a", times: 1048575, tail: '"' }, expected: "REFUSED", step: "size" },
  { name: "1048577 bytes of [", build: { head: "", repeat: "[", times: 1048577, tail: "" }, expected: "REFUSED", step: "size" },
  { name: "33 nested arrays", utf8: "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]", expected: "REFUSED", step: "parse" },
];

const FILE_FORMAT: FileFormatCase[] = [
  {
    name: "a keyring",
    kind: "keyring",
    value: {
      notAfter: 1798761600000,
      policy: "MCowBQYDK2VwAyEAfQNZTmPjT9_g3vetQl2BiLIQRjx52SazyRoXh7V227c",
      services: {
        pi: "MCowBQYDK2VwAyEAUd0vHKUihGesdJJMfvbah8t0g6b1whtUnRRslYPr1i8",
        session: "MCowBQYDK2VwAyEAb0m5BDnl3LzmednUhwMpU9Oc58beN-Saat_c5CTamcY",
      },
      sig: "EqqU4_Zh5JChj0MJ1lK-hWV4J1tSqMaR_QNsXmn4fuV5FcIA6QY0iVkqeAIcC6hdNhhi3aaMSGlBCwgieOQjBw",
    },
    file: `{
  "notAfter": 1798761600000,
  "policy": "MCowBQYDK2VwAyEAfQNZTmPjT9_g3vetQl2BiLIQRjx52SazyRoXh7V227c",
  "services": {
    "pi": "MCowBQYDK2VwAyEAUd0vHKUihGesdJJMfvbah8t0g6b1whtUnRRslYPr1i8",
    "session": "MCowBQYDK2VwAyEAb0m5BDnl3LzmednUhwMpU9Oc58beN-Saat_c5CTamcY"
  },
  "sig": "EqqU4_Zh5JChj0MJ1lK-hWV4J1tSqMaR_QNsXmn4fuV5FcIA6QY0iVkqeAIcC6hdNhhi3aaMSGlBCwgieOQjBw"
}
`,
  },
  {
    name: "a signed root",
    kind: "root",
    value: {
      notAfter: 1798761600000,
      root: "SOU3UQ3YhNm3n8xvLwVDNVE_OjYUyaxSc9I0GLoAFr4",
      rootId: "v128498df6662",
      sig: "4nmqeKZXzaUkClKZ8SzVCIXSb9KiGiZuQSkCwuPnYUIVBdrH09SIFn1qbbqssuFeb99HqcNxvBOAdkQI5uiyDQ",
    },
    file: `{
  "notAfter": 1798761600000,
  "root": "SOU3UQ3YhNm3n8xvLwVDNVE_OjYUyaxSc9I0GLoAFr4",
  "rootId": "v128498df6662",
  "sig": "4nmqeKZXzaUkClKZ8SzVCIXSb9KiGiZuQSkCwuPnYUIVBdrH09SIFn1qbbqssuFeb99HqcNxvBOAdkQI5uiyDQ"
}
`,
  },
  {
    name: "a reply certificate",
    kind: "replyCert",
    value: {
      key: "MCowBQYDK2VwAyEAHBvgTd_hlBakY5DQ-jLgYs8ur1YIxJ0AdTwbAMpFJlw",
      notAfter: 1798761600000,
      policy: "MCowBQYDK2VwAyEAOdyoxLQRNmlGbFkPnV76zvhKoT6dVmtC3o6ZUBRrB-I",
      sig: "Di-W3XltVTD0v5qr14K2ctA6aMBFAWnbAimC3RxiD3_jGijp5TTJ76TgikwuOgvy9H_lFbNj-r_lbPo63gSVAA",
      svc: "mcp-entry",
    },
    file: `{
  "key": "MCowBQYDK2VwAyEAHBvgTd_hlBakY5DQ-jLgYs8ur1YIxJ0AdTwbAMpFJlw",
  "notAfter": 1798761600000,
  "policy": "MCowBQYDK2VwAyEAOdyoxLQRNmlGbFkPnV76zvhKoT6dVmtC3o6ZUBRrB-I",
  "sig": "Di-W3XltVTD0v5qr14K2ctA6aMBFAWnbAimC3RxiD3_jGijp5TTJ76TgikwuOgvy9H_lFbNj-r_lbPo63gSVAA",
  "svc": "mcp-entry"
}
`,
  },
  {
    name: "a proof bundle with two routes",
    kind: "proofs",
    value: {
      proofs: {
        "gateway/orders": {
          dirs: "RLLLLLLL",
          leafSalt: "ujLZXNGXFps4j4nU0wX2Yw",
          rootId: "merkle-vector",
          siblings: [
            "VUR8y6hwSc4cSN7YZf3whGqA_gnZGM10e9whWaUvg7Q",
            "GleOAtomzhKANdq5trEgjsWz1rFhu1SMwzFKJxDPMAc",
            "X06nacS-ouvnBG6KnPfT2pJc-Mj2t_abv_cMQyLyv-M",
            "olRUm8Cy7HiRHy8L4sV--BhtR4rqYEDgEzikzD3oHVs",
            "Pd_M0oMDh2waooX3WuTZvRXzCn65rFu3mBMDV50-3gk",
            "sSQiqDmBAYLdZsjjdFGBcAfrr7GTBIdyf-JYjzifhhA",
            "iJH4gNbjMmaFIrADBEO2WHDKNFM7YXeaR6Kp-X_NLMw",
            "Jwd3p1rdO_wwDGnhA7RAz-9hncnnPwDTs39m1magsK0",
          ],
        },
        "gateway/search": {
          dirs: "LRLLLLLL",
          leafSalt: "izKXq4MjEbVHm7fWohfcuA",
          rootId: "merkle-vector",
          siblings: [
            "WNvdj6tvsMs2Jb8wPRXSqllJVXM5Zze7N1X_flvMOaY",
            "joaLw6HmR-RpIfLxgwy3QIMxG9NGSfYb-YdqeKpN1OM",
            "X06nacS-ouvnBG6KnPfT2pJc-Mj2t_abv_cMQyLyv-M",
            "olRUm8Cy7HiRHy8L4sV--BhtR4rqYEDgEzikzD3oHVs",
            "Pd_M0oMDh2waooX3WuTZvRXzCn65rFu3mBMDV50-3gk",
            "sSQiqDmBAYLdZsjjdFGBcAfrr7GTBIdyf-JYjzifhhA",
            "iJH4gNbjMmaFIrADBEO2WHDKNFM7YXeaR6Kp-X_NLMw",
            "Jwd3p1rdO_wwDGnhA7RAz-9hncnnPwDTs39m1magsK0",
          ],
        },
      },
      rootId: "merkle-vector",
      service: "gateway",
    },
    file: `{
  "proofs": {
    "gateway/orders": {
      "dirs": "RLLLLLLL",
      "leafSalt": "ujLZXNGXFps4j4nU0wX2Yw",
      "rootId": "merkle-vector",
      "siblings": [
        "VUR8y6hwSc4cSN7YZf3whGqA_gnZGM10e9whWaUvg7Q",
        "GleOAtomzhKANdq5trEgjsWz1rFhu1SMwzFKJxDPMAc",
        "X06nacS-ouvnBG6KnPfT2pJc-Mj2t_abv_cMQyLyv-M",
        "olRUm8Cy7HiRHy8L4sV--BhtR4rqYEDgEzikzD3oHVs",
        "Pd_M0oMDh2waooX3WuTZvRXzCn65rFu3mBMDV50-3gk",
        "sSQiqDmBAYLdZsjjdFGBcAfrr7GTBIdyf-JYjzifhhA",
        "iJH4gNbjMmaFIrADBEO2WHDKNFM7YXeaR6Kp-X_NLMw",
        "Jwd3p1rdO_wwDGnhA7RAz-9hncnnPwDTs39m1magsK0"
      ]
    },
    "gateway/search": {
      "dirs": "LRLLLLLL",
      "leafSalt": "izKXq4MjEbVHm7fWohfcuA",
      "rootId": "merkle-vector",
      "siblings": [
        "WNvdj6tvsMs2Jb8wPRXSqllJVXM5Zze7N1X_flvMOaY",
        "joaLw6HmR-RpIfLxgwy3QIMxG9NGSfYb-YdqeKpN1OM",
        "X06nacS-ouvnBG6KnPfT2pJc-Mj2t_abv_cMQyLyv-M",
        "olRUm8Cy7HiRHy8L4sV--BhtR4rqYEDgEzikzD3oHVs",
        "Pd_M0oMDh2waooX3WuTZvRXzCn65rFu3mBMDV50-3gk",
        "sSQiqDmBAYLdZsjjdFGBcAfrr7GTBIdyf-JYjzifhhA",
        "iJH4gNbjMmaFIrADBEO2WHDKNFM7YXeaR6Kp-X_NLMw",
        "Jwd3p1rdO_wwDGnhA7RAz-9hncnnPwDTs39m1magsK0"
      ]
    }
  },
  "rootId": "merkle-vector",
  "service": "gateway"
}
`,
  },
  {
    name: "local rules",
    kind: "rules",
    value: {
      folders: [
        { access: ["read"], path: "." },
        { access: ["read", "write"], destination: "public", label: "public", path: "website" },
        { access: ["read", "write"], destination: "private", path: "notes" },
      ],
      programs: ["cat", "ls"],
      v: 1,
    },
    file: `{
  "folders": [
    {
      "access": [
        "read"
      ],
      "path": "."
    },
    {
      "access": [
        "read",
        "write"
      ],
      "destination": "public",
      "label": "public",
      "path": "website"
    },
    {
      "access": [
        "read",
        "write"
      ],
      "destination": "private",
      "path": "notes"
    }
  ],
  "programs": [
    "cat",
    "ls"
  ],
  "v": 1
}
`,
  },
  {
    name: "integer-like names, written in JCS order",
    kind: null,
    value: new Ordered([
      ["1", 3],
      ["10", 1],
      ["2", 2],
    ]),
    file: `{
  "1": 3,
  "10": 1,
  "2": 2
}
`,
  },
  {
    name: "a value whose members are given out of JCS order, written in it",
    kind: null,
    value: new Ordered([
      ["b", 1],
      ["a", 2],
      ["10", 3],
      ["2", 4],
    ]),
    file: `{
  "10": 3,
  "2": 4,
  "a": 2,
  "b": 1
}
`,
  },
  {
    name: "an empty object and an empty array",
    kind: null,
    value: { a: {}, b: [] },
    file: `{
  "a": {},
  "b": []
}
`,
  },
];

const JCS: JcsCase[] = [
  { name: "RFC 8785 Appendix B: 0000000000000000, zero", binary64: "0000000000000000", expected: "0" },
  { name: "RFC 8785 Appendix B: 8000000000000000, minus zero", binary64: "8000000000000000", expected: "0" },
  { name: "RFC 8785 Appendix B: 0000000000000001, min pos number", binary64: "0000000000000001", expected: "5e-324" },
  { name: "RFC 8785 Appendix B: 8000000000000001, min neg number", binary64: "8000000000000001", expected: "-5e-324" },
  { name: "RFC 8785 Appendix B: 7fefffffffffffff, max pos number", binary64: "7fefffffffffffff", expected: "1.7976931348623157e+308" },
  { name: "RFC 8785 Appendix B: ffefffffffffffff, max neg number", binary64: "ffefffffffffffff", expected: "-1.7976931348623157e+308" },
  { name: "RFC 8785 Appendix B: 4340000000000000, max pos int", binary64: "4340000000000000", expected: "9007199254740992" },
  { name: "RFC 8785 Appendix B: c340000000000000, max neg int", binary64: "c340000000000000", expected: "-9007199254740992" },
  { name: "RFC 8785 Appendix B: 4430000000000000, ~2**68", binary64: "4430000000000000", expected: "295147905179352830000" },
  { name: "RFC 8785 Appendix B: 7fffffffffffffff, NaN", binary64: "7fffffffffffffff", expected: null },
  { name: "RFC 8785 Appendix B: 7ff0000000000000, Infinity", binary64: "7ff0000000000000", expected: null },
  { name: "RFC 8785 Appendix B: 44b52d02c7e14af5", binary64: "44b52d02c7e14af5", expected: "9.999999999999997e+22" },
  { name: "RFC 8785 Appendix B: 44b52d02c7e14af6", binary64: "44b52d02c7e14af6", expected: "1e+23" },
  { name: "RFC 8785 Appendix B: 44b52d02c7e14af7", binary64: "44b52d02c7e14af7", expected: "1.0000000000000001e+23" },
  { name: "RFC 8785 Appendix B: 444b1ae4d6e2ef4e", binary64: "444b1ae4d6e2ef4e", expected: "999999999999999700000" },
  { name: "RFC 8785 Appendix B: 444b1ae4d6e2ef4f", binary64: "444b1ae4d6e2ef4f", expected: "999999999999999900000" },
  { name: "RFC 8785 Appendix B: 444b1ae4d6e2ef50", binary64: "444b1ae4d6e2ef50", expected: "1e+21" },
  { name: "RFC 8785 Appendix B: 3eb0c6f7a0b5ed8c", binary64: "3eb0c6f7a0b5ed8c", expected: "9.999999999999997e-7" },
  { name: "RFC 8785 Appendix B: 3eb0c6f7a0b5ed8d", binary64: "3eb0c6f7a0b5ed8d", expected: "0.000001" },
  { name: "RFC 8785 Appendix B: 41b3de4355555553", binary64: "41b3de4355555553", expected: "333333333.3333332" },
  { name: "RFC 8785 Appendix B: 41b3de4355555554", binary64: "41b3de4355555554", expected: "333333333.33333325" },
  { name: "RFC 8785 Appendix B: 41b3de4355555555", binary64: "41b3de4355555555", expected: "333333333.3333333" },
  { name: "RFC 8785 Appendix B: 41b3de4355555556", binary64: "41b3de4355555556", expected: "333333333.3333334" },
  { name: "RFC 8785 Appendix B: 41b3de4355555557", binary64: "41b3de4355555557", expected: "333333333.33333343" },
  { name: "RFC 8785 Appendix B: becbf647612f3696", binary64: "becbf647612f3696", expected: "-0.0000033333333333333333" },
  { name: "RFC 8785 Appendix B: 43143ff3c1cb0959, round to even", binary64: "43143ff3c1cb0959", expected: "1424953923781206.2" },
  {
    name: "RFC 8785 §3.2.2's sample",
    value: {
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
      string: "\u20ac$\u000f\nA'B\"\\\\\"/",
      literals: [null, true, false],
    },
    expected: String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
  },
  {
    name: "RFC 8785 §3.2.3's sorting example",
    value: {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis",
    },
    expected:
      String.raw`{"\r":"Carriage Return","1":"One","` +
      '\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",' +
      '"\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
  },
  { name: "-0, written 0", binary64: "8000000000000000", expected: "0" },
  { name: "a string holding the noncharacter U+FFFF, written as itself", value: "\uffff", expected: '"\uffff"' },
  { name: "a string holding a lone surrogate", value: "\ud800", expected: null },
];

/** RFC 4648 §5, Table 2: the url-safe alphabet, in the order of the values 0 to 63. */
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Every ending of a short group, one row for each last character c other than A (AA and AAA are rows of their own): after
 * one byte the text is "A" + c, whose last 4 bits are unused, and after two bytes it is "AA" + c, whose last 2 are. The
 * ending is canonical exactly when those bits are zero, and then the bytes follow from the 6-bit value v of c: the one
 * byte is v >> 4, and the two are 00 and v >> 2.
 */
function base64UrlEndings(): Base64UrlCase[] {
  const rows: Base64UrlCase[] = [];
  for (const [prefix, unused, bytes] of [["A", 4, 1], ["AA", 2, 2]] as const) {
    const after = bytes === 1 ? "one byte" : "two bytes";
    for (let v = 1; v < 64; v++) {
      const text = prefix + BASE64URL_ALPHABET[v];
      if (v % (1 << unused) !== 0) {
        rows.push({ name: `${text}, non-zero unused bits after ${after}`, text, expected: null });
      } else {
        const hex = (n: number) => n.toString(16).padStart(2, "0");
        const decoded = bytes === 1 ? hex(v >> 4) : "00" + hex(v >> 2);
        rows.push({ name: `${text}, unused bits zero after ${after}`, text, expected: decoded });
      }
    }
  }
  return rows;
}

/**
 * Texts for the base64url decoder; each answer is worked out from RFC 4648 §3.5 and §5: these by hand, the endings
 * by the rule in base64UrlEndings.
 */
const BASE64URL: Base64UrlCase[] = [
  { name: "the empty text", text: "", expected: "" },
  { name: "AA, one zero byte", text: "AA", expected: "00" },
  { name: "AAA, two zero bytes", text: "AAA", expected: "0000" },
  { name: "AAAA, three zero bytes", text: "AAAA", expected: "000000" },
  { name: "-_-_, the bytes the standard alphabet writes as +/+/", text: "-_-_", expected: "fbffbf" },
  ...base64UrlEndings(),
  { name: "A, a length one more than a multiple of 4", text: "A", expected: null },
  { name: "AA==, padded", text: "AA==", expected: null },
  { name: "AA=, padded once", text: "AA=", expected: null },
  { name: "AAAA=, padding after a whole group", text: "AAAA=", expected: null },
  { name: "A+A, a character of the standard alphabet", text: "A+A", expected: null },
  { name: "A/A, a character of the standard alphabet", text: "A/A", expected: null },
  { name: "a leading space", text: " AA", expected: null },
  { name: "a trailing newline", text: "AA\n", expected: null },
];

/** Each string a binding hashes, holding U+D800 alone; every binding refuses it, so each answer is null. */
const BINDINGS: BindingCase[] = [
  { name: "a prompt holding a lone surrogate", binding: "prompt", inputs: { text: "fix the \ud800typo" }, expected: null },
  {
    name: "a response whose result hash holds a lone surrogate",
    binding: "response",
    inputs: { resultHash: "h\ud800", toolCallId: "call-1", labels: [] },
    expected: null,
  },
  {
    name: "a response whose call id holds a lone surrogate",
    binding: "response",
    inputs: { resultHash: "h1", toolCallId: "call-\ud800", labels: [] },
    expected: null,
  },
  {
    name: "a tools/call whose tool holds a lone surrogate",
    binding: "toolsCall",
    inputs: { tool: "create_\ud800issue", toolCallId: "call-1", arguments: { title: "t" } },
    expected: null,
  },
  {
    name: "a tools/call whose call id holds a lone surrogate",
    binding: "toolsCall",
    inputs: { tool: "create_issue", toolCallId: "call-\ud800", arguments: { title: "t" } },
    expected: null,
  },
  {
    name: "a tools/call whose argument holds a lone surrogate",
    binding: "toolsCall",
    inputs: { tool: "create_issue", toolCallId: "call-1", arguments: { title: "t\ud800" } },
    expected: null,
  },
  {
    name: "a result whose text holds a lone surrogate",
    binding: "result",
    inputs: { result: { content: [{ type: "text", text: "hello \ud800" }] } },
    expected: null,
  },
  {
    name: "a local tool whose name holds a lone surrogate",
    binding: "localTool",
    inputs: { tool: "re\ud800ad", input: { path: "a" }, resolved: { paths: [] } },
    expected: null,
  },
  {
    name: "a local tool whose input holds a lone surrogate",
    binding: "localTool",
    inputs: { tool: "read", input: { path: "a\ud800" }, resolved: { paths: [] } },
    expected: null,
  },
  {
    name: "a Merkle leaf whose route holds a lone surrogate",
    binding: "merkleLeaf",
    inputs: { salt: "000102030405060708090a0b0c0d0e0f", route: "session/pi/local:\ud800read" },
    expected: null,
  },
  {
    name: "an HTTP request whose method holds a lone surrogate",
    binding: "http",
    inputs: { method: "GE\ud800T", target: "/a", body: "" },
    expected: null,
  },
  {
    name: "an HTTP request whose target holds a lone surrogate",
    binding: "http",
    inputs: { method: "GET", target: "/a\ud800", body: "" },
    expected: null,
  },
];

export function buildVectorsJson(): Record<string, unknown> {
  return { about: ABOUT, limits: LIMITS, wire: WIRE, file: FILE, fileFormat: FILE_FORMAT, base64url: BASE64URL, jcs: JCS, bindings: BINDINGS };
}

/** JSON.stringify(value, null, 2), except that an Ordered object keeps its members in the order given. */
function print(value: unknown, indent: string): string {
  if (value instanceof Ordered) return printMembers(value.members, indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const inner = indent + "  ";
    return "[\n" + value.map((item) => inner + print(item, inner)).join(",\n") + "\n" + indent + "]";
  }
  if (typeof value === "object" && value !== null) {
    return printMembers(Object.entries(value).filter(([, member]) => member !== undefined), indent);
  }
  return JSON.stringify(value);
}

function printMembers(members: [string, unknown][], indent: string): string {
  if (members.length === 0) return "{}";
  const inner = indent + "  ";
  return "{\n" + members.map(([name, member]) => inner + JSON.stringify(name) + ": " + print(member, inner)).join(",\n") + "\n" + indent + "}";
}

export function vectorsJsonText(): string {
  return print(buildVectorsJson(), "") + "\n";
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes("--write")) {
  writeFileSync(JSON_JSON, vectorsJsonText());
}
