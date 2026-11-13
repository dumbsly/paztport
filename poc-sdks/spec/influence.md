# Influence

How influence is recorded and committed, the one rule that decides a public write and the one that guards a trusted
record, and how influence crosses an organisation's boundary blinded. The bytes of stamps, roots and keyrings are in
[wire.md](wire.md), the checks in [verification.md](verification.md), and the handshake and the boundary in
[sessions.md](sessions.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Entries](#entries) · [Normalisation and commitment](#normalisation-and-commitment) ·
[Content labels](#content-labels) · [The owner-aware rule](#the-owner-aware-rule) ·
[Trusted records](#trusted-records) · [Blinded influence](#blinded-influence)

Influence is a record of what content the context held when an action was decided. It travels with each call
(`paztport/influence`), and the call's last stamp commits to it (`infl`), so a hop can't drop an entry without
breaking the stamp.

| Class | Meaning |
|---|---|
| `third-party` | Content from outside the trust boundary, which may carry instructions: an issue anyone can write, a web page. |
| `private` | Data that must not reach a public destination unless it belongs to the destination's owner. |
| `public` | Content that is already public. |
| `local-untrusted` | Content the client can't vouch for: a result that failed verification or came from an unattested server, a local read from an unlabelled folder, a program's output. It counts as untrusted. |

A client MUST NOT drop an entry while the content it describes can still steer the session. The agents demo keeps
every entry until the session is cleared.

## Entries

An influence entry is a JSON object with exactly these members:

| Field | Required | Rule |
|---|---|---|
| `cls` | yes | One of the four classes. |
| `src` | yes | A string naming the source, for example `server:<serverId>`, `web:example.com`, for an HTTP response `http:<target>`, or, for a [blinded entry](#blinded-influence) from another organisation, `boundary:<egress>`. |
| `h` | yes | A string identifying the content, such as a hash of it; the agents demo uses the result binding, and the Java SDK an HTTP response's result hash. |
| `cid` | no | A string: the content id from the label the entry came from. |
| `owner` | no | A **non-empty** string: an opaque id of whose data this is. |

A list of entries travels as its JCS bytes and is read as [wire bytes](wire.md#reading). It MUST be rejected when
it is not an array, or any entry is not an object, has a member the table does not name, has an unknown `cls`, a
`src` or `h` that is not a string, a `cid` that is not a string, or an `owner` that is not a non-empty string. A
verifier reports that, and bytes that do not read, as `INFLUENCE_MISMATCH`. An empty `owner` is rejected, not read
as "no owner", so it can never be taken for a known one.

## Normalisation and commitment

`normalise(entries)`:

1. Sort by `h`, then `cls`, then `src`, then `cid`, then `owner`, comparing strings by UTF-16 code units (the
   order JCS uses for keys). For `cid` and `owner`, an absent value sorts before any present one.
2. Remove exact duplicates: entries whose JCS forms are equal. An entry with an owner and the same entry without
   one are different, and both stay.

The commitment is `""` when there are no entries, and otherwise:

```
infl = b64url( H( utf8( JCS( normalise(entries) ) ) ) )
```

Normalising first means the order a client happened to record things in doesn't change the commitment. `v3.json`
pins the commitment in `commitInfluence` (the same entries as the first case of `influence`), and in `influence`
the owner's sort position and the with-and-without case.

## Content labels

A server labels the content of each result it attests. A label is `{ "cid": ..., "cls": ..., "owner": ... }`:

- `cls` is one of the four classes, and `cid` a fresh content id (each SDK uses 16 random bytes, base64url);
- `owner`, when present, MUST be non-empty, and the server MUST take it from its own records of whose data it
  served, never from the content.

The labels are covered by the response binding ([wire.md](wire.md#bindings)), so they can't be changed in
transit. A client MUST add a label to its influence only when the whole response verifies, as the entry
`{ cls, src: "server:<serverId>", h: resultHash, cid, owner }` (with `owner` only when the label has one); over
HTTP, `src` is `"http:<target>"`, the service the request was sent to. A response that does not verify adds
`local-untrusted` instead.

## The owner-aware rule

One standing rule decides every write to a public destination. A write is **refused** when both hold:

- the influence holds untrusted content: any `third-party` or `local-untrusted` entry; and
- the influence holds `private` data that is not the destination owner's: any `private` entry whose `owner` is
  absent or empty, or that differs from the destination's owner, or any `private` entry at all when the
  destination's owner is unknown (absent or empty).

Otherwise the write is allowed. A write to a destination that is not public is not decided by this rule.

An unknown owner, on either side, fails closed: it counts as someone else's. So untrusted content can still
steer a write of a customer's own data to that customer, but never someone else's data, or data whose owner
nobody knows.

**Where the destination owner comes from.** The party applying the rule MUST take the destination's owner from
its own trusted records, such as the authenticated account the write is for or the stored owner of the target.
It MUST NOT take it from the request's arguments, from the content, or from the influence: those are what an
attacker writes.

`v3.json` pins the rule's truth table in `rule`. In the agents demo, neither entries nor destinations have
owners, so the rule reduces to "untrusted content plus any private data refuses a public write".

The client's local gate ([MCP profile](README.md#the-mcp-profile)) applies the same rule to its own tools'
writes into a folder whose destination is `public`, over the session's classes plus `private` when the call
itself reads a private-labelled folder (`INFLUENCE_DENIED`).

### Trusted records

Some writes go not to a destination but into the service's own trusted records: records later decisions take as
fact, such as who holds a card, which the owner-aware rule then reads as a destination's owner. The owner-aware
rule cannot judge such a write. It asks whose private data a write carries, and a record written because
untrusted text asked for it carries none: a hijacked model's charge would register its card to whoever it named,
and a later refund to that card would pass the rule. So a service MUST write a trusted record from a request only
when both of these hold:

- **The request's chain passed [the live order](verification.md#the-live-order) at this hop**, so the influence
  is the one its caller committed to. An origin, a service with no verifier, a hop on which Paztport is off, a chain
  that failed in audit mode, a call in an unsafe partner session and work outside any request never qualify. This
  is the same condition the [egress](sessions.md#between-organisations) signs under.
- **The influence holds no untrusted content:** no `third-party` and no `local-untrusted` entry. That is the
  influence the request holds when the record is written: what came with it, and everything the service has read
  since, such as the responses to its own calls.

`private` and `public` entries, and owners, do not count either way: they say whose data the request read, not who
steered it. A request that fails the rule MAY still be served, but the record MUST NOT be written from it.

| Chain passed the live order at this hop | Influence holds `third-party` or `local-untrusted` | The record |
|---|---|---|
| no | either | not written |
| yes | yes | not written |
| yes | no (no entries, or only `private` and `public` ones, with any owners) | may be written |

`http-v3.json`'s `rules` pins this rule in `trustedRecord`, and for a partner's calls in its partner kinds. (The Java
SDK applies it as `PublicWrites.shapedOnlyByTrusted()`.)

## Blinded influence

The owner-aware rule reads only each entry's class and owner, so that is all the egress sends. It normalises
the influence the request context holds after the internal chain passed the live order at this hop, groups the
entries by (`cls`, `owner`), with no owner a group of its own, and sends one entry per group:

| Field | Value |
|---|---|
| `cls` | The group's class. |
| `src` | `boundary:<egress>`. |
| `h` | The group's commitment, below. |
| `owner` | The group's owner, left out when the group has none. |

A sent entry has no `cid`, and the sent list is normalised. An entry with an owner and the same entry without
one fall in two groups, so two entries are sent. No influence gives no entries, committed as `""`. Every
(class, owner) pair of the originals is in the sent list and no other is, so the partner's verdict under the
owner-aware rule is the one it would reach on the originals.

The egress holds a **boundary key** of exactly 32 bytes, which MUST NOT leave the sender; a key of any other
length MUST be refused. The salt below does not name the egress, so a boundary key MUST belong to one egress
service and MUST NOT be shared with another: two egress services with one key would derive the same salts for
the same request and partner. Replicas of one egress share its key. For each group:

```
salt       = HMAC-SHA256( key, utf8("paztport-boundary-salt\n")
                               ‖ utf8( JCS({ "cls": cls, "owner": owner, "rcv": <partner entry>, "rid": rid }) ) )[0..16]
commitment = b64url( H( utf8("paztport-boundary-entry\n") ‖ salt ‖ utf8( JCS( normalise(group) ) ) ) )
```

`owner` is left out of the salt's object when the group has none, and `[0..16]` is the first 16 bytes. The
commitment covers every field of every original in the group. The salt is per request and per partner, so the
same content gives a different `h` each time: the partner can't tell that two requests carried the same
content, or confirm a guess at it. It is derived, so the sender stores nothing per call to make it, and can
always derive it again.

**Opening an entry.** To show what one sent entry stood for, the sender reveals an opening:
`{ "cls", "originals", "owner", "salt" }`, with `originals` a list of entries, `owner` left out when the entry has
none, and `salt` base64url. An opening opens a sent entry only when all of these hold:

1. `originals` is not empty.
2. The opening's `cls` and `owner` are the sent entry's, and so are every original's: both absent, or equal.
3. `salt` decodes to exactly 16 bytes.
4. The commitment to `originals` under `salt` is the sent entry's `h`.

An opening is read as [wire bytes](wire.md#reading): the JCS bytes of an object with exactly `cls`, `salt` and
`originals`, and `owner` when the entry has one, a non-empty string. A checker MUST answer "does not open" for
anything else, and MUST NOT fail in any other way. A checker that answers over a service, such as the PSP demo's
`/debug/check-opening`, first reads the request body. It refuses a body that does not read (whitespace around the
opening, members out of JCS order, a number that is not a protocol integer) or that is not one JSON object with
`400 {"reason":"MALFORMED_OPENING"}`: that is the service declining the request, not the check failing. It answers
an object that is not an opening, or does not open, with `200 {"opens":false}`.

Revealing one salt opens only that entry: every other group, request and partner has its own salt. Two calls to
one partner in one request are the exception, below.

An opening proves what the sender committed to when it sent the entry, not that the originals were true.

The sender MUST keep the original entries and its boundary key for as long as it wants to open entries; rotating
the key makes earlier entries unopenable. The originals of one call are kept under (`rid`, partner entry). That
names one call, because a second call from the egress with the same `rid` is `REPLAY` at the partner within the
nonce window. A sender that may call the same partner again later in one request, after the window, keeps
every call's originals, not only the last. Those calls derive the same salts, so opening one call's entry also
reveals the salt of the same group's entry in the others. The Java SDK's `BoundaryClient` hands each attested
call's originals and sent list to a listener before the request is sent, and sends nothing if the listener
fails, so no entry leaves that the sender could not open.

`http-v3.json`'s `boundaryInfluence` pins the salts, the sent entries, and an opening that opens and one with an extra
original that does not, each with its JCS bytes in `body`.
