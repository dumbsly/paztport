# Influence

Influence is a record of what content the context held when an action was decided. It is the extension named
`influence`. An extension is a named kind of claim that a hop attaches to its own stamp, in a
[block](wire.md#blocks) the stamp's `ext` commits to, and that the core carries without reading. This file says
where influence applies and what it does not cover, what its items are and how a service that acts on it reads
them, the rule that decides a public write and the one that guards a trusted record, and how influence crosses an
organisation's boundary blinded. The bytes of stamps, blocks, roots and keyrings are in [wire.md](wire.md), the
checks in [verification.md](verification.md), and the handshake and the boundary in [sessions.md](sessions.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Where influence applies](#where-influence-applies) · [What it does not cover](#what-it-does-not-cover) ·
[Classes](#classes) · [Entries](#entries) · [The every-stamp rule](#the-every-stamp-rule) ·
[Content labels](#content-labels) · [The owner-aware rule](#the-owner-aware-rule) ·
[Trusted records](#trusted-records) · [What the rules read](#what-the-rules-read) · [Over MCP](#over-mcp) ·
[Blinded influence](#blinded-influence)

## Where influence applies

Influence guards a component that can be steered by what it reads: a model. An ordinary, deterministic service is
not steered by content, and has simpler means of its own, such as validating its inputs and authorising its
callers, so in a mesh of ordinary services the path is the whole of what Paztport says. Influence has work to do
only around a model: at the service that hosts it, at the services that hand it content, and at the services that
guard a public write it can reach, possibly several hops later. Every service on a chain that reaches such a write
acts on `influence`, even one with nothing to add, or [the every-stamp rule](#the-every-stamp-rule) refuses the
write. Services elsewhere run the core alone, and a mesh with no model runs none of this extension.

Influence is not a general control for backend services: it is for systems with a model in them.

## What it does not cover

Naming `influence` is a hop's word that it tracks what it reads. A hop is the only witness of its own reads (its
database, a tool result, a ticket), and most influence enters that way, so a compromised or careless hop can name
the extension and stay silent about one. Pinning protects a claim once made: each stamp's signature covers its
block, so no later hop can drop or alter an entry without failing [check 9a](verification.md#the-live-order) at
every honest hop after it. It cannot make a hop report.

## Classes

Every entry and every label has one of four classes:

| Class | Meaning |
|---|---|
| `third-party` | Content from outside the trust boundary, which may carry instructions: an issue anyone can write, a web page. |
| `private` | Data that must not reach a public destination unless it belongs to the destination's owner. |
| `public` | Content that is already public. |
| `local-untrusted` | Content the client can't vouch for: a result that failed verification, came from an unattested server or is [silent](#content-labels), a local read from an unlabelled folder, a program's output. It counts as untrusted. |

A client MUST NOT drop an entry while the content it describes can still steer the session. The agents demo keeps
every entry until the session is cleared.

## Entries

An influence entry is an item under `influence` on a request's [block](wire.md#blocks): a JSON object with exactly
these members:

| Field | Required | Rule |
|---|---|---|
| `cls` | yes | One of the four classes. |
| `src` | yes | A string naming the source, for example `server:<serverId>`, `web:example.com`, for an HTTP response `http:<target>`, or, for a [blinded entry](#blinded-influence) from another organisation, `boundary:<egress>`. |
| `h` | yes | A string identifying the content, such as a hash of it; the agents demo uses the result binding, and the Java SDK an HTTP response's result hash. |
| `cid` | no | A string: the content id from the label the entry came from. |
| `owner` | no | A **non-empty** string: an opaque id of whose data this is. |

`h` and `cid` are only compared as text: neither is decoded, so neither is held to a canonical encoding
([wire.md](wire.md#encodings)).

Entries, labels and openings are read as [wire.md](wire.md#reading) reads any object. Entries and labels travel
inside blocks, so the core reads their bytes with the blocks, and this file gives their schema. A service that acts
on `influence` checks each item it is handed under that name, verified or not, before its handler runs. An item on a
request's block MUST be rejected when it is not an object, has a member the table does not name, has an unknown
`cls`, a `src` or `h` that is not a string, a `cid` that is not a string, or an `owner` that is not a non-empty
string. An empty `owner` is rejected, not read as "no owner", so it can never be taken for a known one. An item on a
response's block is read as a [label](#content-labels), which says what a caller does with one that does not read.

A request holding an item that does not read is refused `INFLUENCE_MISMATCH`. Over HTTP the refusal is
`400 {"reason":"INFLUENCE_MISMATCH"}`, in either mode: the core reads no item, so verification never refuses such
a request first, and serving it without the item would hide content from
[the owner-aware rule](#the-owner-aware-rule). An MCP server in audit mode runs the call and notes the code in its
verdict ([Over MCP](#over-mcp)). The code names no one and is never attributable, since the sender may be a hop
that passed along a block it could not have read; the service logs the signer of the offending block for its
operator.

## The every-stamp rule

**What a request holds.** The influence a request holds at a service is every `influence` item in every block it
received, plus what the service adds itself: an entry for each thing it reads, the responses to its own calls
among them ([Content labels](#content-labels)). The verifier hands the service the received items on `OK`, for
each stamp, in chain order ([the live order](verification.md#the-live-order)). A request served without being
verified, in audit mode after a failure or by a service that verifies no requests under a mode, is handed them too
where its chain read and its blocks passed check 9a, but as not verified, and a [trusted record](#trusted-records)
is never written from it. The owner-aware rule and the trusted-records rule read what the request holds.

When the service calls on, its own block holds only the entries it added itself, all of them for this request so
far ([wire.md](wire.md#blocks)). It does not copy the entries it received: those travel on unchanged in their own
blocks, each pinned to the hop that made it.

**The rule.** A service that acts on `influence` MUST name it in every block it signs, with `[]` when it has
nothing to add, except in a boundary block whose internal chain has a stamp that does not name it
([Blinded influence](#blinded-influence)). A guarded public write is refused (`INFLUENCE_DENIED`), and a trusted
record is not written, unless every stamp of the chain names `influence`, whatever the entries say. A stamp that
does not name it is a hop that may have read anything, the model's host included, so the absence of an untrusted
entry proves nothing. A block names `influence` only when it is a member of the block's `items`
([wire.md](wire.md#blocks)): a pass-along block `{"items":{},"requires":["influence"]}` does not name it. Where no
chain passed the live order at this hop, the rule reads what the service is shown
([What the rules read](#what-the-rules-read)).

This is the receiver demanding the extension from its own configuration. It holds whatever the caller's
`requires` says, so a caller that leaves `requires` out gains nothing. `requires` ([wire.md](wire.md#blocks)) is
for the opposite mistake, a write-guarding service deployed without the extension: a caller that requires
`influence` of it is refused at [check 9c](verification.md#the-live-order), before the handler runs, rather than
served by a service that would not apply the rule.

## Content labels

A server that acts on `influence` labels the content of each result it attests. A label is an item under
`influence` on the response's block, `{ "cid": ..., "cls": ..., "owner": ... }`, with exactly those members,
`owner` only when the label has one:

- `cls` is one of the four classes, and `cid` a fresh content id, a string (each SDK uses 16 random bytes,
  base64url);
- `owner`, when present, MUST be non-empty, and the server MUST take it from its own records of whose data it
  served, never from the content.

The response stamp's `ext` commits to its block, so a label can't be changed in transit ([wire.md](wire.md#blocks)).
A responder that acts on `influence` names it on every response it attests, with `[]` when it has no label. When any
block of the response holds a label, it also puts `influence` in the `requires` of the response's last block, so a
caller that does not act on `influence` refuses the response ([check 9c](verification.md#the-live-order)), not
handing it to its application, instead of dropping the labels. Check 9c reads only the last block: over HTTP the
response has one block, and over MCP the last block of the attestation is the one whose `requires` must hold it.

A caller that acts on `influence` adds to what it holds, for each response to a call it makes:

- **A response that verifies and names `influence`, every item under it a label:** one entry for each label,
  `{ cls, src, h: resultHash, cid, owner }`, with `owner` only when the label has one. A label counts only when the
  whole response verifies.
- **A response with an `influence` item that does not read as a label:** no label from that response, and one
  `local-untrusted` entry, as for a response that did not verify. The extension cannot refuse a response, only
  decline to believe it: only the core's check 9c refuses one.
- **A silent response,** one that verifies but whose block does not name `influence`: one `local-untrusted` entry,
  as a response from a service that does not attest adds.
- **Over MCP, a refusal:** a result whose verdict is not an audit note adds nothing, since the tool did not run
  ([the verdict rule](verification.md#the-mcp-server-and-client)).
- **Any other response:** one `local-untrusted` entry, never dropped. That is a response that fails verification,
  one that is not attested, over HTTP a refusal, and over MCP any result in an unsafe session that is not a
  refusal.

Over HTTP every entry a response adds, the `local-untrusted` one included, has `src = "http:<target>"` and
`h = resultHash`. `<target>` is the caller's name for the service it sent the request to: the receiver's policy
name, without any operation, which the response stamp must be by
([naming the receiver](verification.md#receivers-the-peer-and-attribution)). Over MCP the entry for a label has
`src = "server:<serverId>"` and `h = resultHash`. The responder cannot know the `src` a caller uses, so the caller
chooses it.

Over MCP the response chain's stamps are all the server's, so a response that verifies is silent unless every block
of its attestation names `influence`, and holds an item that is not a label unless every `influence` item in any of
them is a label. Either way it adds one `local-untrusted` entry.

Some responses are never attested, so their callers always count them `local-untrusted`:

- A response to a request that failed verification in audit mode: it is served, but not attested
  ([who attests](verification.md#http-requests-and-responses)).
- A response from a hop on which Paztport is off, as any unattested response. So turning a hop off can only add
  caution downstream, never vouch for anything ([outside the modes](verification.md#modes-and-refusals)).
- A partner's reply to an egress: the partner does not attest what it answers, so nothing it says counts as more.
  The entry's `src` is `http:<partner entry>` and its `h` the result hash
  ([sessions.md](sessions.md#between-organisations)).

## The owner-aware rule

One standing rule decides every write to a public destination. A write is **refused** when both hold:

- the influence the request holds ([above](#the-every-stamp-rule)) holds untrusted content: any `third-party` or
  `local-untrusted` entry; and
- it holds `private` data that is not the destination owner's: any `private` entry whose `owner` is absent or
  empty, or that differs from the destination's owner, or any `private` entry at all when the destination's owner
  is unknown (absent or empty).

Otherwise the write is allowed, unless [the every-stamp rule](#the-every-stamp-rule) refuses it first. A write to a
destination that is not public is not decided by this rule.

An unknown owner, on either side, fails closed: it counts as someone else's. So untrusted content can still
steer a write of a customer's own data to that customer, but never someone else's data, or data whose owner
nobody knows.

**Where the destination owner comes from.** The party applying the rule MUST take the destination's owner from
its own trusted records, such as the authenticated account the write is for or the stored owner of the target.
It MUST NOT take it from the request's arguments, from the content, or from the influence: those are what an
attacker writes.

A refused write is `INFLUENCE_DENIED`. Over HTTP it is `403 {"reason":"INFLUENCE_DENIED"}` in either mode: it is
the service's own refusal of the write, not a result of verification, so it does not follow audit mode. Over MCP it
is a verdict, which follows the mode: an audit-mode server runs the call and notes it ([Over MCP](#over-mcp)). Like
`INFLUENCE_MISMATCH`, it names no one and is never attributable.

`v3.json` pins the rule's truth table in `rule`: the two conditions above, not the every-stamp rule. In the agents
demo, neither entries nor destinations have owners, so the rule reduces to "untrusted content plus any private data
refuses a public write".

### Trusted records

Some writes go not to a destination but into the service's own trusted records: records later decisions take as
fact, such as who holds a card, which the owner-aware rule then reads as a destination's owner. The owner-aware
rule cannot judge such a write. It asks whose private data a write carries, and a record written because
untrusted text asked for it carries none: a hijacked model's charge would register its card to whoever it named,
and a later refund to that card would pass the rule. So a service MUST write a trusted record from a request only
when both of these hold:

- **The request's chain passed [the live order](verification.md#the-live-order) at this hop, and every stamp of
  it names `influence`**, so each block's items are the ones its stamp's signer committed to, and no hop on the
  path is one that may have read anything ([the every-stamp rule](#the-every-stamp-rule)). An origin, a service
  with no verifier, a hop on which Paztport is off, a request served in audit mode though its chain failed, a call
  in an unsafe partner session and work outside any request never qualify. Passing the live order at this hop is
  the condition the [egress](sessions.md#between-organisations) signs under.
- **The influence holds no untrusted content:** no `third-party` and no `local-untrusted` entry. That is the
  influence the request holds when the record is written: what came with it, and everything the service has read
  since, such as the responses to its own calls.

`private` and `public` entries, and owners, do not count either way: they say whose data the request read, not who
steered it. A request that fails the rule MAY still be served, but the record MUST NOT be written from it.

| Chain passed the live order at this hop, every stamp naming `influence` | Influence holds `third-party` or `local-untrusted` | The record |
|---|---|---|
| no | either | not written |
| yes | yes | not written |
| yes | no (no entries, or only `private` and `public` ones, with any owners) | may be written |

### What the rules read

The rules read what the service is shown, verified or not, plus what the service itself added. Where no chain
passed the live order at this hop they cannot refuse for what they are not shown, and a trusted record is never
written:

| The request at this hop | What the rules read | A guarded public write | A trusted record |
|---|---|---|---|
| Its chain passed the live order here | every `influence` item handed on, plus what the service added | the every-stamp rule over the chain's stamps, then the owner-aware rule | may be written when every stamp names `influence` and no entry is untrusted |
| Served but not verified, with items handed on as not verified (audit mode after a failure; a service that verifies no requests under a mode) | the items handed on, plus what the service added | the same two rules, over what is shown | never written |
| Nothing handed on (the chain did not read; over MCP, an audit-mode call whose blocks failed check 9a) | what the service added | the owner-aware rule over what the service added; the every-stamp rule has no stamp to read and does not refuse: the rule cannot refuse for what it is not shown | never written |
| At an origin | what the origin added | there is no earlier stamp, so the every-stamp rule holds; the owner-aware rule over what the origin added | never written |

What is handed on, and when, is the core's ([the live order](verification.md#the-live-order)). The item check
([Entries](#entries)) reads the items handed on, verified or not. An unsafe session is none of these rows: there
the server believes nothing from the call, and a tool or endpoint that `disabled` does not list runs with no
influence rule at all ([sessions.md](sessions.md#unsafe-sessions)).

## Over MCP

This section belongs to [the MCP profile](README.md#the-mcp-profile).

**Agent sessions.** The run's origin stamp names `influence` with `[]`. The client's stamp for each call carries
the session's whole influence as its block's `influence` items, since the client added all of it.

**The server's decision.** A server that acts on `influence` decides a write to a public destination, once the call
has verified in an attested session ([sessions.md](sessions.md#the-server-decision)), by the every-stamp rule and
then the owner-aware rule, over the client's influence, the items handed on from its call's blocks
([What the rules read](#what-the-rules-read)), plus every class the server has served in this session
(`INFLUENCE_DENIED`). The served classes only add facts: a client that fails to record a `private` or `third-party`
label can't launder it past the rule. A served class carries no owner, so it counts as unknown.

An MCP server in audit mode runs every call and notes its verdict, `INFLUENCE_DENIED` and `INFLUENCE_MISMATCH`
included, as for every code ([Modes and refusals](verification.md#modes-and-refusals)).

**The client's local gate** ([MCP profile](README.md#the-mcp-profile)) applies the owner-aware rule to its own
tools' writes into a folder whose destination is `public`, over the session's classes plus `private` when the call
itself reads a private-labelled folder (`INFLUENCE_DENIED`).

## Blinded influence

The owner-aware rule reads only each entry's class and owner, so that is all an egress that acts on `influence`
sends across a boundary ([sessions.md](sessions.md#between-organisations)). It MUST NOT send the original entries:
their `src` names internal services and items, and their `h` values could be confirmed by guessing.

**Across a boundary.** The partner sees one stamp, the boundary stamp, so its every-stamp rule cannot see a silent
internal hop. The egress therefore names `influence` in the boundary block only when every stamp of the internal
chain it verified names it. Otherwise it leaves the name out and sends no entries, and the partner's own
every-stamp rule refuses the guarded write and the trusted record, as a service inside the mesh would. This is the
one block in which a service that acts on `influence` leaves the name out.

**The sent entries.** The egress takes the influence the request holds after the internal chain passed the live
order at this hop, groups the entries by (`cls`, `owner`), with no owner a group of its own, and sends one entry per
group as an `influence` item of the boundary block, `[]` when there are none:

| Field | Value |
|---|---|
| `cls` | The group's class. |
| `src` | `boundary:<egress>`. |
| `h` | The group's commitment, below. |
| `owner` | The group's owner, left out when the group has none. |

A sent entry has no `cid`, and the sent list is normalised, so the same influence gives the same block whatever
order the egress met it in. An entry with an owner and the same entry without one fall in two groups, so two
entries are sent. When the egress names `influence` and the request holds no influence, there are no entries: the
boundary block names `influence` with `[]`. Every (class, owner) pair of the originals is in the sent list and no
other is, so the partner's verdict under the owner-aware rule is the one it would reach on the originals.

`normalise(entries)`:

1. Sort by `h`, then `cls`, then `src`, then `cid`, then `owner`, comparing strings by UTF-16 code units (the
   order JCS uses for keys). For `cid` and `owner`, an absent value sorts before any present one.
2. Remove exact duplicates: entries whose JCS forms are equal. An entry with an owner and the same entry without
   one are different, and both stay.

Neither a group's commitment nor the sent list may depend on the order of the blocks the entries came in, or on
the order a hop recorded them in, and an entry can repeat across blocks. So the egress normalises each group
before it commits to it, and the sent list before it sends it.

The egress holds a **boundary key** of exactly 32 bytes, kept as base64url in `boundary.key`
([wire.md](wire.md#keys-and-files)), which MUST NOT leave the sender; a key of any other length MUST be refused.
The salt below does not name the egress, so a boundary key MUST belong to one egress service and MUST NOT be shared
with another: two egress services with one key would derive the same salts for the same request and partner.
Replicas of one egress share its key. A new key makes the entries sent under the old one unopenable (below), so the
Java keygen writes `boundary.key` only when it does not exist, and refuses an existing one that is not 32 bytes. For
each group:

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

**At the partner.** A partner that acts on `influence` applies the owner-aware rule to the sent entries, once the
boundary chain has verified ([sessions.md](sessions.md#between-organisations)), taking the destination owner from
its own records. Its every-stamp rule reads the one boundary stamp.

**Opening an entry.** To show what one sent entry stood for, the sender reveals an opening:
`{ "cls", "originals", "owner", "salt" }`, with `originals` a list of entries, `owner` left out when the entry has
none, and `salt` base64url. An opening opens a sent entry only when all of these hold:

1. `originals` is not empty.
2. The opening's `cls` and `owner` are the sent entry's, and so are every original's: both absent, or equal.
3. `salt` decodes to exactly 16 bytes.
4. The commitment to `originals` under `salt` is the sent entry's `h`.

An opening travels as its wire bytes, the whole HTTP body in the PSP demo, and its reader is a checker. It is read
as [wire bytes](wire.md#reading): the JCS bytes of an object with exactly `cls`, `salt` and `originals`, and `owner`
when the entry has one, a non-empty string. A checker MUST answer "does not open" for anything else, and MUST NOT
fail in any other way. A checker that answers over a service, such as the PSP demo's `/debug/check-opening`, first
reads the request body. It refuses a body that does not read (whitespace around the opening, members out of JCS
order, a number that is not a protocol integer) or that is not one JSON object with
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
