# Sessions and influence

How two sides open a session and decide how far to trust each other, how influence is recorded and committed,
the one rule that decides a public write, and how a chain crosses from one organisation to another. The bytes of
stamps, roots and keyrings are in [wire.md](wire.md), and the checks in [verification.md](verification.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [The handshake](#the-handshake) · [The session id](#the-session-id) · [Status](#status) ·
[Unsafe sessions](#unsafe-sessions) · [The server decision](#the-server-decision) ·
[Recorded handshakes](#recorded-handshakes) · [Influence](#influence) · [Entries](#entries) ·
[Normalisation and commitment](#normalisation-and-commitment) · [Content labels](#content-labels) ·
[The owner-aware rule](#the-owner-aware-rule) · [Between organisations](#between-organisations)

## The handshake

Before it stamps any call, a client opens a session with the JSON-RPC method `paztport/session`. Each side
sends its signed root, its policy key, its keyring and a fresh nonce, and the server signs the reply. There is
one session per connection: a new handshake replaces the current one, with its keyring, nonce cache and served
classes, so calls signed for the old session are refused.

### The request

| Field | Type | Meaning |
|---|---|---|
| `clientRoot` | signed root, or `null` | The client's [signed root](wire.md#the-signed-root). `null` asks for an unsafe session. |
| `clientPolicyKey` | string | The client's policy public key. |
| `clientKeyring` | object | The client's services: name to public key. |
| `clientKeyringSig` | string | The client policy key's signature over the keyring: the `sig` of its [signed keyring](wire.md#the-signed-keyring), over `"paztport-keyring\n" ‖ JCS({ policy: clientPolicyKey, services: clientKeyring })`. |
| `nonce` | string | 16 fresh random bytes, base64url. |

A server MUST answer a request that is not an object, or whose `clientRoot` is neither `null` nor an object of
three strings (`rootId`, `root`, `sig`), whose `clientKeyring` is not an object of strings, or whose
`clientPolicyKey` or `nonce` is not a string, with JSON-RPC error `-32602` (Invalid params), and open no session.
It MUST also open none when the nonce is not 16 bytes or the client root's `sig` is not 64.

A `clientKeyringSig` that is missing or not a string is not malformed, only unsigned: the server reads it as
`""`, which never verifies, so the session is unsafe.

### The reply

| Field | Type | Meaning |
|---|---|---|
| `serverRoot` | signed root, or `null` | The server's signed root. |
| `serverPolicyKey` | string | The server's policy public key. |
| `serverKeyring` | object | The server's services: name to public key. |
| `nonce` | string | 16 fresh random bytes from the server, base64url. |
| `sess` | string | [The session id](#the-session-id). |
| `status` | `"attested"` or `"unsafe"` | See [Status](#status). |
| `disabled` | array of strings | The tools refused in this session: the server's unsafe-session list when `status` is `"unsafe"`, and `[]` when it is `"attested"`. |
| `sig` | string | The server policy key's signature over the reply's other fields. |

The reply's signed bytes are:

```
utf8( "paztport-session-reply\n" ‖ JCS(reply without its "sig" field) )
```

That one signature covers the server's root, keyring, nonce, session id, status and disabled list. So the
server's keyring is signed by its policy key through the reply, and needs no signature of its own here.

### The client's check of the reply

A client pins the server's policy key in advance. In order, the first failure is the outcome:

1. The reply has the shape above (`MALFORMED_REPLY`).
2. `serverPolicyKey` equals the pinned key (`PIN_MISMATCH`).
3. `sig` verifies under the pinned key; an `"attested"` reply has both roots non-null; `sess` equals the session
   id the client derives from its own request and the reply; and `serverRoot`, when present, verifies under the
   pinned key (`BAD_SIGNATURE`).
4. `status` is `"attested"`: the session is attested. Otherwise it is unsafe (`UNSAFE`).

After an outcome from 1 to 3, or a JSON-RPC error or timeout, the server may have opened an attested session
the client can't use, so every unstamped call would be refused. The client SHOULD replace it: it sends the same
request again with `clientRoot: null` and a fresh nonce, and trusts the reply to that either way. A reply
`-32601` (Method not found) means the server has no Paztport, so there is nothing to replace.

## The session id

The session id binds both roots, both nonces and the client's policy key and keyring:

```
sess = b64url( H( 0x02 ‖ flags ‖ clientRootSig ‖ serverRootSig ‖ clientNonce ‖ serverNonce ‖ keysHash ) )
```

| Part | Bytes | Value |
|---|---|---|
| `0x02` | 1 | A fixed domain byte. |
| `flags` | 1 | `0x01` when the client root is present, plus `0x02` when the server root is present. |
| `clientRootSig` | 64, or 0 | The client root's `sig`, decoded. Omitted when `clientRoot` is `null`. |
| `serverRootSig` | 64, or 0 | The server root's `sig`, decoded. Omitted when `serverRoot` is `null`. |
| `clientNonce` | 16 | The request's `nonce`, decoded. |
| `serverNonce` | 16 | The reply's `nonce`, decoded. |
| `keysHash` | 32 | `H(utf8(JCS({ "clientPolicyKey": clientPolicyKey, "clientKeyring": clientKeyring })))` |

Each decoded value MUST have exactly the length shown, or there is no session id. `flags` says which roots are
present, so input without a root can't be read as input with one. The layout is the same as in v2, and
`v2.json` pins it in `deriveSessionId`. It does not cover `clientKeyringSig`: it binds the keyring itself, and
the server checks the signature before it attests.

Every v3 stamp in the session carries `sess`, so a chain made for one session fails in any other.

## Status

A server opens an **attested** session only when all of these hold, and an **unsafe** one otherwise:

- `clientRoot` and its own root are both present;
- `clientRoot` verifies under `clientPolicyKey`, and its own root under its own policy key;
- `clientPolicyKey` is one of the client policy keys the server has pinned;
- `clientKeyringSig` verifies as the signature of the keyring `{ policy: clientPolicyKey, services: clientKeyring }`
  under `clientPolicyKey`.

A server with no pinned client keys MUST open every session unsafe. Without the pin, anyone could make a policy
key, sign a root and keyring with it, and be attested. Without the keyring signature, the keyring would be the
client's own claim. Pinning the policy key rather than a root lets the client rotate its roots and keyrings
without being pinned again.

## Unsafe sessions

An unsafe session is graded trust, not a refusal. In it:

- The server does not verify calls, and does not attest results.
- Every tool in `disabled` is refused with `UNSAFE_SESSION`; every other tool runs, ungated. A server's default
  list SHOULD hold every write tool: a tool left off it runs with no influence rule at all.
- The client counts every result as `local-untrusted`.

A call made before any handshake is treated as in an unsafe session.

## The server decision

Once a call has verified in an attested session ([verification.md](verification.md#the-mcp-server-and-client)),
the server decides it:

1. A call that failed verification is refused with its code.
2. In an attested session, a write to a public destination is decided by [the owner-aware rule](#the-owner-aware-rule),
   over the client's verified influence plus every class the server has served in this session
   (`INFLUENCE_DENIED`). Anything else is allowed.
3. In an unsafe session, or with no session, the tools in `disabled` are refused (`UNSAFE_SESSION`).

The served classes only add facts: a client that fails to record a `private` or `third-party` label can't
launder it past the rule. A served class carries no owner, so it counts as unknown.

A refusal is a result with `isError: true` and `_meta["paztport/verdict"] = { "reason": <code> }`, and the tool
does not run. An audit-mode server runs the call anyway and adds `"audit": true`. A server attests a result only
for a call that verified.

## Recorded handshakes

Offline, a recorded handshake opened an attested session only when the reply's `status` is `"attested"`, the
reply passes the client's check against the recorded pin, both roots verify against their sides' policy keys,
and the keyring signature verifies. When the request has no `clientKeyringSig` field at all, it is legacy: the
keyring check is skipped, and the result is marked legacy ([verification.md](verification.md#the-legacy-rule)).

There is no client pin offline. The server's signed `"attested"` reply, whose session id binds the client's
policy key and keyring, is its statement that it pinned them.

## Influence

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

An influence entry is a JSON object:

| Field | Required | Rule |
|---|---|---|
| `cls` | yes | One of the four classes. |
| `src` | yes | A string naming the source, for example `server:<serverId>` or `web:example.com`. |
| `h` | yes | A string identifying the content, such as a hash of it; the agents demo uses the result binding. |
| `cid` | no | A string: the content id from the label the entry came from. |
| `owner` | no | A **non-empty** string: an opaque id of whose data this is. |

A list of entries MUST be rejected when it is not an array, or any entry is not an object, has an unknown
`cls`, a `src` or `h` that is not a string, a `cid` that is not a string, an `owner` that is not a non-empty
string, or a lone surrogate in any string. A verifier reports that as `INFLUENCE_MISMATCH`. An empty `owner` is
rejected, not read as "no owner", so it can never be taken for a known one. Other fields are dropped; they are
not committed to.

## Normalisation and commitment

`normalise(entries)`:

1. Rebuild each entry with only `cls`, `src`, `h`, and `cid` and `owner` when present.
2. Sort by `h`, then `cls`, then `src`, then `cid`, then `owner`, comparing strings by UTF-16 code units (the
   order JCS uses for keys). For `cid` and `owner`, an absent value sorts before any present one.
3. Remove exact duplicates: entries whose JCS forms are equal. An entry with an owner and the same entry without
   one are different, and both stay.

The commitment is `""` when there are no entries, and otherwise:

```
infl = b64url( H( utf8( JCS( normalise(entries) ) ) ) )
```

Normalising first means the order a client happened to record things in doesn't change the commitment. Entries
without `owner` commit exactly as they did before owners existed, so a v2 commitment is unchanged: the first
case of `v3.json`'s `influence` gives the same commitment as `v2.json`'s `commitInfluence`. `v3.json` pins the
owner's sort position and the with-and-without case.

## Content labels

A server labels the content of each result it attests. A label is `{ "cls": ..., "cid": ..., "owner": ... }`:

- `cls` is one of the four classes, and `cid` a fresh content id (the SDK uses 16 random bytes, base64url);
- `owner`, when present, MUST be non-empty, and the server MUST take it from its own records of whose data it
  served, never from the content.

The labels are covered by the response binding ([wire.md](wire.md#bindings)), so they can't be changed in
transit. A client MUST add a label to its influence only when the whole response verifies, as the entry
`{ cls, src: "server:<serverId>", h: resultHash, cid, owner }` (with `owner` only when the label has one). A
response that does not verify adds `local-untrusted` instead.

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

The client's local gate applies the same rule to its own tools' writes into a folder whose destination is
`public`, over the session's classes plus `private` when the call itself reads a private-labelled folder
(`INFLUENCE_DENIED`).

## Between organisations

When a request crosses from one organisation to another, the receiving organisation (the partner) MUST NOT see
the sender's internal chain, which is the map the protocol keeps private. A boundary attestation crosses
instead. No SDK implements it yet; implementations that bridge two organisations MUST follow this section.

**The sender's egress service.** The sender's last internal hop before the boundary is its egress service. It
MUST:

1. Verify the internal chain it received, as a receiver, in [the live order](verification.md#the-live-order),
   and refuse the request if it fails.
2. Start a new chain at the boundary with exactly one stamp, the **boundary stamp**, signed with the egress
   service's own key, a key in the sender's signed keyring:
   - `svc`: the egress service;
   - `rid`: the internal chain's `rid`, unchanged;
   - `ts`: the time it signs;
   - `sess`: the id of the session the sender opened with the partner;
   - `rcv`: the partner's entry service;
   - `bind`: the binding of the request it sends;
   - `infl`: the commitment to the accumulated influence, **with owners**;
   - `prev`: `""`.
3. Send the influence entries, with their owners, and the proof for the route `<egress>/<partner entry>`, which
   the sender's root MUST hold.
4. Never forward an internal stamp. So the partner learns one service name and the influence, not the route
   behind it, and check 6 (every stamp carries the session) holds unchanged.

**The partner.** The partner MUST pin the sender's policy key in advance, out of band, as partner onboarding.
It pins the key, not a root, so the sender can rotate roots and keyrings without being pinned again. In the
handshake the sender is the client: it sends its signed root, policy key, keyring and keyring signature, and the
partner attests the session only if the policy key is one it pinned. **An unpinned key gives an unsafe
session**, not a refusal: the partner serves what it allows to unattested callers and disables the rest.

The partner verifies the boundary chain in the live order against the sender's root and keyring from the
session, with the egress service as an allowed origin, `receiver` = its own entry service and
`receiverInRoute = true`. It then applies [the owner-aware rule](#the-owner-aware-rule) to the carried
influence, taking the destination owner from its own records.

What the partner can still learn: the boundary proof is the same on every request over that route, so it can
count and cluster requests by route. The root README's known limits cover that.
