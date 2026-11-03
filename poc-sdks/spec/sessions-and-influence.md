# Sessions and influence

How two sides open a session and decide how far to trust each other, how influence is recorded and committed, the
one rule that decides a public write and the one that guards a trusted record, and how a chain crosses from one
organisation to another. The bytes of stamps, roots and keyrings are in [wire.md](wire.md), and the checks in
[verification.md](verification.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [The handshake](#the-handshake) · [Over HTTP](#over-http) · [The session id](#the-session-id) ·
[Status](#status) · [Unsafe sessions](#unsafe-sessions) · [The server decision](#the-server-decision) ·
[Recorded handshakes](#recorded-handshakes) · [Influence](#influence) · [Entries](#entries) ·
[Normalisation and commitment](#normalisation-and-commitment) · [Content labels](#content-labels) ·
[The owner-aware rule](#the-owner-aware-rule) · [Trusted records](#trusted-records) ·
[Between organisations](#between-organisations)

## The handshake

Before it stamps any call, a client opens a session with the JSON-RPC method `paztport/session`. Each side
sends its signed root, its policy key, its keyring and a fresh nonce, and the server signs the reply. There is
one session per connection: a new handshake replaces the current one, with its keyring, nonce cache and served
classes, so calls signed for the old session are refused.

The params are `{"request": "<token>"}`, the [request](#the-request)'s token, and the result is
`{"reply": "<token>"}`, the [reply](#the-reply)'s token, each the base64url of the object's JCS bytes
([wire.md](wire.md#carrying-an-object)). MCP lets every request and result carry `_meta`, such as a progress token:
the server ignores the params' `_meta`, and the client the result's. A server MUST answer params with any other
member, or whose `request` is missing, not a string or does not read, with JSON-RPC error `-32602` (Invalid params),
and open no session. A client MUST take a result with any other member, or whose `reply` is missing or not a string,
as `MALFORMED_REPLY`, as it takes a reply that does not read ([its check](#the-clients-check-of-the-reply)).
`v3.json` pins both readings, in `sessionParams` and `sessionResult` (MCP profile).

### The request

| Field | Type | Meaning |
|---|---|---|
| `clientRoot` | signed root, or `null` | The client's [signed root](wire.md#the-signed-root), whole: its `notAfter` travels inside it. `null` asks for an unsafe session. |
| `clientPolicyKey` | string | The client's policy public key. |
| `clientKeyring` | object | The client's services: name to public key. |
| `clientKeyringSig` | non-empty string | The client policy key's signature over the keyring: the `sig` of its [signed keyring](wire.md#the-signed-keyring), over `"paztport-keyring\n" ‖ JCS({ notAfter: clientKeyringNotAfter, policy: clientPolicyKey, services: clientKeyring })`. |
| `clientKeyringNotAfter` | integer | The keyring's `notAfter`. |
| `nonce` | string | 16 fresh random bytes, base64url. |

`clientKeyringSig` is checked over the request's own `clientKeyringNotAfter` member, and a root's signature over
its own `notAfter` member, as for any [signed root or keyring](wire.md#keys-and-files). A window moved in transit
therefore fails its signature.

A request is read from its bytes as [wire bytes](wire.md#reading), and has exactly the members above; a client root
has exactly a [signed root's](wire.md#the-signed-root) members. Over MCP it is read from the token in the params'
`request`. A server MUST answer a request that does not read, or that is not an object, has a member the table
does not list, or whose `clientRoot` is neither `null` nor an object of exactly string `rootId`, `root` and `sig`
and an integer `notAfter`, whose `clientKeyring` is not an object of strings or names a service that is not a [route
node](wire.md#routes), whose `clientPolicyKey` or `nonce` is not a string, whose `clientKeyringSig` is missing,
`null`, not a string or empty, or whose `clientKeyringNotAfter` or `clientRoot.notAfter` is missing or not an
integer in [0, 2^53 − 1] (`null` included), with JSON-RPC error `-32602` (Invalid params), and open no session. It
MUST also open none when the nonce is not 16 bytes or the client root's `sig` is not 64, and MUST answer that with a
JSON-RPC error other than `-32601`, so the client takes its replacement path
([below](#the-clients-check-of-the-reply)). A request that opens no session leaves the connection's current session,
if any, in place: the TypeScript server fails before it replaces it.

A `clientKeyringSig` that is a string but does not verify is no malformed request: the session is unsafe live, and
offline it is not attested.

`v3.json` pins the reading of a request in `sessionRequest`: a well-formed request, and one whose `clientKeyringSig`
is missing, `null`, empty or a number, one with no `clientKeyringNotAfter`, one whose client root has no
`notAfter` and one whose signed keyring names a service that is not a route node, each malformed.

### The reply

| Field | Type | Meaning |
|---|---|---|
| `serverRoot` | signed root, or `null` | The server's signed root, whole, its `notAfter` inside it. |
| `serverPolicyKey` | string | The server's policy public key. |
| `serverKeyring` | object | The server's services: name to public key. |
| `serverKeyringSig` | string, entry-key form only | The server policy key's signature over the keyring: the `sig` of its [signed keyring](wire.md#the-signed-keyring), over `"paztport-keyring\n" ‖ JCS({ notAfter: serverKeyringNotAfter, policy: serverPolicyKey, services: serverKeyring })`. |
| `serverKeyringNotAfter` | integer, entry-key form only | The `notAfter` that `serverKeyringSig` was made over, present exactly when `serverKeyringSig` is. |
| `serverReplyCert` | object, entry-key form only | A [reply certificate](wire.md#the-reply-certificate) from the server policy key for the server's entry service and its key. |
| `nonce` | string | 16 fresh random bytes from the server, base64url. |
| `sess` | string | [The session id](#the-session-id). |
| `status` | `"attested"` or `"unsafe"` | See [Status](#status). |
| `disabled` | array of strings | The tools refused in this session: the server's unsafe-session list when `status` is `"unsafe"`, and `[]` when it is `"attested"`. |
| `sig` | string | The signature over the reply's other fields: by the entry service's key in the entry-key form, by the server policy key in the policy-key form. |

A reply is read from its bytes as [wire bytes](wire.md#reading), and has exactly the members above, the three of
the entry-key form each only when present; a non-null `serverRoot` has exactly a
[signed root's](wire.md#the-signed-root) members, and a `serverReplyCert` exactly a
[reply certificate's](wire.md#the-reply-certificate). Over MCP it is read from the token in the result's `reply`.

A reply is in one of two forms, told apart only by which fields are present:

- **The entry-key form** carries both `serverKeyringSig` and `serverReplyCert`, and `sig` is made with the key the
  certificate names, the server's entry service's own key. The policy key signs the keyring and the certificate
  offline, so it need not be online to answer handshakes.
- **The policy-key form** carries neither, and `sig` is made with the server policy key.

A reply with one of the two fields and not the other is in neither form, and fails the check. A server SHOULD send
the entry-key form, so that its policy private key can stay offline. Either way the server MUST say
`"attested"` only after the checks of [Status](#status): only the signing key differs between the forms.

The reply's signed bytes are:

```
utf8( "paztport-session-reply\n" ‖ JCS(reply without its "sig" field) )
```

That is the reply as read, every member but `sig`: `serverKeyringSig`, `serverKeyringNotAfter` and
`serverReplyCert` included when present. A reply reads only from its canonical bytes, so these are the JCS bytes of
the object received, less its `sig`.

That one signature covers the server's root, keyring, nonce, session id, status and disabled list. In the
policy-key form the keyring is therefore signed by the policy key through the reply. In the entry-key form the
signer is only the entry service, so the keyring carries the policy key's own signature, and the certificate says
that the signing key is the entry service's and is still current. Without the keyring's signature the keyring
would be only the reply's own claim, and could name any key as the entry service's.

### The client's check of the reply

A client pins the server's policy key in advance, and knows the name of the server's entry service,
`serverEntry`, from its own configuration. It MUST NOT take `serverEntry` from the reply. The check is made at a
time `now`, in milliseconds since the Unix epoch: live, the client's current time. In order, the first failure is
the outcome:

1. The reply reads, with exactly the members above; `serverKeyringSig`, when present, is a string beside a
   `serverKeyringNotAfter`; `serverKeyringNotAfter`, when present, and the `notAfter` of a non-null `serverRoot` are
   integers in [0, 2^53 − 1]; every name in `serverKeyring` is a [route node](wire.md#routes); and
   `serverReplyCert`, when present, is a [reply certificate](wire.md#the-reply-certificate) with exactly its
   members. A field whose value is `null` is present (`MALFORMED_REPLY`).
2. `serverPolicyKey` equals the pinned key (`PIN_MISMATCH`).
3. The signature, then the roots and the session id (`BAD_SIGNATURE`):
   - When `serverKeyringSig` or `serverReplyCert` is present: both are; the keyring
     `{ policy: serverPolicyKey, services: serverKeyring, sig: serverKeyringSig, notAfter: serverKeyringNotAfter }`
     verifies under the pinned key; the certificate verifies under the pinned key; its `svc` equals `serverEntry`;
     `serverKeyring` has a member of its own named `serverEntry`, equal to the certificate's `key`;
     `now <= notAfter`; `now <= serverKeyringNotAfter`; and `sig` verifies under the certificate's `key`.
   - When neither is present: the reply has no `serverKeyringNotAfter` either, and `sig` verifies under the
     pinned key. In this form the keyring has no signature of its own (the policy key signs it through the reply),
     so a keyring window there is vouched for by nothing, and fails like either field without the other.

   Then, in both forms: an `"attested"` reply has both roots non-null; `sess` equals the session id the client
   derives from its own request and the reply; and `serverRoot`, when present, verifies under the pinned key and
   `now <= serverRoot.notAfter`.
4. `status` is `"attested"`: the session is attested. Otherwise it is unsafe (`UNSAFE`).

The server's root, and in the entry-key form its keyring, are judged at `now` whatever the reply's `status`: an
expired one is `BAD_SIGNATURE`, so the client takes its replacement path. A window is relied on only after the
policy key's signature over it has verified, the root's under the pin and the keyring's as above: the entry key
signs the reply, windows included, so the reply's own signature never vouches for one. A server whose own material
has expired ([Status](#status)) is therefore unsafe at the client too. This is the live check; a recorded
handshake is checked offline ([Recorded handshakes](#recorded-handshakes)).

The form is decided by which fields are present, never by which key verifies. A client MUST NOT try the pinned
key when the certificate's key fails, or the other way round: a reply stripped of its certificate, or given one,
would then pass under whichever key signed it. A lookup of `serverEntry` in `serverKeyring` MUST find only the
object's own members, so that a name such as `constructor` finds nothing in a keyring that does not list it.

**What the entry key can do.** A compromised entry-service key, while a certificate for it is unexpired, can forge
a reply's nonce, session id, status and disabled list, and can present any root or keyring the policy key signed
that has not yet expired, but can make none, and can't revive an expired one: roots and keyrings, windows
included, are verified under the pinned key, and a client refuses an expired one live. That key already signs
every response stamp the server attests, so a server that attests its responses already relies on it. Once its
certificates have expired it signs nothing a client accepts, so the revocation delay is the certificate's lifetime
([wire.md](wire.md#the-reply-certificate)).

**Domain separation.** Each kind of signed message starts with its own prefix, so that no signature can be read
as another kind: session replies `"paztport-session-reply\n"`, reply certificates `"paztport-reply-cert\n"`,
roots `"paztport-root\n"`, keyrings `"paztport-keyring\n"`, responder events `"paztport-event\n"`, and stamps
`3|`.

`v3.json` pins the check in `sessionReply`: the entry-key form attested and unsafe, the policy-key form attested, a
check at `notAfter` and one 1 ms after it, and forms that fail: a certificate for another service, for a key other
than the keyring's entry key, or signed by another policy key; a reply signed by another service; a keyring altered
after signing or signed by another policy key; an entry absent from the keyring; either of `serverKeyringSig` and
`serverReplyCert` without the other, whichever key signed the reply; neither field, signed by a key the reply's own
keyring names for the entry; a server root signed by the entry key; an empty and a `null` `serverKeyringSig`; a
`null` `serverReplyCert`; a `notAfter` that is not an integer; a member the reply does not have and a signed keyring
that names a service that is not a route node, each malformed; a pin mismatch; a `serverKeyringNotAfter` moved after
signing, which fails the signature, and one dropped, one that is not an integer and one that is `null`, which are
malformed; and a server root `notAfter` moved after signing, which fails the signature, and one dropped and one that
is not an integer, which are malformed. It pins the judging of the server's material too: a server root at its
`notAfter`, and expired (in the entry-key form, in the policy-key form and in an unsafe reply), and expired with its
`notAfter` moved past `now` in a reply signed again by the entry key; a server keyring at its `notAfter` and
expired; and a `serverKeyringNotAfter` in a policy-key reply. Every other root and keyring in these cases is valid
until long after every case's `now`.

After an outcome from 1 to 3, or a JSON-RPC error or timeout, the server may have opened an attested session
the client can't use, so every unstamped call would be refused. The client SHOULD replace it: it sends the same
request again with `clientRoot: null` and a fresh nonce, and trusts the reply to that either way. A reply
`-32601` (Method not found) means the server has no Paztport, so there is nothing to replace.

### Over HTTP

The Java and Go SDKs carry the handshake over HTTP. The request and the reply are the same JSON objects, and the
session is the same.

| Part | Rule |
|---|---|
| Endpoint | `POST /paztport/session`. The body is the request's JCS bytes, with `Content-Type: application/json`, and a `200` returns the signed reply's JCS bytes. |
| A body that does not read as a request: bytes that are not its JCS bytes (another member order, or a newline after them, as a file an editor saved ends), and a request [above](#the-request) refuses (a `clientKeyringSig` that is missing, `null`, not a string or empty, a `clientKeyring` naming a service that is not a route node, and a `clientKeyringNotAfter` or `clientRoot.notAfter` that is missing or not an integer in [0, 2^53 − 1], included) | `400 {"error":"INVALID_PARAMS"}`. The server reads at most the [wire limit](wire.md#limits), 256 KiB, and answers more than that the same way. |
| A request that opens no session | `400 {"error":"NO_SESSION"}`: the checks of [The request](#the-request), or no client certificate, or one that names no single service or no issuer. |
| `404` | The server has no Paztport. The Java and Go clients cannot tell this from any other failed handshake, so they send the replacement anyway; that is answered `404` too, and the call fails. |

**Sessions are kept by id, each bound to the peer that opened it.** HTTP has no connection to hold a session, so
the server records, with each session, the peer the TLS layer authenticated: the client certificate's issuer (its
RFC 2253 name) and its subject's common name, the service, never a name in the body. Over MCP nothing
changes: one session per connection, as [above](#the-handshake).

- **A handshake adds a session and replaces none.** So clients that share a certificate, such as replicas, each
  keep their own, up to the limit below, and a client that opens a new session does not cut off calls still in
  flight in its earlier one. A request that opens no session changes no session.
- **A peer holds at most N sessions**, a limit the server sets (16 in the Java SDK). A handshake that would give
  it more evicts its least recently used. Replicas that share a certificate are one peer, so beyond N of them
  evict each other's least recently used sessions. A call that then names an evicted session is refused, and the
  client opens a new one on its next call. A server MUST NOT evict one peer's session for another peer's
  handshake.
- **A session no call has used for the server's idle period expires** (15 minutes in the Java SDK).

So the server keeps at most N sessions for each peer its CAs vouch for.

**Calls name their session** in the `X-Path-Session` request header, whose value is the session id
([wire.md](wire.md#http-v3)).

- **No header** means the caller never opened a session. The server treats the call as in an unsafe session.
- **A header that names no live session opened by this call's peer** is refused
  `403 {"reason":"SESSION_UNKNOWN"}`. A server MUST take a session as the call's only when the issuer and the name
  it recorded for it are both those of the call's authenticated peer. A call with no client certificate, or one whose
  certificate has no issuer or names no single service, matches no session. So this covers another peer's id,
  the same name's id under another issuer (issuers are told apart by their distinguished name, not by the CA's
  key), an evicted or expired id, and one from before the server restarted.
  The server MUST NOT take it as unsafe, or a caller refused in an attested session could step down to an unsafe
  one by naming a wrong id. A client that gets it drops the session and opens a new one on its next call. A client
  reads a refusal from its [wire bytes](wire.md#reading), `{"reason":"<code>"}` and no other member; any other body
  gives no reason, and the session is kept.
- **Otherwise** the call is in that session, attested or unsafe as the handshake said, and the session's idle
  period starts again.

In an attested session each call is verified by a verifier of its own, built from the client's keyring and
root as the handshake presented them, with `sess` = the session id, so a stamp made in one session never
verifies in another ([verification.md](verification.md#http-requests-and-responses)). Inside one organisation's
mesh there is no handshake, and `sess` stays `""`.

In an unsafe session the server verifies nothing and believes nothing from the call: it starts with no
influence and no verified chain, whatever headers came. The reply's `disabled` lists operations as
`<METHOD> <route pattern>`, such as `POST /refund`, where the pattern is that of the handler the server
dispatches the request to, not the path the caller wrote. So `/refund;x=1` and `//refund` are refused as
`POST /refund`. A `HEAD` is refused wherever the matching `GET` is. A refusal is `403 {"reason":"UNSAFE_SESSION"}`
and the handler does not run.

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
present, so input without a root can't be read as input with one. `v3.json` pins the layout in `deriveSessionId`.
It does not cover `clientKeyringSig` or `clientKeyringNotAfter`: it binds the keyring itself, and the server
checks the signature, over that window, before it attests.

Every v3 stamp in the session carries `sess`, so a chain made for one session fails in any other.

## Status

A server opens an **attested** session only when all of these hold, and an **unsafe** one otherwise:

- `clientRoot` and its own root are both present;
- `clientRoot` verifies under `clientPolicyKey`, and its own root under its own policy key;
- `clientPolicyKey` is one of the client policy keys the server has pinned;
- `clientKeyringSig` verifies as the signature of the keyring
  `{ policy: clientPolicyKey, services: clientKeyring, notAfter: clientKeyringNotAfter }` under `clientPolicyKey`;
- both keyrings and both roots are current at the handshake, at the server's time `now`:
  `now <= clientRoot.notAfter` and `now <= clientKeyringNotAfter`, and the same for the server's own root and
  keyring.

A server with no pinned client keys MUST open every session unsafe. Without the pin, anyone could make a policy
key, sign a root and keyring with it, and be attested. Without the keyring signature, the keyring would be the
client's own claim. Pinning the policy key rather than a root lets the client rotate its roots and keyrings
without being pinned again.

Without the windows, a root or keyring the client's policy owner once signed would be attested for ever, a narrowed
policy or a retired key among them. Each client window is relied on only once the signature over it has verified,
so one moved in transit makes the session unsafe: the root's own signature is all that guards the root's window. A
server whose own root or keyring has expired while it runs degrades rather than stops: it opens every new session
unsafe, refusing the tools in its unsafe list and running the rest as for any unattested caller. Sessions it
attested earlier are still verified against the client's material, and their calls are refused `POLICY_EXPIRED`
once that expires ([verification.md](verification.md#the-live-order)).

`v3.json` pins this in `sessionStatus`, each case a request, the server's own root and keyring, its policy key, the
client keys it pinned and `now`: attested; an unpinned client key; the client's root and keyring each at its
`notAfter`, expired, and expired with its window moved past `now`; the server's root and keyring at their
`notAfter`; and each expired.

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

A refusal is a result with `isError: true` and `_meta["paztport/verdict"]` the token of `{ "reason": <code> }`, and
the tool does not run. An audit-mode server runs the call anyway, and its verdict adds `"audit": true`. A server
attests a result only for a call that verified.

## Recorded handshakes

A record keeps the request's token as sent and the reply's as received, and a verifier reads each as
[wire bytes](wire.md#reading), as [above](#the-handshake).

Offline, a recorded handshake opened an attested session only when the reply's `status` is `"attested"`, the
reply passes the client's check against the recorded pin and the server's entry service from the verifier's own
configuration, both roots verify against their sides' policy keys, and the keyring signature verifies. A recorded
request that is not a well-formed request, a missing `clientKeyringSig` or a member a request does not have
included, opened no attested session.

The handshake record carries no signed time, so it is judged at each call's recorded time, the call's last stamp's
`ts`, which the client signed: `now` in the check is the time of the record being judged. One session can therefore
be attested for the calls recorded up to its limits and not for those after them. Its limits are the certificate's
`notAfter` (entry-key form) and the `notAfter` of each root and keyring, the client's and the server's. A verifier
asking whether the session was attested at all judges it at the earliest of those, since each is an upper bound. A
recorded response is limited only by the server's root window and, in the entry-key form, the server
keyring's: the client's windows and the certificate do not limit it.

There is no client pin offline. The server's signed `"attested"` reply, whose session id binds the client's
policy key and keyring, is its statement that it pinned them.

A root or keyring is judged at the record's time, on both sides, as above, but only after its own signature has
verified: the root's under its side's policy key, the client keyring's under the client policy key, and the server
keyring's under the pin. Each signature is checked over its own window, so one moved in the record fails its
signature offline too, and an inherited one never counts. One dropped from the record leaves a root or keyring
without a window, which a reader refuses, so the handshake opened no attested session.

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
  is the same condition the [egress](#between-organisations) signs under.
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

## Between organisations

When a request crosses from one organisation to another, the receiving organisation (the partner) MUST NOT see
the sender's internal chain, which is the map the protocol keeps private. A boundary attestation crosses
instead. The Java SDK implements this section over HTTP, in `BoundaryClient` for the sender and in partner mode
for the partner, and the Go SDK in `boundary.Egress` for the sender and `paztporthttp.Sessions` for the partner;
the TypeScript SDK does not. Implementations that bridge two organisations MUST follow it.

**The sender's egress service.** The sender's last internal hop before the boundary is its egress service. It
MUST:

1. Verify the internal chain it received, as a receiver, in [the live order](verification.md#the-live-order),
   and refuse the request if it fails. A request that did not pass the live order at this hop, or that has no
   request scope to be in, MUST NOT cause anything to be signed or sent, the handshake included. So a service
   with no verifier, one on which Paztport is off ([outside the modes](verification.md#modes-and-refusals)), a
   chain that failed in audit mode, and an origin cannot be the egress for that request.
2. Start a new chain at the boundary with exactly one stamp, the **boundary stamp**, signed with the egress
   service's own key, a key in the sender's signed keyring:
   - `svc`: the egress service;
   - `rid`: the internal chain's `rid`, unchanged;
   - `ts`: the time it signs;
   - `sess`: the id of the session the sender opened with the partner;
   - `rcv`: the partner's entry service;
   - `bind`: the binding of the request it sends;
   - `infl`: the commitment to the influence entries it sends (step 3), which carry the owners;
   - `prev`: `""`.

   A boundary stamp MUST have a non-empty `sess`, so it is never valid inside a mesh, where `sess` is `""`.
3. Send the influence as [blinded entries](#blinded-influence), one per class and owner, and the proof for the
   route `<egress>/<partner entry>`, which the sender's root MUST hold. It MUST NOT send the original entries:
   their `src` names internal services and items, and their `h` values could be confirmed by guessing.
4. Never forward an internal stamp. So the partner learns one service name and the classes and owners of the
   influence, not the route or the sources behind them, and check 6 (every stamp carries the session) holds
   unchanged.
5. In an unsafe session, sign no stamp and send no influence. The partner would not verify the stamp, and the
   owners in the influence are private. The call carries only the session id.
6. Pin the partner's policy key and check the handshake reply against it, with `serverEntry` the partner's entry
   service ([above](#the-clients-check-of-the-reply)). Over HTTP, a reply the client cannot use, an HTTP error (a `404`
   included) or no answer within the handshake's timeout (10 s in the Java SDK) is followed by the replacement
   with no root, and the session is taken as unsafe whatever that reply says. From a server with no Paztport the
   replacement gets a `404` too, and the call fails.
7. Record every partner reply as one `local-untrusted` entry (`src` `http:<partner entry>`, `h` the result
   hash). The partner does not attest what it answers, so nothing it says counts as more.

The Java SDK's `BoundaryClient` also checks, when it is built, that its own root and keyring verify under its own
policy key, since a partner could not attest either; that the partner's URL is a scheme and an authority with no
path; and, per call, that the path will be sent exactly as given and cannot change the host. A call refused for
that is refused before any I/O. A `403 SESSION_UNKNOWN` clears the session, so the next call opens a new one; the
refused call is not retried, since it may have changed something. A `403 POLICY_EXPIRED` clears it too: the
partner gives that to every call in an attested session once the client's root or keyring has passed its
`notAfter`, so the next call's handshake gives an unsafe session, and the client logs its own expiry once. Because
a refused call is not retried, a session the partner has expired would fail the next call, so the client also
drops a session no call has used for its own idle period (10 minutes in the Java SDK), and the next call opens a
new one. That period SHOULD be below the partner's.

**The partner.** The partner MUST pin the sender's policy key in advance, out of band, as partner onboarding.
It pins the key, not a root, so the sender can rotate roots and keyrings without being pinned again. In the
handshake the sender is the client: it sends its signed root, policy key, keyring and keyring signature, and the
partner attests the session only if the policy key is one it pinned. **An unpinned key gives an unsafe
session**, not a refusal: the partner serves what it allows to unattested callers and disables the rest.

The partner verifies the boundary chain in the live order against the sender's root and keyring from the
session, with the egress service as an allowed origin, `receiver` = its own entry service and
`receiverInRoute = true`, and the authenticated peer. It then applies [the owner-aware rule](#the-owner-aware-rule)
to the carried influence, taking the destination owner from its own records.

The partner signs its handshake replies in either form ([above](#the-reply)). The Java SDK's partner sends the
entry-key form: it holds its entry service's key and a current reply certificate for it, and its policy key stays
offline. It checks at startup that its keyring verifies under its own pin and holds that key, and that the
certificate names it and has not expired. It does not attest what it answers. In the Java SDK, partner mode
(`paztport.partner.enabled`) replaces the inbound filter with one that has no modes and sends no responder
events; its properties are in the [Java SDK README](../java/README.md#paztport-spring).

What the partner can still learn: the boundary proof is the same on every request over that route, so it can
count and cluster requests by route. It also sees each request's classes and owners, which the rule needs. It does
not see the sources behind them: those cross only as blinded commitments that the sender can open. The root
README's known limits cover these.

### Blinded influence

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
