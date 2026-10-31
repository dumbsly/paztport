# TypeScript SDK

An npm workspace of four packages. Node 22.19 or newer runs the `.ts` sources
directly, with no build step. Nothing is published: the agents demo
([poc-demos/agents-mcp](../../poc-demos/agents-mcp/README.md)) links the packages
with `file:` paths, and they resolve their own dependencies from this workspace,
so install it first.

```bash
npm install
npm run check   # tsc, for the type-level guards that vitest does not check
npm test
```

One test reads a keyring written by the Java keygen, from `PAZTPORT_JAVA_KEYRING`
or else the Java demo's `out/keys/keyring.json`. With neither it skips; `./run test`
writes one and names it, so there it always runs.

## @paztport/core

The protocol, with no transport: base64url, Ed25519 and SHA-256 helpers,
canonical JSON, v1, v2 and v3 stamps and chains, the salted Merkle tree, signed roots
and keyrings, reply certificates, policy building, reason codes, the replay cache, prompt
binding, influence and the owner-aware influence rule, sessions, local tool rules and the
verdict for a local tool call, local steps, the live v1 verifier and the live v3 chain
verifier (`verifyChainV3`).
For responders, `signEvent` signs an event, `createEventVerifier` checks a received body (strictly, with `ts`
read by value) and `isAttributable` says whether the responder may act on it.
Offline verification of a recorded run (`verifyChainOffline`) is here too, and shares its
checks with the live verifier; the agents demo's `npm run verify` uses it.

It implements protocol v3, as the [spec](../spec/README.md) defines it:

- **v3 only, live.** The live chain verifier takes v3 stamps only; a v2 chain is `CHAIN_MISSING`. v2 is
  accepted only offline (`verifyChainOffline`, `recheckResponse`), as legacy, and a chain that mixes the two
  never verifies.
- **The receiver.** Every v3 stamp names the hop it was handed to, and the verifier checks each `rcv` against
  the next stamp and the last against `receiver`. A live call or chain stamped for a different receiver is
  `BINDING_MISMATCH`, not a route failure, so a forwarded chain no longer names its last signer.
- **The peer.** `peer` (`{ svc, inst }`) is the sender a transport authenticated. Given one, the verifier
  checks it is the last signer (`PEER_MISMATCH`, after every other check) and names it as the suspect in every
  result but `POLICY_EXPIRED`. No transport here supplies one yet: the MCP wrappers (`verifyCall`,
  `verifyMcpResponse`, `McpServerSession.checkCall`) pass no peer, because stdio has no TLS, so for MCP over
  stdio the live order ends at check 11, and the peer check is core's (`verifyChainV3`).
- **The policy's window.** A live config requires `policyNotAfter`, the earliest `notAfter` of the keyring and
  root it pins (`earliestNotAfter`); past it, or with none (old-form material), every chain is `POLICY_EXPIRED`,
  before the live order's checks. Every live verifier here is per session: the server's call check takes the client
  root's and `clientKeyringNotAfter`, and the client's response check the server root's and, in the entry-key
  form, `serverKeyringNotAfter` (`serverPolicyNotAfter`).
- **Signed keyrings.** A keyring is signed by its policy key (`signKeyring`, `verifyKeyring`), and the session
  request carries the signature as `clientKeyringSig`, with the keyring's `notAfter` as `clientKeyringNotAfter`.
  A request without the signature is legacy offline and unsafe live. One whose signature is present but
  malformed (not a string) or wrong is unsafe live, and offline is a v3 request whose signature fails, not a
  legacy one.
- **Handshakes judge the windows, live.** `sessionStatus` takes the server's own keyring window and `now`, and
  opens a session unsafe when either side's root or keyring is in the old form or past its `notAfter`, so a server
  whose own material has expired degrades to unsafe sessions. `verifySessionReply` (the client's live check)
  refuses the server's root, and in the entry-key form its keyring, when old form or expired, as `BAD_SIGNATURE`.
  `isAttestedSession` checks a recorded handshake offline at the record's time: an old-form root or keyring is
  accepted and sets no limit, and a new-form one, on either side, counts only up to its `notAfter`.
- **A record set's checks are core's.** `recordedSession` reads a recorded handshake: attested at a time, at all
  (at the earliest of its limits), the `policyNotAfter` a response in it is checked with, and legacy.
  `callInSession` limits a recorded call to its session (`OUTSIDE_SESSION`), `newRecordSet` holds a record set's
  spent keys and its response cache that never forgets, and `verifyRecordedLocalStep` checks a recorded local step
  ([the MCP profile](../spec/README.md#the-mcp-profile)) with its signers given. The agents demo's `verify` calls them.
- **The handshake's pieces are core's.** `parseSessionRequest` reads a request (a missing `clientKeyringSig` stays
  absent, a legacy request, as in the Java SDK), `sessionRequest` and `replacementRequest` write one, and
  `buildSessionReply` answers it in the entry-key form. `checkSessionReply` is the client's check of a raw reply,
  returning a `ReplyCheck` (`ATTESTED`, `UNSAFE`, `MALFORMED_REPLY`, `PIN_MISMATCH` or `BAD_SIGNATURE`). A service
  that loads its own keyring and root checks them with `checkOwnMaterial` and warns near their end with
  `expiryWarnings` (`WARN_WITHIN_MS`, `describeNotAfter`).
- **Legacy is reported.** The offline results say whether a chain was legacy, and the agents demo's `verify`
  marks each such item ([eval README](../../poc-demos/agents-mcp/eval/README.md)).

## @paztport/http

The v1 HTTP request binding (`bindHttp`): SHA-256 over method, path and body. The
Java SDK computes the same bytes for a request with no query. This SDK does not
speak v3 over HTTP, which only the Java SDK does, and does not replay
`spec/vectors/http-v3.json`.

## @paztport/mcp

MCP transport on top of core: the `tools/call` binding, the `_meta` keys
(`paztport/chain`, `paztport/proof`, `paztport/influence` and the rest), the client
side (the replace decision on a session reply, stamping a tool call, reading a tool
result's attestation) and the server side (`McpServerSession`, checking a call,
and the decision on a public write). A call names `mcp:<serverId>.<tool>` as its
receiver, and a response chain ends at the client that made the call. A server
opens an attested session only for a client policy key in its `pinnedClientKeys`.
`McpServerSession` holds no policy private key: it answers handshakes in the
[entry-key form](../spec/sessions-and-influence.md#the-reply), signed by its entry
service's key (`hops[0]`), with the `ServerPolicy`'s `keyringSig` and `replyCert`.
Its constructor refuses to start, through the exported `checkServerPolicy` (core's `checkOwnMaterial` for
the keyring and root, then this server's own checks), with a
policy that does not hold together at the session's clock, lifetime included: a
keyring or root in the old form, expired, or not signed by its policy key; a
`signingKeys[hops[0]]` that is not the entry's keyring key, or a `signingKeys[hops[1]]` that is not
the tools hop's own keyring key; a route proof for `hops[0]/hops[1]` that does not prove against the
root; or a certificate that does not verify under its policy key, names another service or key, or
has expired. Material that is current but has 42 hours (a quarter of the default lifetime) or less
left is warned about once per item (keyring, root, certificate) at construction, naming its `notAfter`,
through the constructor's `warn` argument, `console.error` by default.

## policy-tool

`@paztport/policy-tool`: two command-line tools. `paztport-keygen` writes a
keypair per service, a policy keypair and a keyring signed by the policy key, valid for `--policy-days` days
(default 7). `paztport-policy` signs roots and re-signs the keyring, both in the new form and valid for
`--policy-days` days (default 7), in one of two modes:

- **Rebuild**, `--paths <yaml> --policy-key <file> --keyring <keyring.json> --out <dir> [--depth 8]`: a new tree
  from the `paths.yaml`, so a new `root.json`, `rootId` and proof bundles, which every holder must reload
  together, and the keyring re-signed. Rebuild when the routes change.
- **Renew**, `--renew --policy-key <file> --keyring <keyring.json> --out <dir>`: the `root.json` in `--out` and
  the keyring signed again with a new `notAfter`, keeping the root's `root` and `rootId`, so the proof bundles
  (and any `rules.json`) stay valid and are not touched, and holders can pick up the renewed files one at a time.
  The new `notAfter` is the run's time plus `--policy-days`, so a renewal can shorten a longer existing window.
  It takes no `--paths` or `--depth`. Renewal is the routine operation, run well before `notAfter`; old-form
  and expired files are renewed into the new form all the same.

Either mode first checks that the keyring verifies under the policy key it names, in either form and expired or
not, and that that key is the `--policy-key`; renewing also checks the root verifies under it. Any failure is
refused, exit 2, with nothing written. A rebuild vouches that the routes in the `paths.yaml` are the ones
allowed now; a renewal, that the existing tree's routes all still are, since narrowing a policy is a rebuild.
Re-signing the keyring vouches that each listed key is still its service's current key: the tool can check only
that this policy key signed the keyring before, so retiring a key, which needs a new keyring rather than a
renewed one, is the policy owner's to ensure. With `--reply-cert-svc <name> [--reply-cert-days 7]` either mode
also writes `reply-cert.json`, a [reply certificate](../spec/wire.md#the-reply-certificate) for that service's
key, its lifetime set apart from the policy's, refusing a service the keyring has no key for. A `paths.yaml` with a
`local:` block (folder rules, bound into the root as one more route and written to `rules.json`) needs
`--client-chain <svc,svc,...>`, the client's origin service and then its hops, which the rules route is pinned under;
there is no default, and a rebuild without it is refused. `paztport-policy`
prints only file names, their `notAfter` and the certificate's service.
