# TypeScript SDK

An npm workspace of three packages. Node 22.19 or newer runs the `.ts` sources
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

| Package | What it holds |
| --- | --- |
| [`@paztport/core`](#paztportcore) | The protocol, with no transport. |
| [`@paztport/mcp`](#paztportmcp) | The MCP transport on top of core: the `tools/call` binding, the client side and the server side. |
| [`@paztport/policy-tool`](#policy-tool) | `paztport-keygen` and `paztport-policy`, which write the keys, keyrings, roots and proof bundles the other two read. |

A server checks a received `tools/call` with `verifyCall`. `params` is the call's params object as received, and
`keyrings`, `roots`, `sess` and `policyNotAfter` come from the server's own pinned policy material:

```ts
import { NONCE_TTL_MS, NonceCache } from "@paztport/core";
import { verifyCall } from "@paztport/mcp";

const nonces = new NonceCache(NONCE_TTL_MS);   // remembers the nonce keys spent
const config = { keyrings, roots, allowedOrigins: ["session"], sess, nonces, now: Date.now(), policyNotAfter };
const checked = verifyCall(params, { serverId: "github" }, config);
if (!checked.result.ok) throw new Error(checked.result.reason);   // a reason code, such as BINDING_MISMATCH
// checked.influence holds the call's influence entries, and only when the call verified
```

`verifyCall` derives the receiver (`mcp:github.<tool>`), the binding and the nonce key itself, and never throws.

## @paztport/core

The protocol, with no transport: base64url, Ed25519 and SHA-256 helpers, canonical JSON, v3 stamps and chains, the
salted Merkle tree, signed roots and keyrings, reply certificates, policy building, reason codes, the replay cache,
prompt binding, influence and the owner-aware influence rule, sessions, local tool rules and the verdict for a local
tool call, local steps, the live v3 chain verifier (`verifyChain`), and `keyFileText`, which trims a key file's text
of the JSON whitespace around it and nothing else. For responders, `signEvent` signs an event, `createEventVerifier`
checks a received body (strictly: the envelope and payload must be JCS bytes) and `isAttributable` says whether the
responder may act on it. Offline verification of a recorded run (`verifyChainOffline`) is here too, and shares its
checks with the live verifier; the agents demo's `npm run verify` uses it.

It implements protocol v3, as the [spec](../spec/README.md) defines it, for MCP
only. The TypeScript SDK has no HTTP binding and no delivery key (the Java and Go
SDKs have both), and it neither names nor confirms operations over HTTP, nor
reads their keys (the Java SDK does all three; the Go SDK names operations and
reads their keys, but does not confirm them). Its verifier does accept an
operation in an `rcv`.

- **v3 only.** The live and offline chain verifiers take v3 stamps only: a stamp's `v` must be 3, and a
  chain holding any other is malformed, `CHAIN_MISSING`.
- **Tokens in, tokens out.** The SDK has no JSON library: it reads every Paztport object from bytes with its
  own strict reader, and writes it as its JCS bytes ([wire.md](../spec/wire.md#json)). `writeToken` writes an
  object's token, the base64url of those bytes, and `readToken` reads one; `readWireBytes` reads wire bytes,
  `readFile` a file, and `printFile` writes the file format.
- **Readers.** The three readers throw `MalformedJson`, naming the reading `step`, for bytes they refuse. Each
  object has a reader that takes its token and refuses anything but exactly its members: `readChain`,
  `readProof`, `readInfluence`, `readAttestation`, `readLocalDecision`, `readSessionRequest`,
  `readSessionReply`, `readKeyring`, `readRoot` and `readLocalRules`, and for files `readKeyringFile`,
  `readRootFile`, `readReplyCertFile`, `readProofBundleFile` and `readLocalRulesFile`.
- **Verifiers take tokens.** The verifiers take tokens as received (`verifyChain`'s chain, proof and
  influence, `verifyResponse`'s attestation and `checkSessionReply`'s reply), so a token that does not read is
  the typed rejection of the check that reads it.
- **Canonicalising.** `canonicalize` is JCS for content Paztport only hashes, every number written as RFC 8785
  writes a binary64.
- **The receiver.** Every v3 stamp names the hop it was handed to, and the verifier checks each `rcv` against
  the next stamp and the last against `receiver`. An `rcv` is a service's name or `svc#operation` (check 4
  accepts either for a hop's next service, and takes the last `rcv` as exactly `receiver`). A live call or
  chain stamped for a different receiver is `BINDING_MISMATCH`, not a route failure, so a forwarded chain
  does not blame its last signer.
- **The peer.** `peer` (`{ svc, inst }`) is the sender a transport authenticated. Given one, the verifier
  checks it is the last signer (`PEER_MISMATCH`, after every other check) and names it as the suspect in every
  result but `POLICY_EXPIRED`. No transport in this repository supplies one: the MCP wrappers (`verifyCall`,
  `verifyMcpResponse`, `McpServerSession.checkCall`) pass no peer, because stdio has no TLS, so for MCP over
  stdio the live order ends at check 11, and the peer check is core's (`verifyChain`).
- **The replay cache.** `NonceCache` is a concrete in-memory class, and `VerifierConfig.nonces` takes that
  class rather than an interface: its `seenBefore` is synchronous and has no failure path, so a verifier in
  this SDK keeps its nonce keys in the memory of the process that runs it.
- **The policy's window.** A verifier config pins one or more keyrings (`keyrings`, each a `PinnedKeyring`)
  and roots (`roots`, each a `PinnedRoot`), each with its own `notAfter`, so a rollover can pin the old and
  the new together.
- **Live checks.** Live, only those current at `now` are used: a stamp verifies under any key the current keyrings
  give its service, and a proof against a current root with its `rootId`. A live config also requires
  `policyNotAfter`, the earlier of the latest keyring and the latest root `notAfter` (`pinnedNotAfter`); past
  it every chain is `POLICY_EXPIRED`, before the live order's checks.
- **Offline.** Offline, a keyring or root counts for a record no later than its `notAfter` (`Infinity` for
  none), and a record for which no keyring, or no root, counts is `POLICY_EXPIRED`.
- **Per-session verifiers.** Every live verifier here is per session, pinning that session's one keyring and
  root: the server's call check takes the client root's and `clientKeyringNotAfter` (`earliestNotAfter`), and
  the client's response check the server root's and, in the entry-key form, `serverKeyringNotAfter`
  (`serverPolicyNotAfter`).
- **Event verifiers.** `createEventVerifier` takes `keyrings` too, a non-empty array it copies at
  construction, and accepts a signer any of them has a key for.
- **Signed keyrings.** A keyring is signed by its policy key (`signKeyring`, `verifyKeyring`), and the session
  request carries the signature as `clientKeyringSig`, with the keyring's `notAfter` as `clientKeyringNotAfter`.
  A request without the signature, or with one that is `null`, not a string or empty, is malformed and opens no
  session (`InvalidParams`, JSON-RPC `-32602`). One whose signature is wrong is unsafe live and not attested
  offline.
- **Handshakes judge the windows, live.** `sessionStatus` takes the server's own keyring window and `now`, and
  opens a session unsafe when either side's root or keyring is past its `notAfter`, so a server whose own
  material has expired degrades to unsafe sessions. `verifySessionReply` (the client's live check) refuses the
  server's root, and in the entry-key form its keyring, when expired, as `BAD_SIGNATURE`.
- **Handshakes judged offline.** `isAttestedSession` checks a recorded handshake offline at the record's time:
  each root and keyring, on either side, counts only up to its `notAfter`.
- **A missing `notAfter`.** A root or keyring without a `notAfter` is malformed: `readRoot`, `readRootFile`
  and `readSessionRequest` refuse it, and `verifyRoot` and `verifyKeyring` never accept it.
- **Checking a record set.** `recordedSession` reads a recorded handshake: attested at a time, at all (at the
  earliest of its limits) and the `policyNotAfter` a response in it is checked with, undefined where the
  server's signatures do not verify, which check 0 refuses (`POLICY_EXPIRED`). `callInSession` limits a
  recorded call to its session (`OUTSIDE_SESSION`), `newRecordSet` holds a record set's spent keys and its
  response cache that never forgets, and `verifyRecordedLocalStep` checks a recorded local step ([the MCP
  profile](../spec/README.md#the-mcp-profile)) with its signers given. The agents demo's `verify` calls them.
- **The handshake's pieces.** `readSessionRequest` reads a request from its token, with exactly its members (a
  missing `clientKeyringSig` is refused, as in the Java SDK), `sessionRequest` and `replacementRequest` write
  one, and `buildSessionReply` answers it in the entry-key form. `readSessionReply` reads a reply from its
  token, and `checkSessionReply` is the client's check of a reply's token, returning a `ReplyCheck`
  (`ATTESTED`, `UNSAFE`, `MALFORMED_REPLY`, `PIN_MISMATCH` or `BAD_SIGNATURE`). A service that loads its own
  keyring and root checks them with `checkOwnMaterial` and warns near their end with `expiryWarnings`
  (`WARN_WITHIN_MS`, `describeNotAfter`).
- **The server's decision.** `decideServerCall` is a server's decision on a tool call once its chain has
  verified: in an attested session the influence rule decides over the client's influence and every class the
  server has served (`publicWriteDecision` is the rule for a write), and otherwise the tools disabled when
  unsafe are refused. `sanitiseVerdictReason` makes a server's refusal reason safe to show, since it reaches
  the model, `labelToEntry` turns a verified response's label into the influence entry a client records, and
  `shapedOnlyByTrusted` says whether influence holds no untrusted content.
- **Stamping names.** `mintOrigin` takes the origin name as `svc`, which the policy and its receivers' allowed
  origins must carry too. `mintOrigin` and `stampToolCall` refuse a signing name or a receiver that is not a
  route node (`requireStampableNames`), since such a stamp could never verify, and `stampLocalStep` refuses a
  signing name that is not one (the tool in its `local:<tool>` receiver is data: an unlisted tool's refusal
  verifies without a route proof); `signStamp`, the low-level builder, does not, so a test can still build a
  bad stamp.

## @paztport/mcp

MCP transport on top of core: the `tools/call` binding, the `_meta` keys (`paztport/chain`, `paztport/proof`,
`paztport/influence` and the rest, each value but `paztport/callId`'s a token), the client side and the server
side. A call names `mcp:<serverId>.<tool>` as its receiver, and a response chain ends at the client that made the
call. The handshake's params are `{request}` and its result `{reply}`, each a token: `readSessionParams` reads the
params into a request and `sessionReplyToken` takes the reply token from a result, and a refusal's verdict is a
token that `readVerdict` reads.

The client side opens a session with `openSession` (which sends the replacement request when the reply warrants
one), stamps a tool call, and reads a tool result's attestation. The server side is `McpServerSession`, and
`handleToolCall`, which a server calls for each `tools/call`: it checks the call's chain, has core decide it
(`decideServerCall`), refuses it with `refusedToolResult` in enforce or notes the verdict on the result in audit,
runs the tool and attests the result. A `null` session is a deployment with no Paztport material, so every call is
in an unsafe session. The decision on a public write is core's, so a server in another transport decides the same.

A server opens an attested session only for a client policy key in its `pinnedClientKeys`.
`McpServerSession` holds no policy private key: it answers handshakes in the
[entry-key form](../spec/sessions-and-influence.md#the-reply), signed by its entry
service's key (`hops[0]`), with the `ServerPolicy`'s `keyringSig` and `replyCert`.
Its constructor refuses to start, through the exported `checkServerPolicy` (core's `checkOwnMaterial` for the
keyring and root, then this server's own checks), with a policy that does not hold together at the session's
clock, lifetime included: no `clientOrigins`, an empty list or a blank name in it; a keyring or root whose
`notAfter` is missing or not an integer, expired, or not signed by its policy key; a `signingKeys[hops[0]]` that is
not the entry's keyring key, or a `signingKeys[hops[1]]` that is not the tools hop's own keyring key; a route proof
for `hops[0]/hops[1]` that does not prove against the root; or a certificate that does not verify under its policy
key, names another service or key, or has expired. Material that is current but has 42 hours (a quarter of the
default lifetime) or less left is warned about once per item (keyring, root, certificate) at construction, naming
its `notAfter`, through the constructor's `warn` argument, `console.error` by default.

## policy-tool

`@paztport/policy-tool`: two command-line tools. `paztport-keygen` writes a
keypair per service, a policy keypair and a keyring signed by the policy key, valid for `--policy-days` days
(default 7). `paztport-policy` signs roots and re-signs the keyring, both valid for
`--policy-days` days (default 7), in one of two modes:

- **Rebuild**, `--paths <yaml> --policy-key <file> --keyring <keyring.json> --out <dir> [--depth 8]`: a new tree
  from the `paths.yaml`, so a new `root.json`, `rootId` and proof bundles, which every holder must reload
  together, and the keyring re-signed. Rebuild when the routes change.
- **Renew**, `--renew --policy-key <file> --keyring <keyring.json> --out <dir>`: the `root.json` in `--out` and
  the keyring signed again with a new `notAfter`, keeping the root's `root` and `rootId`, so the proof bundles
  (and any `rules.json`) stay valid and are not touched, and holders can pick up the renewed files one at a time.
  The new `notAfter` is the run's time plus `--policy-days`, so a renewal can shorten a longer existing window.
  It takes no `--paths` or `--depth`. Renewal is the routine operation, run well before `notAfter`; expired
  files are renewed all the same.

Either mode first checks that the keyring has a `notAfter` and verifies under the policy key it names, expired or
not, and that that key is the `--policy-key`; renewing also checks the root verifies under it. Any failure is
refused, exit 2, with nothing written, in a message that leads with the file at fault; the checks are core's
`renewKeyring`, `renewRoot` and `issueReplyCert`. A rebuild refuses a route node that is empty, `.` or `..`, or
holds `/`, `\`, `|` or a lone surrogate (core's `requireValidNode`, also called by `buildPolicy`), naming the
`paths.yaml` and the node. A rebuild vouches that the routes in the `paths.yaml` are the ones allowed now; a
renewal, that the existing tree's routes all still are, since narrowing a policy is a rebuild.
Re-signing the keyring vouches that each listed key is still its service's current key: the tool can check only
that this policy key signed the keyring before, so retiring a key, which needs a new keyring rather than a
renewed one, is the policy owner's to ensure. With `--reply-cert-svc <name> [--reply-cert-days 7]` either mode
also writes `reply-cert.json`, a [reply certificate](../spec/wire.md#the-reply-certificate) for that service's
key, its lifetime set apart from the policy's, refusing a service the keyring has no key for. A `paths.yaml` with
a `local:` block (folder rules, bound into the root as one more route and written to `rules.json`) needs
`--client-chain <svc,svc,...>`, the client's origin service and then its hops, which the rules route is pinned
under; there is no default, and a rebuild without it is refused. `paztport-policy` prints only file names, their
`notAfter` and the certificate's service.
