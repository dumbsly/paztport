# pi-extension

A [pi](https://www.npmjs.com/package/@earendil-works/pi-coding-agent) extension that makes stock pi
a Paztport harness for MCP servers. It starts the MCP servers named in its config, registers their
tools with pi, and sends every call itself:

- **Stamps calls.** Each `tools/call` carries a signed chain: a prompt-origin stamp for the user
  prompt that started the run, then a `pi` stamp bound to this tool, call id and arguments. It also
  carries the route proof and the influence the call was made under.
- **Verifies responses.** Each response is checked against the server's signed policy. Its content
  labels (`public`, `private`, `third-party`) are added to the session's influence only if it
  verifies. A response that fails, or comes from an unattested server, counts as `local-untrusted`.
- **Lets the server decide.** The server refuses a public write once the context holds private
  content plus third-party or untrusted content (`INFLUENCE_DENIED`). The model gets that refusal as
  a tool error.

Without a config the extension does nothing.

## Run it with stock pi

From `agents/`:

```sh
npm install --ignore-scripts
npm run setup-demo          # keys and policies in agents/.demo (server/ and client/)
```

Copy `examples/paztport.config.json` somewhere outside your workspace and replace the `/path/to/...`
paths. Then start pi from a workspace **outside** `agents/.demo`. Any directory that contains the keys
is refused, so `agents/` and the repo root are out too:

```sh
cd /path/to/workspace
pi -e /path/to/paztport/agents/pi-extension --paztport-config /path/to/config.json
```

`PAZTPORT_CONFIG=/path/to/config.json` works in place of the flag. The flag wins when both are set.
Prompt the model with something like *"Fix the README typo reported in the acme/website issues"*,
then classify the run from the outcome log as the
[mock server README](../mock-github-mcp/README.md#outcome-log) describes.

## Config

```json
{
  "mode": "enforce",
  "clientDir": "/path/to/paztport/agents/.demo/client",
  "eventsLog": "/path/to/runs/events.jsonl",
  "servers": [
    { "id": "github", "command": "node", "args": ["…/main.ts", "--mode", "enforce", "…"], "attested": true },
    { "id": "docs", "command": "node", "args": ["…/docs-main.ts"], "attested": false }
  ]
}
```

- `mode`: `enforce`, `no-root` or `off` (see below).
- `clientDir`: the client keys, signed root, `proofs-pi.json` and the pinned `server-policy.pub`, as
  written by `setup-demo`. It holds no policy private key: setup-demo deletes the client's
  `policy.key` once it has signed the root, and the root is checked with the policy public key from
  `keyring.json`.
- `servers[]`: `id` (`[A-Za-z0-9_-]+`), `command`, optional `args` and `env`, and `attested`. An
  attested server also takes `pin`, the path to the server policy public key file. It defaults to
  `<clientDir>/server-policy.pub`.
- `eventsLog` (optional): a JSONL log for the demo UI. It records event types, server and tool names,
  reason codes, influence class counts, rids and call ids. It never records content, arguments,
  keys, signatures or hashes.

- `evidenceLog` (optional): an opt-in JSONL file with what a third party needs to re-verify a run
  offline, kept apart from the events log. It holds the user prompt and rid of each run; for each
  handshake request sent, the request, the raw reply and the pin it was checked against; and, on
  attested connections, each `tools/call` exactly as sent (name, arguments and `_meta`: chain, proof
  and influence) with the time it was stamped, and each raw result including its `_meta` with the
  time it was verified. It is non-secret: no private keys. It does include prompts, tool arguments
  and tool results, so it can hold private content. The model never sees it, and it is not
  workspace-guarded, so keep it outside the agent's working directory.

Relative `clientDir`, `pin`, `eventsLog` and `evidenceLog` paths resolve against the config file's directory.
`command` and `args` are used as given.

Each configured server runs as one child process per pi session. With the example config that is
two processes, the mock GitHub server and the docs server, as in the mock server README. They start
on session start and stop on shutdown. `/new`, `/resume`, `/fork` and reload restart them, each with
a new server session.

Tools are registered as `mcp__<id>__<tool>`, with `id` as an alias. That is pi's own MCP naming:
characters outside `[A-Za-z0-9_]` become `_`. A name longer than 64 characters, or one this extension
already gave a different tool, is cut and ends in `_` plus 8 hex characters of a hash of the server
id and tool name, so it is at most 64 characters and unique.

## Modes

- `enforce`: the full harness. The extension runs a `paztport/session` handshake with each attested
  server. Calls are stamped and responses verified.
- `no-root`: the handshake sends no client root, so the server opens an unsafe session. Reads work
  and writes are refused (`UNSAFE_SESSION`). This shows what an unattested harness gets.
- `off`: no handshake, no stamps and no verification. Calls are plain `tools/call` under the **same
  tool names**, so on and off runs give the model identical tools. Pair it with the server's
  `--mode off` for a baseline. The config, keys and workspace guard are still checked.

In an attested session, a tool call made before any user prompt is refused locally and nothing is
sent.

## What the model sees

- **Tools.** The model sees the tool definitions from each server's `tools/list` as the server gives
  them: name, description and input schema.
- **Results.** A result holds only the server's `text` content items, joined by newlines. Images and
  other content types are dropped, and `_meta` never reaches the model. A refusal's text is replaced
  by one written locally. For `INFLUENCE_DENIED` and `UNSAFE_SESSION` it is:

  > Paztport stopped this action. The system flagged it as unsafe, and it was not carried out.
  > Actions like it stay blocked for the rest of this session, so retrying it or trying another way
  > will not work. A stop like this is the system doing what the user wants. It is not a fault on
  > your part. End your turn now and tell the user that the system flagged actions you attempted as
  > unsafe, and that they should review the logs.

  It doesn't give the reason, because a reason would help a steered model find a way around the
  block. The code is still in `details` (see below). Other refusals are technical, such as an
  expired stamp, and don't last for the session; they come back as `Paztport refused this call:
  <CODE>`. **The wording only nudges the model.** Nothing makes the model end its turn or tell the
  user; it may retry or try something else. The refusal is the control: the refused call is not run,
  whatever the model does next. Local failures, such as an unreachable server, a malformed
  result, or no active run, come back as plain error text. A result that fails verification still
  reaches the model; it is recorded as `local-untrusted`.
- **Details.** Paztport data goes in the tool result's `details`: the server, call id, rid, verdict
  and verification codes, the response's label classes, the session state, and influence **counts
  per class**. A refusal or local failure is marked `refused: true`: the extension wrote its text and
  recorded no influence for it. Details never hold keys, signatures, chains, proofs, hashes or
  content. pi stores them with the session. pi-ai's provider converters (such as Anthropic and
  OpenAI) send only the content. A provider that forwards pi's whole context does receive
  `details`, though: pi's test faux provider and the `pi-messages` API both do.
- **Keys.** If `clientDir`, the config file or any pin resolves inside pi's working directory, the
  extension refuses to start. It registers no tools, raises an
  error, and logs `refused_start` to the events log when one is configured. The one exception is a
  config file inside the workspace: it is refused with the error alone, since its `eventsLog` can't
  be trusted. This keeps keys out of the project; it does not hide them from the model (see
  [Limits](#limits)).

## Limits

- **Trust on first use.** The server policy key is pinned from `server-policy.pub`, which setup-demo
  writes. Nothing else vouches for it. A missing or mismatched pin, or a failed handshake, leaves
  that server unsafe: reads work, writes are refused, and the reason is in `details` and the events
  log.
- **One origin per server session.** The prompt-origin stamp is minted once per run for each server
  session and reused for every call in that run. A new handshake starts a new server session, and
  the server's record of what it has served starts empty again.
- **Influence is sticky for the pi session.** Everything recorded stays, even across prompts, until
  `/new` starts an empty session. Reload keeps the messages, and `/resume`, `/fork` and `pi -c` or
  `--session` restore them, so on those session starts the influence is rebuilt from the restored
  branch: each of this extension's results counts with its label classes from `details`, or as
  `local-untrusted` when it has none (a result marked `refused` in `details`, a refusal or local
  failure, counts for nothing, and in `off` mode none of these results count), and every other MCP
  result counts as `local-untrusted`, as it did live. A summary that `/tree` left of an abandoned
  branch is in context too, so the results on that branch count the same way. `/fork` and `/clone`
  write only the current path to the new session file, so that branch is looked up in the session
  file it was forked or cloned from. That file is named in the new file's header, and it is read
  only if it is a regular file of at most 64 MiB under the same session directory. If the branch
  can't be found there either, for example because that file was deleted, the summary may hold
  anything: it counts as `private` and `local-untrusted`, so public writes are refused (except in
  `off` mode). A compaction summary needs no such step: the entries it summarises are still on the
  restored branch and are counted there. The rebuild trusts the session file, which the model can
  edit through `bash`. Steering messages sent mid-run keep the current run's rid and origin. Only a
  new user prompt starts a new run.
- **Built-in local tools are unlabelled.** In phase 1, results of `read`, `bash`, `edit`, `write` and
  other non-MCP tools are not recorded as influence, so a payload in a workspace file goes untracked.
- **Tool descriptions and server instructions are not tracked.** Descriptions and schemas from
  `tools/list` are not recorded as influence, and neither are MCP server `instructions` or
  descriptions that pi puts in the system prompt (for servers in its own `mcp.json`). Poisoning there
  goes unnoticed.
- **No subagents.** Run and influence state belong to the one pi session. Subagents are not covered.
- **Don't also list these servers in pi's `mcp.json`.** pi's built-in MCP would register the same
  `mcp__<id>__<tool>` names. Results from pi's built-in MCP tools are still recorded, as
  `local-untrusted`.
- **Other extensions run later.** Another extension's `tool_result` handler can rewrite a result after
  this extension recorded it, so the model may see content other than what was hashed.
- **The workspace guard is hygiene, not a boundary.** It keeps the keys, the config and the pins from
  being included in or edited as part of the project by accident. pi's `read` and `bash` tools accept
  absolute paths, so the model can still read these files (`pi.key` among them) or use them through
  `bash`. Phase 2 local enforcement closes this.
- **Not everything is guarded.** The events log path and the server `command`/`args` are not checked
  against the workspace. Key files inside `clientDir` that are symlinks are followed.
- **Aborts don't reach the server.** pi's abort signal is not forwarded to in-flight MCP calls. An
  aborted call runs to completion on the server.
