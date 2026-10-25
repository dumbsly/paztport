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

## Local tool gating

The extension also checks pi's own tools: `read`, `write`, `edit`, `bash`, `grep`, `find` and `ls`.
Each call is checked in pi's `tool_call` hook against rules that are signed into the client policy,
before the tool runs. In plain words: the policy says which folders the session may read or write,
which programs `bash` may start, and which folders are public. A call outside that is refused. A
public write after the session has read private content and also taken in untrusted content is
refused too.

The rules sit in the policy file under a `local:` key, next to the `paths:` list. The route for each
tool, such as `session/pi/local:bash`, must also be listed there, or the tool is refused. This is the
policy the local-tools scenario uses (`policies/client-local-tools.paths.yaml`, the `local:` part):

```yaml
local:
  folders:
    - { path: ".", access: [read] }
    - { path: "website", access: [read, write], label: public, destination: public }
    - { path: "notes", access: [read, write], destination: private }
  programs: [cat, head, tail, wc, grep, ls, diff, pwd, echo, cut, tr, basename, dirname, test, "true", "false", mkdir, touch, cp, mv]
```

The policy tool signs the rules into the client root as one more route, and the extension refuses to
load rules the root does not cover. `clientPolicyDir` in the config (default: `clientDir`) is where
`root.json`, `proofs-pi.json` and `rules.json` are read from.

By mode: `enforce` checks every call as described here. `no-root` has no rules to check against and
refuses every local call. `off` allows everything and records nothing, and pi's own `bash` stays in
place. A local call made before any user prompt is refused.

### The order of checks

The first check that fails decides, in this order:

1. **Route.** Is `session/pi/local:<tool>` listed in the signed policy? If not, the call is refused
   (`PATH_NOT_ALLOWED`).
2. **Checkable.** Could the gate work out what the call would touch? A `bash` command it cannot parse,
   a path with a `..` part in a command, a link it cannot follow, or a tool input it cannot sign
   makes the call `UNCHECKABLE`. `powershell` is `UNCHECKABLE` when its route is listed; when it is
   not, the route check refuses it first (`PATH_NOT_ALLOWED`), as it does any unlisted tool.
3. **Scope.** Every path must fall under a folder rule that allows the access needed (read, write or
   exec), and every program must be allowed. Otherwise `SCOPE_DENIED`. A path that resolves outside
   the workspace with no rule for it, or into a place the extension keeps for itself (the config, the
   keys and pins, the logs, pi's session and agent folders), is refused.
4. **Influence.** If the session holds `private` content together with `third-party` or
   `local-untrusted` content, a write to a folder whose `destination` is `public` is refused
   (`INFLUENCE_DENIED`). This is the same rule the mock server applies to public repositories. A
   call's own reads of private-labelled folders count too: if the call reads a folder labelled
   `private`, `private` is added to the session's classes for this check, so one `bash` command that
   copies a `private` folder into a public one is decided as a read followed by a write would be. The
   call's other read labels are not added: its own reads carry data, not instructions, and the model
   has not seen that content, so it can't have steered the call. With an empty session, that copy is
   allowed, as a private read and then a public write are on the server.

In `enforce` mode, each call that reaches the gate during a run is a signed step in the client's
chain: the stamp binds the call id, the input, what the gate resolved, the verdict, whether the route
was listed, the hash of the rules, and the influence at that moment. The step is written to the
evidence file whether the call was allowed or refused. The input is bound and recorded with the
workspace path written as `<workspace>` and the home folder as `<home>`, in keys and values alike.
Both the spelling pi was given and the real path behind any symlinks are recognised. A path is
replaced only when it appears whole: after the start of a string, a space, a quote, a bracket, `=`,
`:`, `,` or a shell operator, and followed by `/`, the end or one of those. A longer folder name
(`proj.bak`) or a path that only contains the workspace partway through is left as it is. The
recorded input is an encoding, not a command to run: a `<` that was already in the input is written
`<<`, so a single `<` always opens a placeholder and the original input can be read back exactly. A
case-changed spelling of the workspace is not recognised and stays as written. The tool runs with the
input as given. In eval and demo runs, `<home>` is the run's own home folder, which the runner gives
pi, not yours. A call
whose input can't be signed (a lone surrogate, a number JSON can't hold) is refused as `UNCHECKABLE`
and is not signed. In `no-root` mode, and for a call made before any user prompt, the call is refused
with an event only: nothing is signed. The events log gets only the tool name, call id, rid and
verdict. After a call is allowed, its input is frozen (see [Hook order](#hook-order)).

### Folder rules

A folder rule has a `path`, an `access` list, and optionally a `label` and a `destination`.

- `path`: relative to the working folder (`.` is the folder itself) or absolute. It must not leave
  the working folder with `..`. A rule covers everything below it. The longest matching rule wins,
  so `website` beats `.` whatever the order. Paths are resolved to where they really are on disk, so
  a symlink inside the workspace is judged by what it points at.
- `access`: any of `read`, `write`, `exec`. `write` and `exec` cannot be combined in one rule (see
  [Write or run, not both](#write-or-run-not-both)).
- `label`: what a read from this folder adds to the session's influence: `private`, `public` or
  `third-party`. A folder with no label counts as `local-untrusted`, and so does a read outside any
  rule's label. The label is the policy author's claim about the folder; the extension does not look
  at the content.
- `destination`: `public` or `private`. Required when `access` includes `write`. Only a write to a
  `public` destination can be refused for influence.

### Programs

`programs` lists the bare program names `bash` may start (no `/`, no spaces). A name is looked up on
the fixed `PATH` (`/usr/bin:/bin`) and must be listed and found there. If an allowed name is really
a link to a program from the list below, it is treated as that program. A program given with a path,
such as `./tool`, is judged as `exec` access on its folder instead.

Some programs are never allowed, even if listed. Each can start other programs, write anywhere or
reach the network, so a command line that names one cannot be checked. Listing one in a policy makes
the policy fail to load. Names are compared without regard to case, and with a version suffix
(`python3.12` is `python`). The list:

`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `env`, `xargs`, `sudo`, `su`, `doas`, `nohup`, `timeout`, `nice`, `watch`, `exec`, `eval`, `python`, `python3`, `node`, `deno`, `bun`, `perl`, `ruby`, `php`, `lua`, `awk`, `gawk`, `sed`, `find`, `git`, `make`, `npm`, `npx`, `pip`, `pip3`, `osascript`, `open`, `xdg-open`, `tee`, `sort`, `uniq`, `script`, `arch`, `caffeinate`, `busybox`, `tar`, `zip`, `unzip`, `rsync`, `ssh`, `scp`, `sftp`, `less`, `more`, `man`, `vi`, `vim`, `nvim`, `view`, `emacs`, `nano`, `ed`, `ex`, `m4`, `chroot`, `setsid`, `stdbuf`, `flock`, `rbash`, `ash`, `csh`, `tcsh`, `nodejs`, `mawk`, `nawk`, `xcrun`, `launchctl`, `at`, `batch`, `crontab`, `screen`, `tmux`, `expect`, `gdb`, `lldb`, `dtrace`, `sandbox-exec`, `irb`, `julia`, `swift`, `tclsh`, `wish`, `Rscript`, `printf`, `getopts`, `time`, `command`, `lockf`, `pydoc`, `vimdiff`, `rview`, `rvim`, `vimtutor`

Beyond the list, the check reads a small part of the shell. It accepts simple commands joined by
`|`, `&&`, `||`, `;` or a new line, with plain words, single and double quotes and `>`, `>>`, `2>`
and `<` redirects. It refuses anything it would have to guess: `$` and backquote expansions, globs
(`*`, `?`, `[`), `~`, subshells and braces, background jobs, here-documents, variable assignments,
and shell builtins that change state (`cd`, `export`, `source`, `set` and the like). A command list
in which a command other than the last one writes is refused whole, because an earlier write can
change what a later path means.

For the read-only programs (`cat`, `head`, `tail`, `wc`, `grep`, `ls`, `diff`, `pwd`, `echo`, `cut`,
`tr`, `basename`, `dirname`, `test`, `true`, `false`) an operand counts as a path when it contains a
`/`, starts with `.` or `~`, or names something in the working folder. For any other allowed
program, every operand counts as a path it may write. The working folder is always counted as a read.

### Write or run, not both

A folder rule cannot allow both `write` and `exec`. The reason is simple: if the session could write
a file into a folder and then run it from there, the program list would not mean much, because the
new file would be a program the policy never saw. With the two kept apart, a folder holds files the
session can change or programs it can run, not both.

### Paztport's own `bash`

In every mode but `off`, the extension registers its own `bash` tool in place of pi's. It has the same
name, schema and output handling, but it differs in how it starts commands:

- It runs the command with `/bin/sh`, so the shell is the one the check assumed.
- `PATH` is `/usr/bin:/bin`, so programs resolve to the ones the gate looked up.
- The environment is built from an allowlist: `PATH`, `HOME`, `TERM=dumb`, and `LANG`, `LC_ALL` and
  `TZ` if set. `HOME` is the workspace. Nothing else from the parent environment (API keys,
  `BASH_ENV`, `IFS`, `CDPATH` and so on) is passed.
- pi's `shellPath` and `commandPrefix` settings do not apply to it.

### What the model sees from the local gate

A refused local call comes back as a tool error with one of three fixed texts. None says which rule
applied.

For `INFLUENCE_DENIED`, the same text as for the server's refusals above:

> Paztport stopped this action. The system flagged it as unsafe, and it was not carried out. Actions like it stay blocked for the rest of this session, so retrying it or trying another way will not work. A stop like this is the system doing what the user wants. It is not a fault on your part. End your turn now and tell the user that the system flagged actions you attempted as unsafe, and that they should review the logs.

For `SCOPE_DENIED` and `PATH_NOT_ALLOWED`. Scope is not evidence of an injection, so this text does not ask the model to stop:

> Paztport refused this action: it is outside what this session is allowed to do, so it was not carried out.

For `UNCHECKABLE`:

> Paztport couldn't check this command, so it wasn't run. Use simple commands with plain paths.

As with the other refusal text, the wording only nudges the model. The refusal is the control.

### Hook order

pi runs `tool_call` handlers in the order the extensions loaded, and a handler can change the tool's
input in place. Paztport checks the input as it is when its handler runs, then freezes it. So
Paztport must be the last `tool_call` handler, or the only one that changes tool input. If another
extension's handler runs after Paztport and changes the input, the change throws and pi blocks the
call. A handler that runs before Paztport can change the input, but Paztport then checks what it
changed it to, which is what the tool runs with.

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
  restored branch and are counted there. The rebuild trusts the session file. With the local gate
  on, pi's session folder and file are refused to the gated tools, so the model can't edit the file
  through them; in `off` mode, or through a tool the gate does not cover (another extension's), it
  can. Steering messages sent mid-run keep the current run's rid and origin. Only a
  new user prompt starts a new run.
- **Influence from local reads.** A read adds the label of the folder it read from, as the policy
  gives it. A folder with no label, or a read the rules do not place in a folder, counts as
  `local-untrusted`. A `bash` result adds the labels of the folders it read plus `local-untrusted`,
  because a program's output is not fully known. `write` and `edit` results add nothing. A tool that
  is not one of pi's built-ins and not this extension's counts as `local-untrusted`. The labels are
  only as good as the policy's claims about the folders. When a session is restored (`/resume`,
  `/fork`, reload), results of built-in tools are counted again from the labels saved with them. A
  result without Paztport's labels, or one whose tool made nested calls (whatever the tool is
  called), counts as `private` and `local-untrusted`. A restored `write` or `edit` result, and an
  error result holding one of the local refusal texts, count for nothing, as they did live.
- **Tool descriptions and server instructions are not tracked.** Descriptions and schemas from
  `tools/list` are not recorded as influence, and neither are MCP server `instructions` or
  descriptions that pi puts in the system prompt (for servers in its own `mcp.json`). Poisoning there
  goes unnoticed.
- **The `bash` check is conservative, not a guarantee.** It refuses what it cannot work out, but it
  works from the command text and the files as they are when it looks. It does not run the command or
  model what each program does.
- **Allowed programs can have effects the check does not model.** The check knows which paths a
  program is given, not everything the program does with them. Take `cp`, `mv` and `touch` in the
  example policy: the check treats their operands as paths to be written and judges those, and that
  is all it knows about them.
- **Programs whose write target comes from their operands' contents are not modelled.** Do not list
  `curl -O`, `wget`, archive extractors in the style of `tar` and `unzip`, or `ln` in a policy. `curl -O`
  and `wget` write a file named by a URL, an extractor writes the names inside the archive, and `ln`
  with one operand writes `./` plus that operand's base name. The check cannot see those targets.
- **A file can change between the check and the run.** The gate checks, then the tool runs a moment
  later (a check-then-use gap). A link swapped in, or a file replaced by another process in between,
  is not seen.
- **Walking a folder is refused when the folder is odd.** A `bash` command that walks a folder (`ls`,
  `grep`, and any program not on the read-only list, including one given by path, is treated as able to walk the working folder) is refused as
  uncheckable when the folder holds a symlink that points out of it, a folder that cannot be read, or
  more than 20,000 entries. It does not detect hard links and mount points below a walked folder.
- **The `bash` environment is fixed, and it is the workspace's.** Paztport's own `bash` runs
  `/bin/sh` with `PATH=/usr/bin:/bin`, `HOME` set to the workspace and an allowlisted environment.
  pi's `shellPath` and `commandPrefix` settings do not apply. Because `HOME` is the workspace, a
  program the policy allows may read configuration or rc files that are in the workspace. An
  extension loaded before Paztport that registers its own `bash` replaces Paztport's: the gate still
  checks the call, but the fixed shell and environment do not apply.
- **Paztport must be the last `tool_call` handler, or the only one that changes tool input.** After a
  call is allowed its input is frozen, so a later extension that changes it gets the call blocked,
  and a third-party tool that changes its own arguments will fail.
- **`verify` checks the rules against what the gate saw, not the disk.** Offline verification checks
  that the signed rules give the recorded verdict for the recorded resolution. It does not check that
  the gate resolved the paths correctly, and it cannot see the disk as it was.
- **No subagents.** Run and influence state belong to the one pi session. Subagents are not covered.
- **Don't also list these servers in pi's `mcp.json`.** pi's built-in MCP would register the same
  `mcp__<id>__<tool>` names. Results from pi's built-in MCP tools are still recorded, as
  `local-untrusted`.
- **Other extensions run later.** Another extension's `tool_result` handler can rewrite a result after
  this extension recorded it, so the model may see content other than what was hashed.
- **The workspace guard is hygiene, not a boundary.** It keeps the keys, the config and the pins from
  being included in or edited as part of the project by accident. In `off` mode, and for tools the
  local gate does not cover (for example another extension's), nothing stops a tool that takes
  absolute paths from reading them. With the local gate on, calls to pi's built-in tools that name
  these places are refused, subject to the limits below.
- **Not everything is guarded.** The events log path and the server `command`/`args` are not checked
  against the workspace. Key files inside `clientDir` that are symlinks are followed.
- **Aborts don't reach the server.** pi's abort signal is not forwarded to in-flight MCP calls. An
  aborted call runs to completion on the server.
