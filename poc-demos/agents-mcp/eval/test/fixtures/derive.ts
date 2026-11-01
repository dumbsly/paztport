// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds the two fixture sets from one results folder of `npm run eval -- --modes on,off`, a Paztport-on run that the
// server blocked and a Paztport-off run. Run it from poc-demos/agents-mcp/:
//
//   node eval/test/fixtures/derive.ts <results folder> <on run, e.g. on-001> <off run, e.g. off-002>
//
// eval-results/ holds the on run as on-001, a copy of it with the repo in one signed call changed so that the call no
// longer matches its binding (on-002, the check must fail it), a copy cut down to its run record (on-003), the off
// run's outcome log (off-001) and the results.json that lists them: the eval's own entries for the two real runs and
// entries for the copies derived from the on run's. recorded-on-run/ (demo-ui) holds the on run with the
// transcript's thinking and answer text deltas dropped; nothing depends on them and they are most of its size, and
// the `*_start` events give the same activity. Every evidence record is written in the evidence format, each
// Paztport object as its token (tokenForm); a record already in that form is copied as it is. Nothing else is edited.
//
// The script writes only those files. The expected reports and stdout files beside them are left as they are, and
// are rebuilt from `npm run verify` after the files above change, in each fixture set:
//   - expected-folder-report.json, expected-file-report.json (eval-results) and expected-verify-report.json
//     (recorded-on-run) are `JSON.stringify(report, null, 2) + "\n"`, as the tests build them, for the report of
//     verifyResultsDir (the folder) or verifyEvidence (an evidence.jsonl), the fixture's path replaced by `<fixture>`;
//   - expected-folder-stdout.txt and expected-file-stdout.txt are what `npm run verify -- <folder>` and
//     `npm run verify -- <folder>/runs/on-001/evidence.jsonl` print, the fixture's path replaced by `<fixture>`.

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { writeToken, type JsonValue } from "@paztport/core";

type Rec = Record<string, any>;

/** The tokens of the `_meta` members `names`, the other members as they are. */
const metaTokens = (meta: Rec, names: string[]): Rec =>
  Object.fromEntries(Object.entries(meta).map(([k, v]) => [k, names.includes(k) ? writeToken(v as JsonValue) : v]));

/**
 * Whether a record's Paztport fields, `fields` by name, are tokens: true when every one is a string, false when none
 * is. A record with some of each is neither form, and throws, naming the record's type and a field that is no token.
 */
function inTokenForm(type: string, fields: [name: string, value: unknown][]): boolean {
  const values = fields.filter(([, v]) => typeof v !== "string");
  if (values.length === 0) return true;
  if (values.length === fields.length) return false;
  throw new Error(`a ${type} record whose ${values[0]![0]} is not a token, beside fields that are`);
}

/** The fields of `o` among `names` that it has and that are not null. */
const present = (o: Rec, names: string[]): [string, unknown][] =>
  names.filter((k) => Object.hasOwn(o, k) && o[k] !== null).map((k) => [k, o[k]]);

const CALL_TOKENS = ["paztport/chain", "paztport/proof", "paztport/influence"];
const RESULT_TOKENS = ["paztport/attestation", "paztport/verdict"];

/**
 * A record in the evidence format, each Paztport object it holds written as its token, the token of exactly the
 * object the record holds. The signed bytes are unchanged: a stamp signs the join of its fields, a session reply the
 * JCS of itself less `sig`, a local step the JCS of its input and decision, and a keyring its window, policy key and
 * services. A record already in the token form, and a run record, come back as they are. A record partly in each
 * form, or of a type the format does not have, throws.
 */
function tokenForm(r: Rec): Rec {
  switch (r.type) {
    case "run":
      return r;
    case "session":
      if (inTokenForm("session", present(r, ["request", "reply"]))) return r;
      return { ...r, request: writeToken(r.request), reply: r.reply === null ? null : writeToken(r.reply) };
    case "call": {
      const meta = r.params._meta;
      if (inTokenForm("call", present(meta, CALL_TOKENS))) return r;
      return { ...r, params: { ...r.params, _meta: metaTokens(meta, CALL_TOKENS) } };
    }
    case "response": {
      const meta = r.result?._meta ?? {};
      const fields = present(meta, RESULT_TOKENS);
      if (fields.length === 0 || inTokenForm("response", fields)) return r;
      return { ...r, result: { ...r.result, _meta: metaTokens(meta, RESULT_TOKENS) } };
    }
    case "client": {
      if (inTokenForm("client", present(r, ["keyring", "root", "signedRoot", "rules", "rulesProof"]))) return r;
      const ring = { notAfter: r.keyringNotAfter, policy: r.policyPublicKey, services: r.keyring, sig: r.keyringSig };
      return {
        v: r.v,
        type: r.type,
        keyring: writeToken(ring),
        root: writeToken(r.signedRoot),
        rules: r.rules === null ? null : writeToken(r.rules),
        rulesProof: r.rulesProof === null ? null : writeToken(r.rulesProof),
      };
    }
    case "local": {
      if (inTokenForm("local", present(r, ["decision", "chain", "proof", "influence"]))) return r;
      const { callId, resolved, verdict, routeAllowed, rulesHash } = r;
      return {
        v: r.v,
        type: r.type,
        tool: r.tool,
        callId,
        rid: r.rid,
        now: r.now,
        input: r.input,
        decision: writeToken({ callId, resolved, verdict, routeAllowed, rulesHash }),
        chain: writeToken(r.chain),
        proof: r.proof === null ? null : writeToken(r.proof),
        influence: writeToken(r.influence),
      };
    }
  }
  throw new Error("a record of a type the evidence format does not have");
}

/** An evidence line in the token form: the line itself when its record is in that form already. */
function tokenLine(line: string): string {
  const rec = JSON.parse(line);
  const out = tokenForm(rec);
  return out === rec ? line : JSON.stringify(out);
}

const [folder, onName, offName] = process.argv.slice(2);
if (folder === undefined || onName === undefined || offName === undefined) {
  console.error("usage: node eval/test/fixtures/derive.ts <results folder> <on run> <off run>");
  process.exit(2);
}
const onDir = join(folder, "runs", onName);
const offDir = join(folder, "runs", offName);
const evalResults = JSON.parse(readFileSync(join(folder, "results.json"), "utf8"));
const here = import.meta.dirname;
const lines = (file: string): string[] => readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");

// eval-results
const results = join(here, "eval-results");
rmSync(join(results, "runs"), { recursive: true, force: true });
const on1 = join(results, "runs/on-001");
mkdirSync(on1, { recursive: true });
for (const f of ["events.jsonl", "outcome.jsonl"]) cpSync(join(onDir, f), join(on1, f));
const evidence = lines(join(onDir, "evidence.jsonl")).map(tokenLine);
writeFileSync(join(on1, "evidence.jsonl"), evidence.join("\n") + "\n");

let tampered = false;
const changed = evidence.map((l) => {
  const rec = JSON.parse(l);
  if (!tampered && rec.type === "call" && rec.params?.arguments?.repo === "payroll-notes") {
    rec.params.arguments.repo = "website";
    tampered = true;
  }
  return JSON.stringify(rec);
});
if (!tampered) throw new Error("no call on payroll-notes in the on run's evidence");
mkdirSync(join(results, "runs/on-002"), { recursive: true });
writeFileSync(join(results, "runs/on-002/evidence.jsonl"), changed.join("\n") + "\n");

const runRecord = evidence.filter((l) => JSON.parse(l).type === "run");
if (runRecord.length !== 1) throw new Error("expected one run record in the on run's evidence");
mkdirSync(join(results, "runs/on-003"), { recursive: true });
writeFileSync(join(results, "runs/on-003/evidence.jsonl"), runRecord[0] + "\n");

mkdirSync(join(results, "runs/off-001"), { recursive: true });
cpSync(join(offDir, "outcome.jsonl"), join(results, "runs/off-001/outcome.jsonl"));

const entry = (name: string) => {
  const e = evalResults.runs.find((r: { dir: string }) => r.dir === `runs/${name}`);
  if (e === undefined) throw new Error(`results.json lists no ${name}`);
  return e;
};
const onEntry = entry(onName);
const offEntry = { ...entry(offName), index: 1, dir: "runs/off-001" };
writeFileSync(
  join(results, "results.json"),
  JSON.stringify(
    {
      formatVersion: evalResults.formatVersion,
      scenario: evalResults.scenario,
      payload: evalResults.payload,
      model: evalResults.model,
      runs: [
        { ...onEntry, index: 1, dir: "runs/on-001" },
        { ...onEntry, index: 2, dir: "runs/on-002", verify: { status: "failed", problems: [] } },
        { ...onEntry, index: 3, dir: "runs/on-003", verify: { status: "not-recorded", problems: [] } },
        offEntry,
      ],
    },
    null,
    2,
  ) + "\n",
);

// demo-ui's recorded run
const rec = join(here, "../../../demo-ui/test/fixtures/recorded-on-run");
mkdirSync(rec, { recursive: true });
for (const f of ["canary.txt", "events.jsonl", "outcome.jsonl", "run.json"]) cpSync(join(onDir, f), join(rec, f));
writeFileSync(join(rec, "evidence.jsonl"), evidence.join("\n") + "\n");
const kept = lines(join(onDir, "transcript.jsonl")).filter((l) => {
  const t = JSON.parse(l).assistantMessageEvent?.type;
  return t !== "thinking_delta" && t !== "text_delta";
});
writeFileSync(join(rec, "transcript.jsonl"), kept.join("\n") + "\n");
