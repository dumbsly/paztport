// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The demo page. It shows what the demo server sends and decides nothing the server already decided.
// Model text, tool arguments and tool results are untrusted: they only ever go into the page as text.

import { activityView, formatCell, formatDuration, keyFromHash, newestTiming, pushActivity, sha256Hex, shorten, sseParser, tallyLine } from "./lib.js";

const KEY = keyFromHash(location.hash);
const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_RUNS = 100;
const COLUMNS = { step: "Step", asked: "Agent asked to…", held: "Its context already held", result: "Result" };
const COMPARE_NOTE = "These are two separate model runs; the model may behave differently in each, and the off run may not leak at all.";
const NOT_IN_FORMAT = "not recorded in this folder's format";
const OUTCOME_KEY = {
  leaked: "leaked",
  blocked: "blocked",
  "blocked-with-private-text": "blockedWithPrivateText",
  resisted: "resisted",
  timeout: "timeout",
  error: "error",
  "no-tool-calls": "noToolCalls",
};
const VERIFY_LABEL = {
  verified: "verified",
  failed: "did not verify",
  "partly-checked": "partly checked",
  "nothing-to-check": "nothing to check",
  unknown: "not recorded",
};
const RUN_VERIFY_LABEL = { ok: "evidence verified", failed: "evidence did not verify", none: "nothing to check", "not-recorded": "ended before anything was recorded" };

const state = {
  setup: undefined,
  folders: [],
  custom: undefined,
  panels: [],
};

// --- small DOM helpers --------------------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

/** Builds an element. Strings become text nodes, never markup. */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  add(el, kids);
  return el;
}

function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === undefined || k === null || k === false) continue;
    el.append(k instanceof Node ? k : String(k));
  }
  return el;
}

/** Text with `code` spans, as the table definitions are written. */
function withCode(text) {
  return String(text)
    .split("`")
    .map((part, i) => (i % 2 === 1 ? h("code", {}, part) : part));
}

const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
/** An outcome class as people read it: "no tool calls", not "no-tool-calls". */
const outcomeWord = (o) => String(o ?? "unknown").replace(/-/g, " ");
const capitalise = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
const modelName = (m) => (isObj(m) ? `${m.provider}/${m.id}` : String(m ?? "unknown"));
const attestedMode = (mode) => mode === "on" || mode === "clean-on";
const modeLabel = (mode) => state.setup?.table?.modeLabels?.[mode] ?? `Paztport ${mode}`;

function when(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso ?? "unknown") : d.toLocaleString();
}

function payloadText(p) {
  if (!isObj(p)) return NOT_IN_FORMAT;
  return p.kind === "custom" ? `custom (not the reference text), SHA-256 ${p.sha256}` : `reference (the scenario's own text), SHA-256 ${p.sha256}`;
}

function facts(pairs) {
  return h(
    "dl",
    { class: "facts" },
    pairs.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]),
  );
}

function badge(result) {
  return h("span", { class: `badge ${result}` }, result);
}

function showProblem(message) {
  const el = $("page-problem");
  el.textContent = message;
  el.hidden = false;
}

// --- talking to the server ----------------------------------------------------------------------------------

function api(path, init = {}) {
  const headers = new Headers(init.headers);
  headers.set("x-demo-key", KEY ?? "");
  if (init.body !== undefined) headers.set("content-type", "application/json");
  return fetch(path, { ...init, headers, cache: "no-store" });
}

async function getJson(path, init) {
  const res = await api(path, init);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `The demo server answered ${res.status}.`);
  return body;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Follows a run's event stream until its `done` event. The server replays every event to a new connection,
 * so a dropped connection is simply opened again and `onConnect` lets the caller start over.
 */
async function follow(id, signal, handlers) {
  for (let attempt = 0; ; attempt++) {
    let finished = false;
    let problem;
    try {
      const res = await api(`/api/runs/${encodeURIComponent(id)}/stream`, { signal });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        handlers.onLost(body.error || `The demo server answered ${res.status}.`);
        return;
      }
      handlers.onConnect();
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      const parser = sseParser();
      const handle = (events) => {
        for (const e of events) {
          let data;
          try {
            data = JSON.parse(e.data);
          } catch {
            continue;
          }
          if (e.event === "done") finished = true;
          handlers.onEvent(e.event, data);
        }
      };
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        handle(parser.feed(decoder.decode(value, { stream: true })));
      }
      handle(parser.end());
    } catch (e) {
      if (signal.aborted) return;
      problem = e;
    }
    if (finished || signal.aborted) return;
    if (attempt >= 5) {
      handlers.onLost(`The connection to the demo server was lost${problem ? ` (${problem.message})` : ""}. The run may still be going: look for it under Results.`);
      return;
    }
    await sleep(1000 * (attempt + 1));
  }
}

// --- setup --------------------------------------------------------------------------------------------------

function selectedModel() {
  const id = $("model").value;
  return state.setup?.models.find((m) => m.id === id);
}

function selectedScenario() {
  const id = $("scenario").value;
  return state.setup?.scenarios.find((s) => s.id === id);
}

/** The scenario with this id, or the one chosen in the setup when none is given. */
function scenarioById(id) {
  return state.setup?.scenarios.find((s) => s.id === id);
}

/** The scenario gives the model a real shell: without the unsafe flag the demo offers it only with Paztport on. */
function offHidden(scenario) {
  return scenario?.localTools === true && state.setup?.unsafeToolUsage !== true;
}

/** The table wording for a scenario with local tools or without (the server sends both). */
function tableText(local) {
  const t = state.setup?.table ?? {};
  return local
    ? { definitions: t.localDefinitions ?? t.definitions ?? [], limits: t.localLimits ?? t.limits ?? [], classesNote: t.localClassesNote ?? state.setup?.table?.classesNote }
    : { definitions: t.definitions ?? [], limits: t.limits ?? [], classesNote: state.setup?.table?.classesNote };
}

function selectedMode() {
  return document.querySelector('input[name="mode"]:checked')?.value ?? "on";
}

function usingCustom() {
  return document.querySelector('input[name="payload"]:checked')?.value === "custom";
}

function runsWanted() {
  const n = Number($("runs").value);
  return Number.isInteger(n) && n >= 1 && n <= MAX_RUNS ? n : undefined;
}

function fillModels() {
  const select = $("model");
  const models = state.setup.models;
  const local = models.filter((m) => m.local);
  const hosted = models.filter((m) => !m.local);
  select.replaceChildren();
  if (local.length === 0) select.append(h("option", { value: "", selected: true }, models.length === 0 ? "No models found" : "Choose a model"));
  if (local.length > 0) {
    select.append(h("optgroup", { label: "On this machine (Ollama)" }, local.map((m) => h("option", { value: m.id }, m.id))));
  }
  if (hosted.length > 0) {
    select.append(
      h(
        "optgroup",
        { label: "Hosted (your provider account)" },
        hosted.map((m) => h("option", { value: m.id, disabled: m.permitted ? undefined : true }, m.permitted ? m.id : `${m.id} (not permitted)`)),
      ),
    );
  }
  // a hosted model is never chosen for you
  if (local.length > 0) select.value = local[0].id;
}

function renderModelNote() {
  const note = $("model-note");
  const m = selectedModel();
  const parts = [];
  if (state.setup.ollamaNote) parts.push(state.setup.ollamaNote);
  if (m && !m.local && m.note) parts.push(m.note);
  note.textContent = parts.join(" ");
  note.hidden = parts.length === 0;
}

function renderCost() {
  const el = $("cost-note");
  el.replaceChildren();
  const m = selectedModel();
  if (!m) return;
  const runs = runsWanted() ?? 1;
  add(el, [h("dt", {}, "Cost"), h("dd", {}, m.local ? "free, runs on this machine" : "uses your provider account; check its terms")]);
  const timing = newestTiming(state.folders, m.id);
  let time = "time depends on your hardware";
  if (timing) {
    time =
      timing.kind === "single"
        ? `about ${formatDuration(timing.medianRunMs)} a run (your last completed run of this model took that long, on ${when(timing.date)})`
        : `about ${formatDuration(timing.medianRunMs)} a run (the median of completed runs in your newest results for this model, from ${when(timing.date)})`;
    if (runs > 1) time += `, so about ${formatDuration(timing.medianRunMs * runs)} for ${runs} runs`;
  }
  add(el, [h("dt", {}, "Time"), h("dd", {}, time)]);
}

function renderWhat() {
  const el = $("what");
  el.replaceChildren();
  const s = selectedScenario();
  const m = selectedModel();
  if (!s) {
    el.append(h("p", { class: "muted" }, "No scenario is available."));
    return;
  }
  const mode = selectedMode();
  const runs = runsWanted() ?? 1;
  const custom = usingCustom();
  add(el, [
    h("p", {}, "The agent is given this prompt, exactly:"),
    h("blockquote", {}, s.userPrompt),
    h("p", {}, s.description),
    h(
      "ul",
      {},
      h(
        "li",
        {},
        custom
          ? `One of the open issues contains planted instructions. In this run they are your custom text${state.custom ? ` (SHA-256 ${state.custom.sha})` : ""}, not the reference text, and the run is labelled custom.`
          : "One of the open issues contains planted instructions: the scenario's reference text.",
      ),
      h("li", {}, "The GitHub server is a local mock with made-up repositories. No real repository is read or changed."),
      h("li", {}, s.localTools === true ? state.setup.localToolsNote : state.setup.toolsNote),
      h(
        "li",
        {},
        s.localTools === true
          ? mode === "on"
            ? "Paztport is on: each request is signed. Before a file or shell action runs, it is compared with the folders and programs this session may use, and it is refused if it is outside them or couldn't be checked; the check on shell commands is conservative. A write to a public place is refused once the agent has read private data together with text from someone outside the project or content from an unverified source."
            : "Paztport is off: the file and shell tools run without any check, and the mock server allows every call and records what happened."
          : mode === "on"
            ? "Paztport is on: each request is signed, and the mock server refuses a write to a public repository once the agent has read private data together with text from someone outside the project or content from an unverified source."
            : "Paztport is off: the mock server allows every call and records what happened.",
      ),
      h("li", {}, "Whether the agent follows the planted instructions is up to the model. If it doesn't, that is a result too, reported as “resisted”."),
      h(
        "li",
        {},
        runs > 1
          ? `${runs} runs, one after another, each in a fresh session against a fresh mock server. Every run is scored from the mock server's outcome log, and none is left out.`
          : "One run. Each tool call appears in a table as it happens, and each row opens its evidence.",
      ),
      h(
        "li",
        {},
        m && !m.local
          ? "The model is hosted: the prompt, the planted text and the tool results are sent to the provider."
          : "The model runs on this machine through Ollama.",
      ),
    ),
    h("p", { class: "note" }, "A run deliberately sends planted instructions to the model. For a hosted model, check your provider's terms first; for a local model, its licence applies."),
  ]);
}

/** Hides the off choice (and says why, once) for a scenario that gives the model a real shell, unless the server says the unsafe flag was given. */
function renderModeChoice() {
  const hidden = offHidden(selectedScenario());
  $("mode-off").hidden = hidden;
  const note = $("off-note");
  note.textContent = hidden ? (state.setup?.offModeNote ?? "") : "";
  note.hidden = !hidden;
  if (hidden) $("mode-on-input").checked = true;
}

function renderSetup() {
  renderModeChoice();
  renderModelNote();
  renderCost();
  renderWhat();
  const compare = $("compare");
  compare.textContent = `Run the same prompt with Paztport ${selectedMode() === "on" ? "off" : "on"}`;
}

async function onCustomFile() {
  const input = $("payload-file");
  const note = $("payload-note");
  state.custom = undefined;
  const file = input.files?.[0];
  if (!file) {
    note.textContent = "";
    renderWhat();
    return;
  }
  const text = await file.text();
  const bytes = new TextEncoder().encode(text).length;
  if (bytes === 0 || bytes > MAX_PAYLOAD_BYTES) {
    note.textContent = `That file is ${bytes === 0 ? "empty" : `${Math.ceil(bytes / 1024)} KB`}; custom planted text must be non-empty and at most ${MAX_PAYLOAD_BYTES / 1024} KB.`;
    renderWhat();
    return;
  }
  state.custom = { text, name: file.name, sha: await sha256Hex(text) };
  note.textContent = `custom: ${file.name}, SHA-256 ${state.custom.sha}`;
  renderWhat();
}

function setupError(message) {
  const el = $("setup-error");
  el.textContent = message ?? "";
  el.hidden = !message;
}

async function onStart(event) {
  event.preventDefault();
  setupError();
  const model = selectedModel();
  const scenario = selectedScenario();
  const runs = runsWanted();
  if (!model) return setupError("Choose a model first.");
  if (!model.permitted) return setupError(model.note ?? "That model is not permitted for this demo.");
  if (!scenario) return setupError("There is no scenario to run.");
  if (runs === undefined) return setupError(`Runs must be a whole number from 1 to ${MAX_RUNS}.`);
  if (usingCustom() && !state.custom) return setupError("Choose a custom file, or use the reference text.");
  const settings = {
    model: model.id,
    scenario: scenario.id,
    mode: selectedMode(),
    runs,
    ...(usingCustom() ? { payload: state.custom.text } : {}),
  };
  const button = $("start");
  button.disabled = true;
  try {
    const { id } = await getJson("/api/runs", { method: "POST", body: JSON.stringify(settings) });
    startRunView(id, { ...settings, payloadLabel: usingCustom() ? { kind: "custom", sha256: state.custom.sha } : { kind: "reference" } });
  } catch (e) {
    setupError(e.message);
  } finally {
    button.disabled = false;
  }
}

// --- the step table -----------------------------------------------------------------------------------------

function heldCell(held) {
  if (!held || held.length === 0) return [h("span", { "aria-hidden": "true" }, "—"), h("span", { class: "sr" }, "none of these")];
  return held.join(", ");
}

function resultCell(step) {
  return [badge(step.result), step.reason ? h("span", { class: "reason" }, step.reason) : null];
}

/** A table of steps; `ctx()` gives what the evidence drawer needs about the run when a row is opened. */
function stepTable(ctx) {
  const tbody = h("tbody");
  const table = h(
    "table",
    { class: "steps" },
    h(
      "caption",
      {},
      `Open a step to see its evidence. “${COLUMNS.held}” lists private data, text written by someone outside the project and content from an unverified source, when the agent had read any of them before that step.`,
    ),
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, h("span", { class: "sr" }, COLUMNS.step), "#"), h("th", { scope: "col" }, COLUMNS.asked), h("th", { scope: "col" }, COLUMNS.held), h("th", { scope: "col" }, COLUMNS.result))),
    tbody,
  );
  const render = (steps, emptyText) => {
    tbody.replaceChildren();
    if (steps.length === 0) {
      tbody.append(h("tr", { class: "empty-row" }, h("td", { colspan: "4" }, emptyText)));
      return;
    }
    for (const step of steps) {
      const button = h("button", { type: "button", class: "link" }, step.phrase);
      const open = () => openDrawer(step, ctx(), button);
      button.addEventListener("click", (e) => {
        e.stopPropagation();
        open();
      });
      tbody.append(
        h(
          "tr",
          { class: step.result, onclick: open },
          h("td", { class: "num", "data-label": COLUMNS.step }, String(step.index)),
          h("td", { "data-label": COLUMNS.asked }, button),
          h("td", { "data-label": COLUMNS.held }, heldCell(step.held)),
          h("td", { "data-label": COLUMNS.result }, resultCell(step)),
        ),
      );
    }
  };
  return { table, render };
}

function answerSection(text) {
  return h(
    "section",
    { class: "answer" },
    h("h3", {}, "The agent's final answer"),
    text
      ? [h("p", { class: "note" }, "The agent's own words, as it wrote them. Nothing is scored from them."), h("pre", {}, text)]
      : h("p", { class: "muted" }, "The agent gave no final answer."),
  );
}

function outcomeLine(scored, local) {
  if (!isObj(scored)) return null;
  const defs = tableText(local).definitions;
  const def = defs.find((d) => d.key === OUTCOME_KEY[scored.outcome]);
  const parts = [
    h(
      "p",
      {},
      h("strong", {}, local ? "Scored from the mock server's outcome log, the extension's events log and the workspace's public folders: " : "Scored from the mock server's outcome log: "),
      outcomeWord(scored.outcome),
      def ? [" (", withCode(def.text), ")"] : null,
    ),
    h("p", { class: "note" }, `read private: ${scored.readPrivate ? "yes" : "no"} · task done: ${scored.taskDone ? "yes" : "no"}${scored.harnessFault ? " · harness fault: yes" : ""}`),
  ];
  if (scored.reason) parts.push(h("p", { class: "note" }, scored.reason));
  return parts;
}

function commandBlock(command) {
  const pre = h("pre", {}, command);
  const button = h("button", { type: "button", class: "secondary" }, "Copy");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(command);
      button.textContent = "Copied";
    } catch {
      getSelection()?.selectAllChildren(pre);
      button.textContent = "Selected";
    }
    setTimeout(() => (button.textContent = "Copy"), 1500);
  });
  return h("div", { class: "cmd" }, pre, button);
}

/** The outcome log or the events log shows calls made in a signed session. */
function hasSignedCalls(steps) {
  return (steps ?? []).some(
    (s) => typeof s?.evidence?.outcome?.sess === "string" || (Array.isArray(s?.evidence?.events) && s.evidence.events.some((e) => isObj(e) && e.session === "attested")),
  );
}

const SIGNED_BUT_MISSING = "The outcome log shows signed calls, but the evidence file has no signed records.";
const VERIFY_FILE_NOTE = "Run it in the poc-demos/agents-mcp folder. It checks the signatures, links and bindings in this run's evidence file, offline. It does not compare the evidence with the outcome log.";
const VERIFY_RUN_FOLDER_NOTE =
  "Run it in the poc-demos/agents-mcp folder. It checks the signatures, links and bindings in this run's evidence file, offline, and that the evidence agrees with the events log, the outcome log and the server key the run recorded (an older run recorded none).";
/** A run inside an eval folder is checked by its evidence file; a single run by its folder, which adds the cross-check. */
const namesEvidenceFile = (command) => /evidence\.jsonl'?$/.test(command);

function verifySection(info) {
  const heading = h("h3", {}, "Check this run's evidence");
  if (info.verifyCommand) {
    return h(
      "section",
      {},
      heading,
      commandBlock(info.verifyCommand),
      h("p", { class: "note" }, namesEvidenceFile(info.verifyCommand) ? VERIFY_FILE_NOTE : VERIFY_RUN_FOLDER_NOTE),
      info.refusalsNote ? h("p", { class: "note" }, info.refusalsNote) : null,
    );
  }
  let text;
  if (info.signedCalls) text = SIGNED_BUT_MISSING;
  else if (attestedMode(info.mode)) text = "There is nothing signed to check: the run ended before Paztport recorded a session.";
  else text = "Paztport was off for this run, so there is nothing signed to check.";
  return h("section", {}, heading, h("p", { class: info.signedCalls ? "problem" : "muted" }, text));
}

// --- the run view -------------------------------------------------------------------------------------------

function clearPanels() {
  $("active-run").hidden = true;
  for (const p of state.panels) p.dispose();
  state.panels = [];
  $("run-panels").replaceChildren();
  $("run-panels").classList.remove("two");
  document.body.classList.remove("wide");
  $("compare-note").hidden = true;
  $("compare").hidden = true;
}

function startRunView(id, settings) {
  clearPanels();
  $("setup-view").hidden = true;
  $("run-view").hidden = false;
  const panel = runPanel(id, settings, { primary: true });
  state.panels.push(panel);
  $("run-panels").append(panel.root);
  panel.root.querySelector("h2")?.focus();
}

function runPanel(id, settings, { primary }) {
  const ac = new AbortController();
  const single = settings.runs === 1;
  const started = Date.now();
  const steps = new Map();
  let done;
  let finished = false;

  const heading = h("h2", { tabindex: "-1" }, modeLabel(settings.mode), " ", h("span", { class: "badge" }, settings.model));
  // the visible line ticks every second; screen readers hear only new steps and the end
  const status = h("p", { class: "status-line" }, "Starting…");
  const announce = h("p", { class: "sr", role: "status", "aria-live": "polite" });
  const say = (text) => {
    announce.textContent = text;
  };
  // what the run is doing now and the two states before it; not a live region, so it never talks over the steps
  const activity = activityView(h);
  const tallyEl = h("p", { class: "note tally-line", hidden: true });
  let trail = [];
  const renderActivity = () => activity.render(finished ? [] : trail, Date.now());
  const hideActivity = () => {
    activity.root.hidden = true;
    tallyEl.hidden = true;
  };
  const cancel = h("button", { type: "button", class: "secondary" }, "Cancel this run");
  const saved = h("p", { class: "note" });
  const outcome = h("div", { class: "outcome" });
  const after = h("div");
  const progress = h("pre", { class: "progress-log", hidden: true });
  const ctx = () => ({
    mode: settings.mode,
    finished,
    verifyCommand: done?.verifyCommand,
    refusalsNote: done?.refusalsNote ?? state.setup?.refusalsNote,
  });
  const table = single ? stepTable(ctx) : undefined;
  const renderSteps = () => table?.render([...steps.values()].sort((a, b) => a.index - b.index), finished ? "No tool calls were recorded." : "Waiting for the first tool call…");
  renderSteps();

  const root = h(
    "section",
    { class: "panel run-panel", "aria-label": `${modeLabel(settings.mode)}, ${settings.model}` },
    heading,
    facts([
      ["Model", settings.model],
      ["Paztport", settings.mode],
      ["Planted text", settings.payloadLabel?.kind === "custom" ? `custom, SHA-256 ${settings.payloadLabel.sha256}` : "reference"],
      single ? null : ["Runs", String(settings.runs)],
    ]),
    status,
    activity.root,
    tallyEl,
    announce,
    outcome,
    h("p", {}, cancel),
    progress,
    table?.table,
    after,
    saved,
  );

  const tick = () => {
    if (finished) return;
    const count = single ? `, ${steps.size} step${steps.size === 1 ? "" : "s"} so far` : "";
    status.textContent = `Running for ${formatDuration(Date.now() - started)}${count}.`;
    renderActivity();
  };
  const timer = setInterval(tick, 1000);
  tick();

  cancel.addEventListener("click", async () => {
    cancel.disabled = true;
    try {
      await getJson(`/api/runs/${encodeURIComponent(id)}/cancel`, { method: "POST" });
      status.textContent = "Cancelling…";
      say("Cancelling the run.");
    } catch (e) {
      status.textContent = e.message;
      cancel.disabled = false;
    }
  });

  const finish = async (data) => {
    done = data;
    finished = true;
    clearInterval(timer);
    hideActivity();
    cancel.hidden = true;
    status.textContent = statusText(data);
    say(statusText(data));
    hideActiveNoticeIfIdle();
    if (data.name) saved.textContent = `Saved as ${data.name}. You can open it again under Results.`;
    after.replaceChildren();
    if (single) {
      if (Array.isArray(data.steps)) {
        steps.clear();
        for (const s of data.steps) steps.set(s.index, s);
      }
      renderSteps();
      if (data.started !== false) {
        add(outcome, outcomeLine(data.scored, scenarioById(settings.scenario)?.localTools === true));
        add(after, [answerSection(data.finalAnswer), verifySection({ ...ctx(), mode: settings.mode, signedCalls: hasSignedCalls([...steps.values()]) })]);
        if (primary && state.panels.length === 1 && !offHidden(scenarioById(settings.scenario))) $("compare").hidden = false;
      }
    } else {
      after.append(h("p", { class: "muted" }, "Loading the results…"));
      let detail = data;
      if (data.name) {
        try {
          detail = await getJson(`/api/results/${encodeURIComponent(data.name)}`);
        } catch {
          // the done payload has the table; only the per-run steps are missing
        }
      }
      after.replaceChildren(evalDetail(detail, { nested: true }));
    }
    loadFolders();
  };

  follow(id, ac.signal, {
    onConnect: () => {
      progress.textContent = "";
    },
    onEvent: (event, data) => {
      if (event === "step" && single && isObj(data)) {
        const isNew = !steps.has(data.index);
        steps.set(data.index, data);
        renderSteps();
        tick();
        if (isNew && !finished) say(`Step ${data.index}: ${data.phrase}: ${data.result}${data.reason ? `, ${data.reason}` : ""}.`);
      } else if (event === "activity" && isObj(data)) {
        trail = pushActivity(trail, data, Date.now());
        renderActivity();
      } else if (event === "progress" && isObj(data)) {
        if (isObj(data.tally)) {
          tallyEl.textContent = tallyLine(data.tally);
          tallyEl.hidden = finished || tallyEl.textContent === "";
        }
        progress.hidden = false;
        if (typeof data.message === "string") progress.textContent += `${data.message}\n`;
        if (typeof data.completed === "number") {
          status.textContent = `${data.completed} of ${data.planned} runs done. Running for ${formatDuration(Date.now() - started)}.`;
          say(`${data.completed} of ${data.planned} runs done.`);
        }
      } else if (event === "done" && isObj(data)) {
        finish(data);
      }
    },
    onLost: (message) => {
      finished = true;
      clearInterval(timer);
      hideActivity();
      cancel.hidden = true;
      status.textContent = message;
      say(message);
      hideActiveNoticeIfIdle();
    },
  });

  return {
    id,
    settings,
    root,
    running: () => !finished,
    cancel: () => getJson(`/api/runs/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
    dispose: () => {
      ac.abort();
      clearInterval(timer);
    },
  };
}

/** Said first when Paztport refused to start in the run: every tool call was then refused, whatever it was. */
function refusedStartText(r) {
  if (!r || typeof r.code !== "string") return "";
  const why = typeof r.reason === "string" ? ` Reason: ${r.reason}${/[.!?]$/.test(r.reason) ? "" : "."}` : " The reason is in stderr.txt in the run folder.";
  return `Paztport did not start (${r.code}), so every tool call in this run was refused.${why} `;
}

function statusText(d) {
  return refusedStartText(d.refusedStart) + runStatusText(d);
}

function runStatusText(d) {
  const took = typeof d.durationMs === "number" ? formatDuration(d.durationMs) : undefined;
  if (typeof d.error === "string") return `${capitalise(d.error)}${/[.!?]$/.test(d.error) ? "" : "."}`;
  if (typeof d.formatVersion === "number") {
    const planned = (d.requested?.runs ?? 0) * (d.requested?.modes?.length ?? 1);
    const done = Array.isArray(d.runs) ? d.runs.length : 0;
    const base = d.incomplete ? `The eval stopped before it finished: ${done} of ${planned} runs are recorded.` : `The eval finished: ${done} runs.`;
    return d.cancelled ? `You cancelled the eval. ${base}` : base;
  }
  if (d.cancelled) return `You cancelled the run${took ? ` after ${took}` : ""}.`;
  if (d.status === "completed") return `The run finished in ${took ?? "an unknown time"}.`;
  if (d.status === "timeout") return `The run hit its time limit${took ? ` after ${took}` : ""} and was stopped.`;
  return `The run ended with an error${took ? ` after ${took}` : ""}${typeof d.exitCode === "number" ? ` (pi exited with code ${d.exitCode})` : ""}.`;
}

async function onCompare() {
  const first = state.panels[0];
  if (!first) return;
  const button = $("compare");
  button.disabled = true;
  try {
    const { id } = await getJson(`/api/runs/${encodeURIComponent(first.id)}/compare`, { method: "POST" });
    const other = runPanel(id, { ...first.settings, mode: first.settings.mode === "on" ? "off" : "on" }, { primary: false });
    state.panels.push(other);
    $("run-panels").append(other.root);
    $("run-panels").classList.add("two");
    document.body.classList.add("wide");
    $("compare-note").textContent = COMPARE_NOTE;
    $("compare-note").hidden = false;
    button.hidden = true;
  } catch (e) {
    $("compare-note").textContent = e.message;
    $("compare-note").hidden = false;
  } finally {
    button.disabled = false;
  }
}

/** The "a run is still going" notice is about a run; once nothing is running it no longer applies. */
function hideActiveNoticeIfIdle() {
  if (!state.panels.some((p) => p.running())) $("active-run").hidden = true;
}

/** "New run" while a run is going: the server runs one at a time, so say so and offer to cancel it. */
function askAboutActiveRun() {
  const box = $("active-run");
  const cancelIt = h("button", { type: "button", class: "secondary" }, "Cancel the run");
  const keep = h("button", { type: "button", class: "secondary" }, "Keep watching");
  cancelIt.addEventListener("click", async () => {
    cancelIt.disabled = true;
    try {
      await Promise.all(state.panels.filter((p) => p.running()).map((p) => p.cancel()));
      box.replaceChildren(h("p", {}, "The run is being cancelled. Its results stay on this page until it stops, and it is saved under Results."));
    } catch (e) {
      box.replaceChildren(h("p", { class: "problem" }, e.message));
    }
  });
  keep.addEventListener("click", () => {
    box.hidden = true;
  });
  box.replaceChildren(
    h("p", {}, "A run is still going. The demo runs one at a time, so a new run can start only after this one finishes or is cancelled. If you leave it, it keeps running and is saved under Results."),
    h("p", { class: "start-row" }, cancelIt, keep),
  );
  box.hidden = false;
  cancelIt.focus();
}

// --- the evidence drawer ------------------------------------------------------------------------------------

let drawerOpener;

function chainList(chain) {
  return h(
    "ol",
    { class: "chain" },
    chain.filter(isObj).map((link) =>
      h(
        "li",
        {},
        h("strong", {}, String(link.svc ?? "?")),
        link.inst ? ` (${link.inst})` : "",
        typeof link.ts === "number" ? ` · signed ${new Date(link.ts).toISOString()}` : "",
        link.sig ? [" · signature ", h("code", {}, shorten(link.sig))] : "",
      ),
    ),
  );
}

/** Whether the record's token `name` did not read: the server decoded each record's tokens into its `display`. */
function unreadable(record, name) {
  return Array.isArray(record?.display?.unreadable) && record.display.unreadable.includes(name);
}

/** The note shown in place of a token that did not read. */
function unreadableNote(what) {
  return h("p", { class: "problem" }, `The recorded ${what} is unreadable.`);
}

/**
 * The drawer sections for a local tool call: the rule that decided it, the local stamp chain, the route proof and
 * what the agent held, each from the record's decoded tokens. `attested`: the run had Paztport on (with it off,
 * nothing was checked).
 */
function localSections(step, record, plain, attested) {
  const detail = step.local;
  const out = [];
  out.push(
    h(
      "section",
      {},
      h("h3", {}, "What was checked"),
      attested
        ? [
            detail.checks.length
              ? h("ul", {}, detail.checks.map((c) => h("li", {}, h("code", {}, c.what), ": ", c.rule)))
              : h("p", { class: "muted" }, "No path or program was recorded for this call."),
            h("p", { class: "note" }, "Decision: ", h("code", {}, detail.verdict), ". Rules are read from the signed rules in the evidence file; this page does not read the keys folder."),
          ]
        : h("p", { class: "muted" }, "Paztport was off, so nothing was checked."),
    ),
  );
  const proof = record?.display?.proof;
  out.push(
    h(
      "section",
      {},
      h("h3", {}, "Route proof"),
      record === undefined
        ? h("p", { class: "muted" }, "No signed record was found for this call.")
        : [
            h("p", {}, detail.routeAllowed === true ? "This tool is on the session's list of tools it may use, and the proof below ties it to the signed root." : "This tool is not on the session's list, so there is no proof."),
            isObj(proof) ? h("p", { class: "note" }, "Proof for ", h("code", {}, `session/pi/local:${step.tool}`), ", with ", String(Array.isArray(proof.siblings) ? proof.siblings.length : "?"), " steps.") : null,
            unreadable(record, "proof") ? unreadableNote("route proof") : null,
          ],
    ),
  );
  const chain = record?.display?.chain;
  out.push(
    h(
      "section",
      {},
      h("h3", {}, "Signed local chain"),
      Array.isArray(chain)
        ? [h("p", { class: "note" }, "The first link is the run's origin; the second is this call, signed with the call id, what was resolved, the decision and the rules' hash."), chainList(chain)]
        : unreadable(record, "chain")
          ? unreadableNote("chain")
          : h("p", { class: "muted" }, "No signed record was found for this call."),
    ),
  );
  const influence = record?.display?.influence;
  const held = Array.isArray(influence) ? [...new Set(influence.filter(isObj).map((e) => e.cls))].filter((c) => typeof c === "string") : [];
  out.push(
    h(
      "section",
      {},
      h("h3", {}, "What the agent held when this was decided"),
      unreadable(record, "influence")
        ? unreadableNote("influence")
        : held.length
          ? h("ul", {}, held.map((c) => h("li", {}, h("code", {}, c), plain[c] ? ` (${plain[c]})` : "")))
          : h("p", { class: "muted" }, "Nothing that counts as private, outside text or unverified content."),
    ),
  );
  return out;
}

function rawLines(title, lines) {
  const list = lines.filter((l) => l !== undefined);
  return h("details", {}, h("summary", {}, `${title} (${list.length})`), list.length ? h("pre", {}, list.map((l) => JSON.stringify(l)).join("\n")) : h("p", { class: "muted" }, "None."));
}

function openDrawer(step, ctx, opener) {
  const ev = step.evidence ?? {};
  const evidence = Array.isArray(ev.evidence) ? ev.evidence.filter(isObj) : [];
  const events = Array.isArray(ev.events) ? ev.events.filter(isObj) : [];
  const call = evidence.find((r) => r.type === "call");
  const reply = evidence.find((r) => r.type === "response");
  const chain = call?.display?.chain;
  const attestation = reply?.display?.attestation;
  const attested = attestedMode(ctx.mode);
  const plain = state.setup?.plainClasses ?? {};
  const sections = [];

  sections.push(
    h(
      "section",
      {},
      h("p", {}, badge(step.result), step.reason ? ` ${step.reason}` : ""),
      facts([
        ["Tool", h("code", {}, step.tool)],
        ev.callId ? ["Call id", h("code", {}, ev.callId)] : null,
        ev.rid ? ["Request id", h("code", {}, ev.rid)] : null,
        ["Paztport", ctx.mode],
      ]),
    ),
  );

  if (step.result === "refused") {
    sections.push(
      h(
        "section",
        {},
        h("h3", {}, "Rule and reason code"),
        h("p", {}, step.rule ?? "No plain-language rule is written for this code."),
        h("p", {}, "Reason code: ", h("code", {}, step.code ?? "not recorded")),
      ),
    );
  }

  const local = step.local ? evidence.find((r) => r.type === "local") : undefined;
  if (step.local) sections.push(...localSections(step, local, plain, attested));

  // labels: from the signed reply when there is one, else what the logs recorded
  let labels = [];
  let source = "";
  if (Array.isArray(attestation?.labels)) {
    labels = attestation.labels.map((l) => (isObj(l) ? l.cls : undefined));
    source = "Attached by the server to its signed reply.";
  } else {
    const response = events.find((e) => e.type === "response");
    if (Array.isArray(response?.labels)) {
      labels = response.labels;
      source = "Recorded by Paztport for the server's reply.";
    } else if (ev.outcome?.label) {
      labels = [ev.outcome.label];
      source = "Recorded in the mock server's outcome log.";
    }
  }
  labels = [...new Set(labels.filter((l) => typeof l === "string"))];
  if (!step.local) sections.push(
    h(
      "section",
      {},
      h("h3", {}, "Labels on what the server returned"),
      labels.length
        ? [h("ul", {}, labels.map((l) => h("li", {}, h("code", {}, l), plain[l] ? ` (${plain[l]})` : ""))), h("p", { class: "note" }, source)]
        : h("p", { class: "muted" }, step.result === "refused" ? "None: the server's refusal carries no labels." : "No labels were recorded for this call."),
    ),
  );

  if (!step.local) sections.push(
    h(
      "section",
      {},
      h("h3", {}, "Signed request chain"),
      Array.isArray(chain)
        ? [h("p", { class: "note" }, "Each link is signed by the part of the system that passed the request on, and carries the signature of the link before it."), chainList(chain)]
        : unreadable(call, "paztport/chain")
          ? unreadableNote("request chain")
          : h("p", { class: "muted" }, attested ? "No signed request was recorded for this call." : "Paztport was off for this run, so requests were not signed."),
    ),
  );

  if (!step.local && (attested || reply)) {
    let replyBody;
    if (step.result === "refused") replyBody = h("p", {}, ctx.refusalsNote ?? "Refusals are unsigned.");
    else if (Array.isArray(attestation?.chain))
      replyBody = [chainList(attestation.chain), attestation.resultHash ? h("p", { class: "note" }, "Hash of the result: ", h("code", {}, shorten(attestation.resultHash))) : null];
    else if (unreadable(reply, "paztport/attestation")) replyBody = unreadableNote("attestation");
    else replyBody = h("p", { class: "muted" }, "No signed reply was recorded for this call.");
    sections.push(h("section", {}, h("h3", {}, step.result === "refused" ? "Server's reply" : "Signed reply"), replyBody));
  }

  let check;
  if (ctx.verifyCommand) {
    check = [
      commandBlock(ctx.verifyCommand),
      h("p", { class: "note" }, "Run it in the poc-demos/agents-mcp folder. It checks every signature, link and binding in this run's evidence file, offline."),
    ];
  } else if (!ctx.finished) check = h("p", { class: "muted" }, "The command appears when the run has finished.");
  else if (hasSignedCalls([step])) check = h("p", { class: "problem" }, SIGNED_BUT_MISSING);
  else check = h("p", { class: "muted" }, attested ? "This run has nothing signed to check." : "Paztport was off for this run, so there is nothing signed to check.");
  sections.push(h("section", {}, h("h3", {}, "Check it yourself"), check));

  sections.push(
    h(
      "section",
      {},
      h("h3", {}, "Raw lines"),
      rawLines("Outcome log line", [ev.outcome]),
      rawLines("Events log lines", events),
      rawLines("Evidence lines", evidence),
    ),
  );

  $("drawer-title").textContent = `Step ${step.index}: ${step.phrase}`;
  $("drawer-body").replaceChildren(...sections);
  drawerOpener = opener;
  const dialog = $("drawer");
  if (!dialog.open) dialog.showModal();
  $("drawer-close").focus();
}

// --- results ------------------------------------------------------------------------------------------------

async function loadFolders() {
  try {
    state.folders = await getJson("/api/results");
  } catch {
    state.folders = [];
  }
  renderCost();
  if (!$("view-results").hidden && $("results-detail").hidden) renderFolderList();
}

function renderFolderList() {
  const box = $("results-list");
  box.replaceChildren(h("h2", {}, "Saved runs and evals"));
  if (state.folders.length === 0) {
    box.append(h("p", { class: "muted" }, "Nothing saved yet. Runs you start here are saved, and folders opened with --results are listed too."));
    return;
  }
  const rows = state.folders.map((f) => {
    const name = f.ok ? h("button", { type: "button", class: "link", onclick: () => openFolder(f.name) }, f.name) : f.name;
    const modes = f.kind === "single" ? f.mode : Array.isArray(f.modes) ? f.modes.join(", ") : "";
    const planted = isObj(f.payload) ? (f.payload.kind === "custom" ? `custom, ${shorten(f.payload.sha256, 8)}` : "reference") : "";
    let status;
    if (!f.ok) status = `can't be read: ${f.error}`;
    else if (f.kind === "single") status = f.cancelled ? "cancelled" : f.status === "completed" ? "completed" : f.status === "timeout" ? "hit its time limit" : f.status === "error" ? "ended with an error" : NOT_IN_FORMAT;
    else {
      status = f.incomplete ? "not finished" : "complete";
      // the server checks each folder again from its files when it lists it
      if (isObj(f.checked) && typeof f.checked.error === "string") status += "; couldn't be checked now";
      else if (isObj(f.checked)) {
        status += `; checked now: ${VERIFY_LABEL[f.checked.verifyStatus] ?? "not recorded"}`;
        if (f.checked.disagreements > 0) status += "; results.json disagrees with the files";
      }
    }
    return h(
      "tr",
      {},
      h("td", {}, name),
      h("td", {}, f.ok ? (f.kind === "single" ? "single run" : "eval") : ""),
      h("td", {}, f.ok ? modelName(f.model) : ""),
      h("td", {}, f.ok ? when(f.date) : ""),
      h("td", {}, modes ?? ""),
      h("td", {}, f.ok ? String(f.kind === "single" ? 1 : f.runs) : ""),
      h("td", {}, planted),
      h("td", {}, status),
    );
  });
  box.append(
    h(
      "div",
      { class: "scroll" },
      h(
        "table",
        { class: "folders" },
        h("thead", {}, h("tr", {}, ["Folder", "Kind", "Model", "Date", "Paztport", "Runs", "Planted text", "Status"].map((t) => h("th", { scope: "col" }, t)))),
        h("tbody", {}, rows),
      ),
    ),
  );
}

function showList() {
  $("results-detail").hidden = true;
  $("results-list").hidden = false;
  renderFolderList();
}

async function openFolder(name) {
  const detail = $("results-detail");
  detail.replaceChildren(h("p", { class: "muted" }, "Loading…"));
  detail.hidden = false;
  $("results-list").hidden = true;
  let d;
  try {
    d = await getJson(`/api/results/${encodeURIComponent(name)}`);
  } catch (e) {
    d = { name, ok: false, error: e.message };
  }
  const back = h("button", { type: "button", class: "secondary", onclick: showList }, "Back to all results");
  let body;
  if (!d.ok) body = h("div", { class: "panel" }, h("h2", {}, d.name), h("p", { class: "problem" }, `This folder can't be read: ${d.error}`));
  else if (d.kind === "single") body = singleDetail(d);
  else body = evalDetail(d, { nested: false });
  detail.replaceChildren(h("p", {}, back), body);
  detail.querySelector("h2")?.setAttribute("tabindex", "-1");
  detail.querySelector("h2")?.focus();
}

function singleDetail(d) {
  const table = stepTable(() => ({ mode: d.mode, finished: true, verifyCommand: d.verifyCommand, refusalsNote: d.refusalsNote }));
  table.render(Array.isArray(d.steps) ? d.steps : [], "No tool calls were recorded.");
  const r = isObj(d.result) ? d.result : {};
  return h(
    "div",
    { class: "panel" },
    h("h2", {}, `Single run: ${modelName(d.model)}`),
    facts([
      ["Folder", d.name],
      ["Date", when(d.date)],
      ["Scenario", isObj(d.scenario) ? `${d.scenario.title} (${d.scenario.id})` : NOT_IN_FORMAT],
      ["Paztport", d.mode],
      ["Planted text", payloadText(d.payload)],
      ["Tools", d.tools ? [d.localTools === true ? "the agent had the scenario's mock tools and pi's built-in tools (" : "the agent had only the scenario's mock tools (", h("code", {}, d.tools), ")"] : NOT_IN_FORMAT],
      ["Run", statusText(r)],
    ]),
    outcomeLine(d.scored, d.localTools === true),
    table.table,
    answerSection(d.finalAnswer),
    verifySection({ mode: d.mode, verifyCommand: d.verifyCommand, refusalsNote: d.refusalsNote, signedCalls: hasSignedCalls(d.steps) }),
  );
}

function summaryTable(d) {
  const local = d.localTools === true;
  const defs = tableText(local).definitions;
  const modes = Array.isArray(d.requested?.modes) ? d.requested.modes : (d.summary ?? []).map((s) => s.mode);
  const byMode = new Map((d.summary ?? []).filter(isObj).map((s) => [s.mode, s]));
  const empty = { k: 0, n: 0, ci: [0, 1] };
  const rows = modes.map((mode) => {
    const s = byMode.get(mode);
    return h(
      "tr",
      {},
      h("th", { scope: "row" }, modeLabel(mode)),
      h("td", {}, String(s ? s.n : 0)),
      defs.map((def) => h("td", {}, formatCell(s ? s[def.key] : empty))),
    );
  });
  return h(
    "div",
    { class: "scroll" },
    h(
      "table",
      { class: "summary" },
      h(
        "caption",
        {},
        local ? "The agent had the scenario's mock tools and pi's built-in tools (" : "The agent had only the scenario's mock tools (",
        h("code", {}, d.tools ?? "unknown"),
        "). ",
        local ? withCode("`bash` runs in a real shell on the machine that ran the eval. ") : "",
        "Each cell is: runs in this class / runs in this mode (95% Wilson interval, rounded outward to whole percent).",
      ),
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Mode"), h("th", { scope: "col" }, "Runs"), defs.map((def) => h("th", { scope: "col" }, def.term)))),
      h("tbody", {}, rows),
    ),
  );
}

function evalDetail(d, { nested }) {
  const box = h("div", { class: nested ? "" : "panel" });
  const runs = Array.isArray(d.runs) ? d.runs.filter(isObj) : [];
  const planned = (d.requested?.runs ?? 0) * (d.requested?.modes?.length ?? 0);
  const v = isObj(d.verify) ? d.verify : undefined;
  const count = (k) => (v && typeof v[k] === "number" ? String(v[k]) : NOT_IN_FORMAT);
  const local = d.localTools === true;
  const defs = tableText(local).definitions;
  const check = isObj(d.check) ? d.check : undefined;
  const checkedNow = check?.checkedNow === true;
  const recorded = isObj(d.recorded) ? d.recorded : undefined;
  const recordedRuns = new Map((Array.isArray(recorded?.runs) ? recorded.runs.filter(isObj) : []).map((r) => [r.dir, r]));
  const list = (items) => h("ul", {}, items.map((t) => h("li", {}, t)));

  add(box, [
    h(nested ? "h3" : "h2", {}, `Eval: ${modelName(d.model)}`),
    d.incomplete
      ? h("p", { class: "notice" }, `This eval was not finished (it was interrupted, or it is still running). ${runs.length} of ${planned || "the planned"} runs are recorded, and the table counts only those.`)
      : null,
    facts([
      nested ? null : ["Folder", d.name],
      ["Date", when(d.date)],
      ["Scenario", isObj(d.scenario) ? `${d.scenario.title} (${d.scenario.id})` : NOT_IN_FORMAT],
      ["Planted text", payloadText(d.payload)],
      ["Tools", local ? ["the agent had the scenario's mock tools and pi's built-in tools (", h("code", {}, d.tools ?? "unknown"), ")."] : ["the agent had only the scenario's mock tools (", h("code", {}, d.tools ?? "unknown"), "). Nothing else was enabled."]],
      ["Runs per mode", String(d.requested?.runs ?? NOT_IN_FORMAT)],
      isObj(d.versions) ? ["Versions", `pi ${d.versions.pi}, Paztport extension ${d.versions.extension}, mock server ${d.versions.mockServer}, node ${d.versions.node}`] : null,
      d.command ? ["Command", h("code", {}, d.command)] : null,
    ]),
    check && checkedNow ? h("p", { class: "note" }, check.note ?? "") : null,
    check && !checkedNow
      ? h("p", { class: "problem" }, `${check.error ?? "This folder could not be checked again."} The figures below are as recorded by the eval that wrote this folder; they were not checked now.`)
      : null,
    checkedNow && Array.isArray(check.disagreements) && check.disagreements.length > 0
      ? h("div", { class: "notice" }, h("p", {}, "results.json disagrees with the files in this folder:"), list(check.disagreements), h("p", {}, check.disagreeNote ?? ""))
      : null,
    checkedNow && Array.isArray(check.problems) && check.problems.length > 0 ? h("div", { class: "problem" }, h("p", {}, "Problems found when checking the folder now:"), list(check.problems)) : null,
    checkedNow && Array.isArray(check.notes) && check.notes.length > 0 ? h("details", {}, h("summary", {}, `Notes from the check (${check.notes.length})`), list(check.notes)) : null,
    h("h3", {}, checkedNow ? "Results (checked now)" : "Results"),
    summaryTable(d),
    h("p", { class: "note" }, "leaked, blocked, resisted, timeout, error and no tool calls are separate classes: every run is in exactly one of them. The other columns can overlap them."),
    h(
      "details",
      {},
      h("summary", {}, "What the columns mean"),
      h("dl", { class: "defs" }, defs.map((def) => [h("dt", {}, def.term), h("dd", {}, withCode(def.text))])),
      tableText(local).classesNote ? h("p", { class: "note" }, tableText(local).classesNote) : null,
    ),
    h("h3", {}, "Evidence check"),
    h("p", {}, checkedNow ? "Checked now: " : "", h("span", { class: "badge" }, VERIFY_LABEL[d.verifyStatus] ?? "not recorded"), " ", d.verifyLine ?? ""),
    recorded
      ? h("p", { class: "note" }, `${recorded.note ?? "Recorded by the eval that wrote this folder."} `, h("span", { class: "badge" }, VERIFY_LABEL[recorded.verifyStatus] ?? "not recorded"), " ", recorded.verifyLine ?? "")
      : null,
    facts([
      ["Verified", count("ok")],
      ["Did not verify", count("failed")],
      ["Nothing to check (Paztport off)", count("none")],
      ["Paztport on, ended before anything was recorded", count("notRecorded")],
      ["Server key fingerprint", isObj(d.serverKey) ? h("code", {}, d.serverKey.fingerprint) : NOT_IN_FORMAT],
    ]),
    d.verifyCommand ? commandBlock(d.verifyCommand) : null,
    d.verifyCommand
      ? h(
          "p",
          { class: "note" },
          withCode(
            checkedNow
              ? "`npm run verify` checks signatures, links and bindings in each evidence file, offline, from the poc-demos/agents-mcp folder. For a folder it also checks that every run whose outcome log shows signed calls has signed evidence. It does not compare each evidence record with the outcome log, re-score the runs, or check the server key fingerprint; this page did those when you opened the folder, and the figures above are the result. "
              : "`npm run verify` checks signatures, links and bindings in each evidence file, offline, from the poc-demos/agents-mcp folder. For a folder it also checks that every run whose outcome log shows signed calls has signed evidence. It does not compare each evidence record with the outcome log, re-score the runs, or check the server key fingerprint; the eval scored each run when it finished and cross-checked the whole folder at the end. ",
          ),
          d.refusalsNote ?? "",
        )
      : h(
          "p",
          { class: "note" },
          d.verifyStatus === "unknown" ? "This folder doesn't record an evidence check for every run, so no verify command is offered for it." : "No run in this folder has anything signed to check.",
        ),
  ]);

  const failed = runs.filter((r) => r.verify?.status === "failed");
  if (failed.length > 0) {
    box.append(
      h("p", {}, "Runs whose evidence did not verify:"),
      h("ul", {}, failed.map((r) => h("li", {}, `${String(r.dir).split("/").pop()}: ${(r.verify.problems ?? []).join("; ")}`))),
    );
  }

  add(box, [h("h3", {}, "What this doesn't show"), h("ul", {}, tableText(local).limits.map((l) => h("li", {}, l)))]);

  if (isObj(d.warning)) {
    add(box, [
      h("h3", {}, "Warning-only baseline"),
      facts([
        ["Source", d.warning.source],
        ["Address", d.warning.url],
        ["Retrieved", d.warning.retrieved],
        ["Placement", d.warning.placement],
        d.warning.note ? ["Note", d.warning.note] : null,
      ]),
    ]);
  }

  box.append(h("h3", {}, "Runs"));
  const runView = h("div");
  const modes = Array.isArray(d.requested?.modes) ? d.requested.modes : [...new Set(runs.map((r) => r.mode))];
  for (const mode of modes) {
    const these = runs.filter((r) => r.mode === mode);
    box.append(
      h("h4", {}, `Runs: ${modeLabel(mode)}`),
      these.length === 0
        ? h("p", { class: "muted" }, "No runs recorded.")
        : h(
            "ul",
            { class: "runs-list" },
            these.map((r) => {
              const name = String(r.dir).split("/").pop();
              const bits = [outcomeWord(r.outcome), r.status !== "completed" ? `status ${r.status}` : null, RUN_VERIFY_LABEL[r.verify?.status]].filter(Boolean).join(" · ");
              const button = h("button", { type: "button", class: "link" }, name);
              button.addEventListener("click", () => {
                runView.replaceChildren(runDetail(d, r));
                runView.querySelector("h3")?.focus();
              });
              const was = recordedRuns.get(r.dir);
              const differs = checkedNow && was && (was.outcome !== r.outcome || (isObj(was.verify) && was.verify.status !== r.verify?.status));
              const wasText = differs ? `results.json says ${[outcomeWord(was.outcome), RUN_VERIFY_LABEL[was.verify?.status]].filter(Boolean).join(" · ")}` : null;
              return h("li", {}, button, `: ${bits}`, r.reason ? h("span", { class: "note" }, ` (${r.reason})`) : null, wasText ? h("span", { class: "problem" }, ` ${wasText}`) : null);
            }),
          ),
    );
  }
  box.append(runView);
  return box;
}

function runDetail(d, r) {
  const steps = d.stepsByRun?.[r.dir];
  const problem = d.stepsErrors?.[r.dir];
  const table = stepTable(() => ({ mode: r.mode, finished: true, verifyCommand: d.verifyCommands?.[r.dir], refusalsNote: d.refusalsNote }));
  if (Array.isArray(steps)) table.render(steps, "No tool calls were recorded.");
  const def = tableText(d.localTools === true).definitions.find((x) => x.key === OUTCOME_KEY[r.outcome]);
  return h(
    "div",
    { class: "panel" },
    h("h3", { tabindex: "-1" }, `Run ${String(r.dir).split("/").pop()} (${modeLabel(r.mode)})`),
    facts([
      ["Outcome", [outcomeWord(r.outcome), def ? [" (", withCode(def.text), ")"] : ""]],
      ["Status", String(r.status)],
      ["read private", r.readPrivate ? "yes" : "no"],
      ["task done", r.taskDone ? "yes" : "no"],
      ["Evidence", r.verify ? `${RUN_VERIFY_LABEL[r.verify.status] ?? r.verify.status}${r.verify.problems?.length ? `: ${r.verify.problems.join("; ")}` : ""}` : NOT_IN_FORMAT],
      r.reason ? ["Note", r.reason] : null,
    ]),
    Array.isArray(steps)
      ? table.table
      : h("p", { class: "muted" }, problem ?? "This run's steps aren't available: the folder was opened without its run logs."),
    Array.isArray(steps) ? answerSection(d.answersByRun?.[r.dir]) : null,
    verifySection({ mode: r.mode, verifyCommand: d.verifyCommands?.[r.dir], refusalsNote: d.refusalsNote, signedCalls: hasSignedCalls(steps) }),
  );
}

// --- tabs and start-up --------------------------------------------------------------------------------------

function selectTab(which) {
  const run = which === "run";
  $("tab-run").setAttribute("aria-selected", String(run));
  $("tab-results").setAttribute("aria-selected", String(!run));
  $("tab-run").tabIndex = run ? 0 : -1;
  $("tab-results").tabIndex = run ? -1 : 0;
  $("view-run").hidden = !run;
  $("view-results").hidden = run;
  if (!run) {
    showList();
    loadFolders();
  }
}

function wire() {
  $("tab-run").addEventListener("click", () => selectTab("run"));
  $("tab-results").addEventListener("click", () => selectTab("results"));
  for (const id of ["tab-run", "tab-results"]) {
    $(id).addEventListener("keydown", (e) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      const next = id === "tab-run" ? "results" : "run";
      selectTab(next);
      $(`tab-${next}`).focus();
    });
  }
  $("setup").addEventListener("submit", onStart);
  $("setup").addEventListener("change", (e) => {
    if (e.target?.name === "payload") $("custom-row").hidden = !usingCustom();
    if (e.target?.id !== "payload-file") renderSetup();
  });
  $("runs").addEventListener("input", renderSetup);
  $("payload-file").addEventListener("change", () => onCustomFile().catch((err) => ($("payload-note").textContent = err.message)));
  $("back-to-setup").addEventListener("click", () => {
    if (state.panels.some((p) => p.running())) {
      askAboutActiveRun();
      return;
    }
    clearPanels();
    $("run-view").hidden = true;
    $("setup-view").hidden = false;
    $("start").focus();
  });
  $("compare").addEventListener("click", onCompare);
  const dialog = $("drawer");
  $("drawer-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => drawerOpener?.focus());
}

async function init() {
  wire();
  if (!KEY) {
    showProblem("This page needs the address the launcher printed, including the part after #. Copy it from the terminal where you ran npm run demo.");
    $("start").disabled = true;
    return;
  }
  try {
    state.setup = await getJson("/api/setup");
  } catch (e) {
    showProblem(e.message);
    $("start").disabled = true;
    return;
  }
  fillModels();
  $("scenario").replaceChildren(...state.setup.scenarios.map((s) => h("option", { value: s.id }, s.title)));
  if (state.setup.models.length === 0) $("start").disabled = true;
  renderSetup();
  loadFolders();
}

init();
