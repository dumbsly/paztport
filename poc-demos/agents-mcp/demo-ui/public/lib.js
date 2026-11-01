// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Small helpers for the demo page, kept free of the DOM so they can be tested in Node.

/** The per-launch key from the address: the part after #key=. */
export function keyFromHash(hash) {
  const params = new URLSearchParams(String(hash || "").replace(/^#/, ""));
  const key = params.get("key");
  return key ? key : undefined;
}

/**
 * Reads a text/event-stream in chunks. `feed` returns the events completed by this chunk; `end` returns
 * an event left without its closing blank line when the stream ends.
 */
export function sseParser() {
  let buffer = "";
  const parseBlock = (block) => {
    let event = "message";
    const data = [];
    for (const line of block.split("\n")) {
      if (line === "" || line.startsWith(":")) continue;
      const at = line.indexOf(":");
      const field = at < 0 ? line : line.slice(0, at);
      let value = at < 0 ? "" : line.slice(at + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    return data.length > 0 ? { event, data: data.join("\n") } : undefined;
  };
  const take = (final) => {
    // a chunk can end between the \r and \n of one line break
    const held = !final && buffer.endsWith("\r") ? "\r" : "";
    buffer = (held ? buffer.slice(0, -1) : buffer).replace(/\r\n?/g, "\n");
    const out = [];
    let at;
    while ((at = buffer.indexOf("\n\n")) >= 0) {
      const e = parseBlock(buffer.slice(0, at));
      buffer = buffer.slice(at + 2);
      if (e) out.push(e);
    }
    if (final && buffer.trim() !== "") {
      const e = parseBlock(buffer);
      buffer = "";
      if (e) out.push(e);
    }
    buffer += held;
    return out;
  };
  return {
    feed: (chunk) => {
      buffer += chunk;
      return take(false);
    },
    end: () => take(true),
  };
}

/** What the page shows for a figure the folder does not record. */
export const NOT_RECORDED = "not recorded";

/** The runs an eval asked for (runs per mode times modes), or undefined when either is not recorded. */
export function plannedRuns(requested) {
  return requested && typeof requested.runs === "number" && Array.isArray(requested.modes) ? requested.runs * requested.modes.length : undefined;
}

/** A results-table cell, as summary.md prints it: k / n (lo–hi%), bounds rounded outward. */
export function formatCell(c) {
  if (!c || typeof c.k !== "number" || typeof c.n !== "number") return NOT_RECORDED;
  if (c.n === 0) return "0 / 0";
  const lo = Math.floor(c.ci[0] * 100 + 1e-9);
  const hi = Math.ceil(c.ci[1] * 100 - 1e-9);
  return `${c.k} / ${c.n} (${lo}–${hi}%)`;
}

/** "4 s", "1 min 8 s", "10 min". */
export function formatDuration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r === 0 ? `${m} min` : `${m} min ${r} s`;
}

const ENDED = new Set(["finished", "stopped"]);
const TRAIL = 3;

/**
 * The activity trail: what the run is doing now, then the two states before it. An entry keeps only the server's
 * label, never model text. An event that repeats the top entry (a reconnect replaying the latest) changes nothing;
 * a new run (starting, or another place in a series) starts a new trail. Returns the trail unchanged for anything
 * malformed.
 */
export function pushActivity(trail, a, now) {
  if (!a || typeof a.label !== "string" || typeof a.state !== "string") return trail;
  const where = typeof a.where === "string" ? a.where : undefined;
  const since = typeof a.since === "number" ? a.since : now;
  const top = trail[0];
  if (top && top.label === a.label && top.since === since && top.where === where) return trail;
  const entry = { state: a.state, label: a.label, where, since };
  if (!top || a.state === "starting" || top.where !== where) return [entry];
  return [entry, { ...top, ended: since }, ...trail.slice(1)].slice(0, TRAIL);
}

/**
 * The trail as lines of text. The top line has the place in a series and the seconds in this state (none once the
 * run has ended). The lines below are past states: no trailing ellipsis, and the time they lasted, kept as it was
 * when they ended, unless that was under a second.
 */
export function trailLines(trail, now) {
  return trail.map((e, i) => {
    if (i === 0) {
      const time = ENDED.has(e.state) ? "" : ` (${formatDuration(now - e.since)})`;
      return `${e.where !== undefined ? `${e.where} — ` : ""}${e.label}${time}`;
    }
    const lasted = typeof e.ended === "number" ? e.ended - e.since : 0;
    return `${e.label.replace(/…$/, "")}${Math.round(lasted / 1000) >= 1 ? ` (${formatDuration(lasted)})` : ""}`;
  });
}

/**
 * The trail's elements, built with the page's element helper `h`. Plain paragraphs: no live region and no role,
 * because the top line changes every second; the page's own status region announces steps and the end.
 */
export function activityView(h) {
  const lines = [h("p", { class: "activity-line" }), h("p", { class: "activity-line past" }), h("p", { class: "activity-line past" })];
  const root = h("div", { class: "activity-trail", hidden: true }, ...lines);
  const render = (trail, now) => {
    const text = trailLines(trail, now);
    lines.forEach((el, i) => {
      el.textContent = text[i] ?? "";
      el.hidden = el.textContent === "";
    });
    root.hidden = text.length === 0;
  };
  return { root, lines, render };
}

/** The classes so far in an eval, with the summary's names; other is timeout, error and no tool calls. */
export function tallyLine(t) {
  if (!t || !["leaked", "blocked", "resisted", "other"].every((k) => typeof t[k] === "number")) return "";
  return `So far: leaked ${t.leaked}, blocked ${t.blocked}, resisted ${t.resisted}, other ${t.other} (timeout, error or no tool calls).`;
}

/** The first and last few characters of a long identifier or signature. */
export function shorten(s, keep = 10) {
  const t = String(s);
  return t.length <= keep * 2 + 1 ? t : `${t.slice(0, keep)}…${t.slice(-4)}`;
}

/** The SHA-256 of some text, as hex. */
export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The newest folder for a model that knows its median run time, or undefined. */
export function newestTiming(folders, modelId) {
  const matching = (folders || []).filter(
    (f) => f && f.ok && f.model && `${f.model.provider}/${f.model.id}` === modelId && typeof f.medianRunMs === "number",
  );
  matching.sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")));
  return matching[0];
}
