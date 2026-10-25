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

/** A results-table cell, as summary.md prints it: k / n (lo–hi%), bounds rounded outward. */
export function formatCell(c) {
  if (!c || typeof c.k !== "number" || typeof c.n !== "number") return "not recorded in this folder's format";
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

/**
 * The activity line under the timer: what the run is doing and how long it has been doing it, for example
 * "The model is thinking… (38 s)". A finished run has no time; anything malformed shows nothing.
 */
export function activityLine(a, now) {
  if (!a || typeof a.text !== "string") return "";
  if (a.state === "finished" || typeof a.since !== "number") return a.text;
  return `${a.text} (${formatDuration(now - a.since)})`;
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
