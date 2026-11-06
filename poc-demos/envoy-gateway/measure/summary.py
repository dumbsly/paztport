#!/usr/bin/env python3
# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
"""Summaries of the Envoy Gateway measurements' k6 runs (measure/k6/edge.js), for measure/common.sh.

  summary.py medians <runs file> <label>...
      The runs file holds one "<label> RESULT {json}" line a run, in the order they ran. For each label: its
      runs' count, the median of their p50, p90, p99, max and rps with the lowest and highest in brackets, and
      their statuses added up. Then, for each label after the first, what it adds to the first: the difference of
      the medians of p50 and p99, and the lowest and highest difference between the two in one round (their n-th
      runs). Refuses a run whose statuses do not sum to its requests.

  summary.py rate <runs file> <offered rate>
      For each run of an open model (k6's rate executor), whether k6 kept to the offered rate: its achieved
      requests a second within 2% of the offered, and no request dropped. A run that did not is said so plainly;
      it is not refused.

  summary.py stages <runs file> <route> <replicas> <round> <rounds file>
      The runs file holds one "<offered rate> RESULT {json}" line a stage of a ramp, each stage a run at a constant
      offered rate, in the order they ran. Prints a table of the stages: offered, achieved, p50, p99, dropped,
      statuses, and whether the stage was sustained: no request dropped, achieved within 2% of offered (the bound
      the rate check uses), and every response a 200. A stage with a request dropped is marked: k6's pool ran out,
      which with the pool the suite gives it means the system held the requests. Then the round's highest sustained
      stage, which it also adds to the rounds file as "<route> <replicas> <round> <rate>" (0 when none was). It is a
      definition, not a target: a run either kept to it or did not.

  summary.py ceiling <rounds file> <sustained file> <replicas> <route>...
      For each route, at that many replicas: each round's highest sustained stage, from the rounds file, and their
      median (the lower middle one, so it is a stage) with the lowest and highest; the median goes into the
      sustained file as "<route> <replicas> <median>". Where two routes' medians are the same, it says so: the
      ramps then carry no information about what the processor adds there.

  summary.py window <fails file>
      The responses other than the expected that a run saw: their count by status, the first and the last (UTC),
      and the span between them. When the run's .result ("<expected status> RESULT {json}") and .window
      ("WINDOW {json}") files from k6_run are beside the fails file, these come from them, and cover every response.
      Otherwise from the fails file's edge.js "FAIL {json}" lines, which list at most 20000: when the .result file
      says the run counted more than were listed, it says so first, as the window then covers only the ones listed.

  summary.py timeline <fails file> <events file>
      The run's timeline on k6's clock: the events file's "<epoch ms> <what happened>" lines, and the first and the
      last response other than the expected, in order, each at its offset from the run's start (the .window file's
      t0); then each second of the run, how many responses came back in it and how many of those were not the
      expected, a run of seconds with none of those on one line.

  summary.py seconds <fails file> <from epoch ms> <to epoch ms>
      The run's whole seconds that lie between the two times: "<first> <last> <expected> <5xx> <rest>", the first
      and the last second's offsets and the responses in them by kind (as edge.js's WINDOW counts them), or
      "none" when no whole second does.

  summary.py first <fails file> <epoch ms>
      The first second of the run, from the one that holds the time given, with an expected response in it:
      "<its offset> <the time given, as an offset from the run's start, in seconds>", or "none".

  summary.py last <fails file> <from epoch ms> <to epoch ms>
      The last second of the run that overlaps the two times and holds a response other than the expected:
      "<its offset> <its end, in epoch ms>", or "none".

  summary.py after <fails file> <epoch ms>
      The responses other than the expected in the seconds of the run from the one that holds the time given:
      "<how many> <in how many seconds>", then one line for each such second, "+<offset>: <n> (5xx <n>, other
      <n>)"; or "none".
"""
import datetime
import json
import os
import statistics
import sys


def die(message):
    sys.exit("summary.py: " + message)


def read_runs(path, labels):
    runs = {label: [] for label in labels}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            label, _, rest = line.strip().partition(" ")
            if not rest.startswith("RESULT "):
                die("%s:%d is not a '<label> RESULT {json}' line" % (path, n))
            if label not in runs:
                die("%s:%d has the label %s, which is not one of %s" % (path, n, label, " ".join(labels)))
            r = json.loads(rest[len("RESULT "):])
            total = sum(r["status"].values())
            if total != r["reqs"]:
                die("%s:%d: the statuses sum to %d, not to the %d requests" % (path, n, total, r["reqs"]))
            runs[label].append(r)
    for label in labels:
        if not runs[label]:
            die("no %s run in %s" % (label, path))
    return runs


def spread(values, unit=""):
    return "%.2f%s (%.2f-%.2f)" % (statistics.median(values), unit, min(values), max(values))


def statuses(rs):
    total = {}
    for r in rs:
        for status, n in r["status"].items():
            total[status] = total.get(status, 0) + n
    return " ".join("%s=%d" % (s, n) for s, n in sorted(total.items()) if n) or "none"


def medians(path, labels):
    runs = read_runs(path, labels)
    width = max(len(label) for label in labels)
    for label in labels:
        rs = runs[label]
        print("  %-*s  %d runs  p50 %s  p90 %s  p99 %s  max %s  rps %s  dropped %d  status %s" % (
            width, label, len(rs),
            spread([r["p50"] for r in rs], " ms"), spread([r["p90"] for r in rs], " ms"),
            spread([r["p99"] for r in rs], " ms"), spread([r["max"] for r in rs], " ms"),
            spread([r["rps"] for r in rs]), sum(r["dropped"] for r in rs), statuses(rs)))
    base = labels[0]
    for label in labels[1:]:
        parts = []
        for q in ("p50", "p99"):
            added = statistics.median(r[q] for r in runs[label]) - statistics.median(r[q] for r in runs[base])
            rounds = [b[q] - a[q] for a, b in zip(runs[base], runs[label])]
            parts.append("%s %+.2f ms (one round's: %+.2f to %+.2f)" % (q, added, min(rounds), max(rounds)))
        print("  %s adds to %s: %s" % (label, base, ", ".join(parts)))


def rate(path, offered):
    with open(path) as f:
        lines = [line.strip().partition(" ") for line in f if line.strip()]
    seen = {}
    for label, _, rest in lines:
        if not rest.startswith("RESULT "):
            die("%s holds a line that is not '<label> RESULT {json}'" % path)
        r = json.loads(rest[len("RESULT "):])
        seen[label] = seen.get(label, 0) + 1
        off = (r["rps"] - offered) / offered * 100
        kept = abs(off) <= 2 and r["dropped"] == 0
        print("  %s round %d: %.1f/s achieved of %g/s offered (%+.1f%%), %d dropped: %s" % (
            label, seen[label], r["rps"], offered, off, r["dropped"],
            "at the offered rate" if kept else "NOT at the offered rate, so this run's latency is not at that load"))


def stages(path, route, replicas, round_, out):
    rows = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            offered, _, rest = line.strip().partition(" ")
            if not rest.startswith("RESULT ") or not offered.isdigit() or int(offered) <= 0:
                die("%s:%d is not an '<offered rate> RESULT {json}' line" % (path, n))
            r = json.loads(rest[len("RESULT "):])
            total = sum(r["status"].values())
            if total != r["reqs"]:
                die("%s:%d: the statuses sum to %d, not to the %d requests" % (path, n, total, r["reqs"]))
            offered = int(offered)
            kept = (r["dropped"] == 0 and abs(r["rps"] - offered) <= 0.02 * offered and r["reqs"] > 0
                    and r["status"].get("200") == r["reqs"])
            rows.append((offered, r, kept))
    if not rows:
        die("no stage in %s" % path)
    print("  %8s  %9s  %7s  %9s  %9s  %8s  %-9s  %s" % (
        "offered", "achieved", "", "p50", "p99", "dropped", "sustained", "statuses"))
    for offered, r, kept in rows:
        print("  %6d/s  %7.1f/s  %+6.1f%%  %6.2f ms  %6.2f ms  %8d  %-9s  %s%s" % (
            offered, r["rps"], (r["rps"] - offered) / offered * 100, r["p50"], r["p99"], r["dropped"],
            "yes" if kept else "no", statuses([r]), "  (k6's pool ran out)" if r["dropped"] else ""))
    sustained = [offered for offered, _, kept in rows if kept]
    best = max(sustained) if sustained else 0
    if not best:
        print("  %s, %s processor replica(s), round %s: no stage sustained" % (route, replicas, round_))
    else:
        notes = []
        if best == max(offered for offered, _, _ in rows):
            notes.append("the highest offered, so its ceiling is at or above it")
        below = [offered for offered, _, kept in rows if not kept and offered < best]
        if below:
            notes.append("though not %s" % ", ".join("%d/s" % b for b in below))
        print("  %s, %s processor replica(s), round %s: highest sustained stage %d/s%s" % (
            route, replicas, round_, best, "".join(" (%s)" % n for n in notes)))
    with open(out, "a") as f:
        f.write("%s %s %s %d\n" % (route, replicas, round_, best))


def ceiling(rounds_path, out, replicas, routes):
    seen = {route: [] for route in routes}
    with open(rounds_path) as f:
        for n, line in enumerate(f, 1):
            parts = line.split()
            if len(parts) != 4 or not parts[3].isdigit():
                die("%s:%d is not a '<route> <replicas> <round> <rate>' line" % (rounds_path, n))
            if parts[1] == replicas and parts[0] in seen:
                seen[parts[0]].append(int(parts[3]))
    medians = {}
    for route in routes:
        rates = seen[route]
        if not rates:
            die("no round of %s at %s replica(s) in %s" % (route, replicas, rounds_path))
        medians[route] = statistics.median_low(rates)
        print("  %s, %s processor replica(s): highest sustained stage in each of %d rounds %s; median %d/s (%d-%d)"
              % (route, replicas, len(rates), " ".join("%d/s" % r for r in rates), medians[route], min(rates),
                 max(rates)))
        with open(out, "a") as f:
            f.write("%s %s %d\n" % (route, replicas, medians[route]))
    for i, a in enumerate(routes):
        for b in routes[i + 1:]:
            if medians[a] == medians[b]:
                print("  %s and %s have the same median (%d/s): at %s replica(s) the ramps carry no information about"
                      " what the processor adds" % (a, b, medians[a], replicas))


def utc(ms):
    t = datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
    return t.strftime("%H:%M:%S.") + "%03dZ" % (ms % 1000)


def read_window(path):
    """The .window file beside a fails file, as its WINDOW json, or None."""
    name = path[:-len(".fails")] + ".window" if path.endswith(".fails") else None
    if not name or not os.path.exists(name):
        return None
    with open(name) as f:
        line = f.readline().strip()
    if not line:
        return None
    if not line.startswith("WINDOW "):
        die("%s is not a 'WINDOW {json}' line" % name)
    return json.loads(line[len("WINDOW "):])


def need_window(path):
    w = read_window(path)
    if w is None or w.get("t0") is None:
        die("no WINDOW line with a t0 beside %s" % path)
    return w


def result_of(path):
    """The expected status and the RESULT json from the .result file beside a fails file, or None."""
    result = path[:-len(".fails")] + ".result" if path.endswith(".fails") else None
    if not result or not os.path.exists(result):
        return None
    with open(result) as f:
        expect, _, rest = f.readline().strip().partition(" ")
    if not rest.startswith("RESULT "):
        die("%s is not an '<expected status> RESULT {json}' line" % result)
    return expect, json.loads(rest[len("RESULT "):])


def unexpected(path):
    """The count of responses other than the expected that the run's .result file gives, or None."""
    res = result_of(path)
    if res is None or res[0] not in res[1]["status"]:
        return None
    return res[1]["reqs"] - res[1]["status"][res[0]]


def window(path):
    w, res = read_window(path), result_of(path)
    if w is not None and res is not None and res[0] in res[1]["status"]:
        expect, r = res
        by = {st: n for st, n in r["status"].items() if st != expect and n}
        total = sum(by.values())
        if not total:
            print("  0 responses other than the expected")
            return
        print("  %d responses other than the expected (%s): first %s, last %s, span %.3f s" % (
            total, ", ".join("%s: %d" % (st, n) for st, n in sorted(by.items())), utc(w["first"]), utc(w["last"]),
            (w["last"] - w["first"]) / 1000))
        return
    fails = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            if not line.startswith("FAIL "):
                die("%s:%d is not a 'FAIL {json}' line" % (path, n))
            fails.append(json.loads(line[len("FAIL "):]))
    counted = unexpected(path)
    if counted is not None and counted > len(fails):
        print("  the run counted %d responses other than the expected, and k6 listed %d of them (at most 20000,"
              " each user its share): the window below covers the listed ones only, and may end before the run's did"
              % (counted, len(fails)))
    if not fails:
        print("  0 responses other than the expected")
        return
    times = sorted(x["t"] for x in fails)
    by = {}
    for x in fails:
        by[x["status"]] = by.get(x["status"], 0) + 1
    print("  %d responses other than the expected (%s): first %s, last %s, span %.3f s" % (
        len(fails), ", ".join("%s: %d" % (s, n) for s, n in sorted(by.items())),
        utc(times[0]), utc(times[-1]), (times[-1] - times[0]) / 1000))


def counts(w):
    n = max(len(w["expected"]), len(w["5xx"]), len(w["rest"]))
    pad = lambda xs: xs + [0] * (n - len(xs))
    return list(zip(pad(w["expected"]), pad(w["5xx"]), pad(w["rest"])))


def timeline(path, events_path):
    w = need_window(path)
    t0 = w["t0"]
    items = []
    with open(events_path) as f:
        for n, line in enumerate(f, 1):
            at, _, what = line.strip().partition(" ")
            if not at.isdigit() or not what:
                die("%s:%d is not an '<epoch ms> <what happened>' line" % (events_path, n))
            items.append((int(at), what))
    if w["first"] is not None:
        items.append((w["first"], "the first response other than the expected"))
        items.append((w["last"], "the last response other than the expected"))
    print("  the timeline, on k6's clock (the run began at %s):" % utc(t0))
    for at, what in sorted(items, key=lambda x: x[0]):
        print("    %+8.2f s  %s  %s" % ((at - t0) / 1000, utc(at), what))
    seconds = counts(w)
    print("  each second of the run: the responses in it, and how many of them were not the expected (5xx, rest)")
    words, i = [], 0
    while i < len(seconds):
        e, x, r = seconds[i]
        if x + r == 0:
            j, total = i, 0
            while j < len(seconds) and seconds[j][1] + seconds[j][2] == 0:
                total += seconds[j][0]
                j += 1
            span = "+%d" % i if j - i == 1 else "+%d-%d" % (i, j - 1)
            words.append("%s: %d, none" % (span, total))
            i = j
        else:
            words.append("+%d: %d, %d (%d, %d)" % (i, e + x + r, x + r, x, r))
            i += 1
    if w["late"]:
        words.append("later than the seconds counted: %d" % w["late"])
    for k in range(0, len(words), 5):
        print("    " + "; ".join(words[k:k + 5]))


def seconds_between(path, start, end):
    w = need_window(path)
    t0, inside = w["t0"], []
    for i, c in enumerate(counts(w)):
        if t0 + 1000 * i >= start and t0 + 1000 * (i + 1) <= end:
            inside.append((i, c))
    if not inside:
        print("none")
        return
    print("%d %d %d %d %d" % (inside[0][0], inside[-1][0], sum(c[0] for _, c in inside),
                              sum(c[1] for _, c in inside), sum(c[2] for _, c in inside)))


def first_expected(path, at):
    w = need_window(path)
    t0 = w["t0"]
    for i, c in enumerate(counts(w)):
        if t0 + 1000 * (i + 1) > at and c[0]:
            print("%d %.2f" % (i, (at - t0) / 1000))
            return
    print("none")


def last_unexpected(path, start, end):
    w = need_window(path)
    t0, found = w["t0"], None
    for i, c in enumerate(counts(w)):
        if t0 + 1000 * (i + 1) > start and t0 + 1000 * i < end and c[1] + c[2]:
            found = i
    print("none" if found is None else "%d %d" % (found, t0 + 1000 * (found + 1)))


def after_unexpected(path, at):
    w = need_window(path)
    t0 = w["t0"]
    seconds = [(i, c) for i, c in enumerate(counts(w)) if t0 + 1000 * (i + 1) > at and c[1] + c[2]]
    if not seconds:
        print("none")
        return
    print("%d %d" % (sum(c[1] + c[2] for _, c in seconds), len(seconds)))
    for i, c in seconds:
        print("+%d: %d (5xx %d, other %d)" % (i, c[1] + c[2], c[1], c[2]))


def main(argv):
    if len(argv) >= 3 and argv[0] == "medians":
        medians(argv[1], argv[2:])
    elif len(argv) == 3 and argv[0] == "rate":
        rate(argv[1], float(argv[2]))
    elif len(argv) == 6 and argv[0] == "stages":
        stages(argv[1], argv[2], argv[3], argv[4], argv[5])
    elif len(argv) >= 5 and argv[0] == "ceiling":
        ceiling(argv[1], argv[2], argv[3], argv[4:])
    elif len(argv) == 2 and argv[0] == "window":
        window(argv[1])
    elif len(argv) == 3 and argv[0] == "timeline":
        timeline(argv[1], argv[2])
    elif len(argv) == 4 and argv[0] == "seconds" and argv[2].isdigit() and argv[3].isdigit():
        seconds_between(argv[1], int(argv[2]), int(argv[3]))
    elif len(argv) == 3 and argv[0] == "first" and argv[2].isdigit():
        first_expected(argv[1], int(argv[2]))
    elif len(argv) == 4 and argv[0] == "last" and argv[2].isdigit() and argv[3].isdigit():
        last_unexpected(argv[1], int(argv[2]), int(argv[3]))
    elif len(argv) == 3 and argv[0] == "after" and argv[2].isdigit():
        after_unexpected(argv[1], int(argv[2]))
    else:
        die("usage: summary.py medians <runs file> <label>... | rate <runs file> <offered rate>"
            " | stages <runs file> <route> <replicas> <round> <rounds file>"
            " | ceiling <rounds file> <sustained file> <replicas> <route>... | window <fails file>"
            " | timeline <fails file> <events file> | seconds <fails file> <from ms> <to ms>"
            " | first <fails file> <ms> | last <fails file> <from ms> <to ms> | after <fails file> <ms>")


if __name__ == "__main__":
    main(sys.argv[1:])
