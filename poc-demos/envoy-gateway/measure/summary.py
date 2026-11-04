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

  summary.py stages <runs file> <route> <replicas> <sustained file>
      The runs file holds one "<offered rate> RESULT {json}" line a stage of a ramp, each stage a run at a constant
      offered rate, in the order they ran. Prints a table of the stages: offered, achieved, p50, p99, dropped,
      statuses, and whether the stage was sustained: achieved within 5% of offered, and every response a 200. Then
      the highest stage sustained, which it also adds to the sustained file as "<route> <replicas> <rate>" (0 when
      none was). It is a definition, not a target: a run either kept to it or did not.

  summary.py window <fails file>
      The fails file holds edge.js's "FAIL {json}" lines: their count by status, the first and the last (UTC),
      and the span between them. When the run's .result file is beside it ("<expected status> RESULT {json}", from
      k6_run) and the run counted more responses other than the expected than were listed (edge.js lists at most
      20000), it says so first: the window then covers only the ones listed, and the run went on past its end.
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


def stages(path, route, replicas, out):
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
            kept = abs(r["rps"] - offered) <= 0.05 * offered and r["reqs"] > 0 and r["status"].get("200") == r["reqs"]
            rows.append((offered, r, kept))
    if not rows:
        die("no stage in %s" % path)
    print("  %8s  %9s  %7s  %9s  %9s  %8s  %-9s  %s" % (
        "offered", "achieved", "", "p50", "p99", "dropped", "sustained", "statuses"))
    for offered, r, kept in rows:
        print("  %6d/s  %7.1f/s  %+6.1f%%  %6.2f ms  %6.2f ms  %8d  %-9s  %s" % (
            offered, r["rps"], (r["rps"] - offered) / offered * 100, r["p50"], r["p99"], r["dropped"],
            "yes" if kept else "no", statuses([r])))
    sustained = [offered for offered, _, kept in rows if kept]
    best = max(sustained) if sustained else 0
    if not best:
        print("  %s, %s processor replica(s): no stage sustained" % (route, replicas))
    else:
        notes = []
        if best == max(offered for offered, _, _ in rows):
            notes.append("the highest offered, so its ceiling is at or above it")
        below = [offered for offered, _, kept in rows if not kept and offered < best]
        if below:
            notes.append("though not %s" % ", ".join("%d/s" % b for b in below))
        print("  %s, %s processor replica(s): highest sustained stage %d/s%s" % (
            route, replicas, best, "".join(" (%s)" % n for n in notes)))
    with open(out, "a") as f:
        f.write("%s %s %d\n" % (route, replicas, best))


def utc(ms):
    t = datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
    return t.strftime("%H:%M:%S.") + "%03dZ" % (ms % 1000)


def unexpected(path):
    """The count of responses other than the expected that the run's .result file gives, or None."""
    result = path[:-len(".fails")] + ".result" if path.endswith(".fails") else None
    if not result or not os.path.exists(result):
        return None
    with open(result) as f:
        expect, _, rest = f.readline().strip().partition(" ")
    if not rest.startswith("RESULT "):
        die("%s is not an '<expected status> RESULT {json}' line" % result)
    r = json.loads(rest[len("RESULT "):])
    if expect not in r["status"]:
        return None
    return r["reqs"] - r["status"][expect]


def window(path):
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


def main(argv):
    if len(argv) >= 3 and argv[0] == "medians":
        medians(argv[1], argv[2:])
    elif len(argv) == 3 and argv[0] == "rate":
        rate(argv[1], float(argv[2]))
    elif len(argv) == 5 and argv[0] == "stages":
        stages(argv[1], argv[2], argv[3], argv[4])
    elif len(argv) == 2 and argv[0] == "window":
        window(argv[1])
    else:
        die("usage: summary.py medians <runs file> <label>... | rate <runs file> <offered rate>"
            " | stages <runs file> <route> <replicas> <sustained file> | window <fails file>")


if __name__ == "__main__":
    main(sys.argv[1:])
