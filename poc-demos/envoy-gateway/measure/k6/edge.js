// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The one k6 script of the Envoy Gateway measurements: POSTs to TARGET, and counts every response by its status.
// measure/common.sh runs it in a Job in the cluster (k6_run), with its settings in the environment:
//
//   TARGET    the URL, such as http://paztport-edge.envoy-gateway-system.svc/orders
//   HOST      the Host header, to pick a route by its host; none by default
//   BODY      small (a 400-byte JSON order, the default), large (262144 bytes) or a number of bytes: the order padded
//             to that length, or 0 for no body
//   EXECUTOR  vus (the default): VUS virtual users, each sending its next request when the last is answered, for
//             DURATION (a closed model);
//             rate: RATE requests a second for DURATION, from PREALLOC virtual users (an open model);
//             ramp: the rate STAGES sets, as k6's JSON stages ([{"target": 100, "duration": "30s"}, ...], targets in
//             requests a second, from 0), from PREALLOC virtual users.
//             Under rate and ramp, k6 starts no more users than PREALLOC: a request it cannot start for want of a
//             free one is counted as dropped, never sent late.
//   EXPECT    the expected status, 200 by default
//
// It prints one line, RESULT {json}: reqs (every request sent), rps, p50, p90, p99 and max (each in ms), dropped,
// and status, the count of each response status, with k6's status 0 (no response: a reset, a refused connection or a
// timeout) and any status not listed counted as other, so that the counts sum to reqs. For each response with a
// status other than EXPECT it prints FAIL {"t": <epoch ms>, "status": <status>}, at most 20000 in all: each virtual
// user prints at most its share. Then one line, WINDOW {json}, that covers every response, listed or not: t0, the
// epoch ms at which the run began (k6's setup); first and last, the epoch ms of the first and the last response other
// than EXPECT (null when there was none); and, for each whole second of the run from t0, how many responses came
// back in it, as three lists: expected (EXPECT), 5xx (a 5xx other than EXPECT) and rest (any other, status 0
// included), each ending at its last second with a response. A response later than the seconds counted (the run's
// length, its gracefulStop and 30 s more) is counted in late, which is 0 unless something went very wrong.
//
// Every request has a 10 s timeout, and each scenario a 15 s gracefulStop, the time k6 lets requests in flight at
// the end finish before it cuts them off: so a request that hangs ends as a timeout, counted as other, before k6
// would cut it off uncounted. Redirects are not followed, so each request is one response, counted by its own
// status.

import http from 'k6/http';
import { Counter, Trend } from 'k6/metrics';

const env = __ENV;
const TARGET = env.TARGET;
if (!TARGET) {
  throw new Error('TARGET is not set');
}
const HOST = env.HOST || '';
const EXPECT = Number(env.EXPECT || 200);
const EXECUTOR = env.EXECUTOR || 'vus';
const LISTED = ['200', '403', '413', '500', '502', '503', '504'];
const MAX_FAILS = 20000;
// The request timeout must stay below the scenarios' gracefulStop (see the header).
const TIMEOUT = '10s';
const GRACEFUL_STOP = '15s';

// order <bytes>: a JSON order, its note padded so that the whole is exactly that many bytes.
function order(bytes) {
  const bare = JSON.stringify({ item: 'widget', quantity: 1, note: '' });
  if (bytes < bare.length) {
    throw new Error(`BODY ${bytes} is shorter than the smallest order, ${bare.length} bytes`);
  }
  return JSON.stringify({ item: 'widget', quantity: 1, note: 'x'.repeat(bytes - bare.length) });
}

function body(spec) {
  if (spec === 'small') return order(400);
  if (spec === 'large') return order(262144);
  if (/^[0-9]+$/.test(spec)) return Number(spec) === 0 ? null : order(Number(spec));
  throw new Error(`BODY ${spec} is not small, large or a number of bytes`);
}

const BODY = body(env.BODY || 'small');

function need(name) {
  if (!env[name]) throw new Error(`EXECUTOR ${EXECUTOR} needs ${name}`);
  return env[name];
}

function scenario() {
  switch (EXECUTOR) {
    case 'vus':
      return {
        executor: 'constant-vus',
        vus: Number(need('VUS')),
        duration: need('DURATION'),
        gracefulStop: GRACEFUL_STOP,
      };
    case 'rate':
      return {
        executor: 'constant-arrival-rate',
        rate: Number(need('RATE')),
        timeUnit: '1s',
        duration: need('DURATION'),
        preAllocatedVUs: Number(need('PREALLOC')),
        maxVUs: Number(need('PREALLOC')),
        gracefulStop: GRACEFUL_STOP,
      };
    case 'ramp':
      return {
        executor: 'ramping-arrival-rate',
        startRate: 0,
        timeUnit: '1s',
        stages: JSON.parse(need('STAGES')),
        preAllocatedVUs: Number(need('PREALLOC')),
        maxVUs: Number(need('PREALLOC')),
        gracefulStop: GRACEFUL_STOP,
      };
    default:
      throw new Error(`EXECUTOR ${EXECUTOR} is not vus, rate or ramp`);
  }
}

const SCENARIO = scenario();
const USERS = SCENARIO.vus || SCENARIO.maxVUs;
const FAILS_EACH = Math.max(1, Math.floor(MAX_FAILS / USERS));

// seconds <duration>: a k6 duration (such as 20s, 1m30s or 500ms) in seconds.
function seconds(d) {
  const units = { ms: 0.001, s: 1, m: 60, h: 3600 };
  const parts = String(d).match(/[0-9.]+(ms|h|m|s)/g);
  if (!parts || parts.join('') !== String(d)) throw new Error(`not a k6 duration: ${d}`);
  return parts.reduce((sum, p) => {
    const unit = p.match(/(ms|h|m|s)$/)[0];
    return sum + Number(p.slice(0, -unit.length)) * units[unit];
  }, 0);
}

// The seconds the WINDOW line counts: the run's own length, its gracefulStop, and 30 s more.
const LENGTH = SCENARIO.stages ? SCENARIO.stages.reduce((sum, st) => sum + seconds(st.duration), 0)
  : seconds(SCENARIO.duration);
const SECONDS = Math.ceil(LENGTH) + seconds(GRACEFUL_STOP) + 30;
const KINDS = ['expected', '5xx', 'rest'];
const perSecond = {};
for (const kind of KINDS) {
  perSecond[kind] = [];
  for (let i = 0; i < SECONDS; i++) perSecond[kind].push(new Counter(`second_${kind}_${i}`));
}
const late = new Counter('second_late');
// When each response other than EXPECT came back, in ms from t0: its min and max are the first and the last.
const unexpectedAt = new Trend('unexpected_at');

export const options = {
  scenarios: { edge: SCENARIO },
  summaryTrendStats: ['min', 'med', 'p(90)', 'p(99)', 'max'],
  maxRedirects: 0,
  // A run's numbers are its RESULT line alone.
  discardResponseBodies: true,
};

const counters = {};
for (const s of LISTED.concat(['other'])) {
  counters[s] = new Counter(`status_${s}`);
}

const params = { headers: { 'Content-Type': 'application/json' }, timeout: TIMEOUT };
if (HOST) params.headers.Host = HOST;

let fails = 0;

// The run's start, the same for every virtual user: the WINDOW line's t0.
export function setup() {
  return { t0: Date.now() };
}

export default function (data) {
  const res = http.post(TARGET, BODY, params);
  const at = Date.now();
  const key = LISTED.includes(String(res.status)) ? String(res.status) : 'other';
  counters[key].add(1);
  let kind = 'expected';
  if (res.status !== EXPECT) {
    kind = res.status >= 500 && res.status <= 599 ? '5xx' : 'rest';
    unexpectedAt.add(at - data.t0);
  }
  const second = Math.max(0, Math.floor((at - data.t0) / 1000));
  if (second < SECONDS) {
    perSecond[kind][second].add(1);
  } else {
    late.add(1);
  }
  if (res.status !== EXPECT && fails < FAILS_EACH) {
    fails++;
    console.log(`FAIL ${JSON.stringify({ t: at, status: res.status })}`);
  }
}

function count(data, name) {
  const m = data.metrics[name];
  return m ? m.values.count : 0;
}

function round(n) {
  return Math.round(n * 100) / 100;
}

export function handleSummary(data) {
  const d = data.metrics.http_req_duration ? data.metrics.http_req_duration.values : {};
  const status = {};
  for (const s of LISTED.concat(['other'])) {
    status[s] = count(data, `status_${s}`);
  }
  const result = {
    reqs: count(data, 'http_reqs'),
    rps: round(data.metrics.http_reqs ? data.metrics.http_reqs.values.rate : 0),
    p50: round(d.med || 0),
    p90: round(d['p(90)'] || 0),
    p99: round(d['p(99)'] || 0),
    max: round(d.max || 0),
    dropped: count(data, 'dropped_iterations'),
    status,
  };
  const t0 = data.setup_data ? data.setup_data.t0 : null;
  const at = data.metrics.unexpected_at ? data.metrics.unexpected_at.values : null;
  const window = {
    t0,
    first: at && t0 !== null ? t0 + at.min : null,
    last: at && t0 !== null ? t0 + at.max : null,
    late: count(data, 'second_late'),
  };
  for (const kind of KINDS) {
    const counts = [];
    for (let i = 0; i < SECONDS; i++) counts.push(count(data, `second_${kind}_${i}`));
    while (counts.length && counts[counts.length - 1] === 0) counts.pop();
    window[kind] = counts;
  }
  return { stdout: `RESULT ${JSON.stringify(result)}\nWINDOW ${JSON.stringify(window)}\n` };
}
