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
// user prints at most its share.
//
// Every request has a 10 s timeout, and each scenario a 15 s gracefulStop, the time k6 lets requests in flight at
// the end finish before it cuts them off: so a request that hangs ends as a timeout, counted as other, before k6
// would cut it off uncounted. Redirects are not followed, so each request is one response, counted by its own
// status.

import http from 'k6/http';
import { Counter } from 'k6/metrics';

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

export const options = {
  scenarios: { edge: SCENARIO },
  summaryTrendStats: ['med', 'p(90)', 'p(99)', 'max'],
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

export default function () {
  const res = http.post(TARGET, BODY, params);
  const key = LISTED.includes(String(res.status)) ? String(res.status) : 'other';
  counters[key].add(1);
  if (res.status !== EXPECT && fails < FAILS_EACH) {
    fails++;
    console.log(`FAIL ${JSON.stringify({ t: Date.now(), status: res.status })}`);
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
  return { stdout: `RESULT ${JSON.stringify(result)}\n` };
}
