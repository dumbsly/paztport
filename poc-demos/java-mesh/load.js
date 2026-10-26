// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// k6 load script for Paztport. Drives the legitimate path
// client -> gateway -> orders -> payment and reports latency percentiles.
//
// Run (from a container on the mesh network):
//   docker run --rm --network paztport-mesh \
//     -e TARGET=http://gateway:8080/checkout -e VUS=10 -e DURATION=20s \
//     -v "$PWD/load.js:/scripts/load.js:ro" grafana/k6 run /scripts/load.js
//
// Compare payment in `off` vs `enforce` mode (toggle via POST /admin/mode) to
// isolate the verifier's added latency. See measure.sh.

import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '20s',
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(99)', 'max'],
};

const TARGET = __ENV.TARGET || 'http://gateway:8080/checkout';

export default function () {
  const res = http.post(TARGET, '{}', { headers: { 'Content-Type': 'application/json' } });
  check(res, { 'status is 200': (r) => r.status === 200 });
}

// Emit one machine-readable line so the runner can capture percentiles.
export function handleSummary(data) {
  const d = data.metrics.http_req_duration.values;
  const failed = data.metrics.http_req_failed ? data.metrics.http_req_failed.values.rate : 0;
  const line =
    `RESULT med=${d.med.toFixed(2)}ms p99=${d['p(99)'].toFixed(2)}ms ` +
    `avg=${d.avg.toFixed(2)}ms max=${d.max.toFixed(2)}ms fail=${(failed * 100).toFixed(2)}%`;
  return { stdout: line + '\n' };
}
