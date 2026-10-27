// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// k6 load script for Paztport. Drives the legitimate path
// client -> gateway -> orders -> payment and reports latency percentiles.
//
// Run (from a container on the mesh network, as root so it can read the
// owner-only key file):
//   docker run --rm --user 0:0 --network paztport-mesh \
//     -v "$PWD/out/keys/tls/operator.crt:/tls/operator.crt:ro" \
//     -v "$PWD/out/keys/tls/operator.key:/tls/operator.key:ro" \
//     -e TARGET=https://gateway:8080/checkout -e VUS=10 -e DURATION=20s \
//     -v "$PWD/load.js:/scripts/load.js:ro" grafana/k6 run /scripts/load.js
//
// measure.sh runs it with payment in `off` and in `enforce` mode (toggled via
// POST /admin/mode), warmed up and alternated; its header says what the
// difference covers.
//
// Every hop is mutual TLS, so k6 presents the operator's certificate. k6 has no
// option to trust a private CA, so it skips checking the gateway's certificate
// instead (insecureSkipTLSVerify); the gateway still checks the operator's, and
// every hop behind it verifies as usual.

import http from 'k6/http';
import { check } from 'k6';

const TARGET = __ENV.TARGET || 'https://gateway:8080/checkout';

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '20s',
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(99)', 'max'],
  insecureSkipTLSVerify: true,
  tlsAuth: [
    {
      domains: [TARGET.split('/')[2].split(':')[0]],
      cert: open('/tls/operator.crt'),
      key: open('/tls/operator.key'),
    },
  ],
};

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
