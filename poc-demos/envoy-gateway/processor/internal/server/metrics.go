// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/edge"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material"
)

// outcomes are every outcome a request can have, each counted from zero.
var outcomes = []edge.Outcome{
	edge.Stamped, edge.RefusedRoute, edge.RefusedMaterial, edge.RefusedBody, edge.RefusedError, edge.Abandoned,
}

// metrics are the processor's own metrics, in a registry of their own with the Go runtime's and the
// process's.
type metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	stamp    prometheus.Histogram
	body     prometheus.Histogram
}

// newMetrics returns the processor's metrics, reporting how long set has left by the clock now.
func newMetrics(set *material.Set, now func() time.Time) *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "paztport_edge_requests_total",
			Help: "Requests the edge handled, by outcome: stamped; refused for its route, its material, its body " +
				"or anything else; or abandoned, its stream ended before the edge decided it.",
		}, []string{"outcome"}),
		stamp: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "paztport_edge_stamp_seconds",
			Help: "How long stamping each stamped request took, hashing its body and signing.",
			// From 50 µs, about a signature and a small body's hash, to 100 ms.
			Buckets: []float64{0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
		}),
		body: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "paztport_edge_body_bytes",
			Help: "The size of each decided request's body, whole or as far as the edge read it.",
			// 256 B to 16 MiB, four times apart.
			Buckets: prometheus.ExponentialBuckets(256, 4, 9),
		}),
	}
	for _, o := range outcomes {
		m.requests.WithLabelValues(string(o))
	}
	m.registry.MustRegister(
		m.requests, m.stamp, m.body,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "paztport_edge_material_seconds_left",
			Help: "How long the edge's policy material stays ready: below zero once it has expired, when the " +
				"edge refuses every request.",
		}, func() float64 { return set.TimeLeft(now().UnixMilli()).Seconds() }),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// observe counts one decided request.
func (m *metrics) observe(o edge.Observation) {
	m.requests.WithLabelValues(string(o.Outcome)).Inc()
	if o.Outcome == edge.Stamped {
		m.stamp.Observe(o.StampDuration.Seconds())
	}
	m.body.Observe(float64(o.BodyBytes))
}
