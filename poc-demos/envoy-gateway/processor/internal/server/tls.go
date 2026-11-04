// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// EdgeName is the one common name the client certificate's subject may carry: Envoy's, as the edge.
const EdgeName = "edge"

// oidCommonName is the attribute type of a subject's common name (CN), 2.5.4.3.
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// errNotEdge is the handshake's refusal of a client certificate whose subject is not CN=edge alone.
var errNotEdge = errors.New("server: the client certificate's subject is not the common name " + EdgeName + " alone")

// serverTLS returns the gRPC port's TLS: TLS 1.3 only, the processor's certificate, and a client
// certificate required, chaining to the client CA, whose leaf's subject holds exactly one common name,
// edge. Any other client's connection is refused in the handshake, so nothing it sends reaches the
// processor; each refusal is logged, with nothing of the certificate.
func serverTLS(cfg Config, log *slog.Logger) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("server: the server certificate or its key does not load: %w", err)
	}
	pem, err := os.ReadFile(cfg.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("server: the client CA does not load: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("server: the client CA %s holds no PEM certificate", cfg.ClientCA)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := edgeOnly(cs); err != nil {
				log.Warn("refused a client", "reason", err.Error())
				return err
			}
			return nil
		},
	}, nil
}

// edgeOnly accepts a connection whose verified client leaf's subject holds the common name edge and no
// other common name. It reads every attribute of the subject, not the parsed CommonName, which keeps only
// the last of several.
func edgeOnly(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		return errNotEdge
	}
	var names []any
	for _, atv := range cs.PeerCertificates[0].Subject.Names {
		if atv.Type.Equal(oidCommonName) {
			names = append(names, atv.Value)
		}
	}
	if len(names) != 1 {
		return errNotEdge
	}
	if name, ok := names[0].(string); !ok || name != EdgeName {
		return errNotEdge
	}
	return nil
}
