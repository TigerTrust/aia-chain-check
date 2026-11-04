// Package aia verifies AIA extension presence and TLS chain completeness
// (CA/B Forum ballot SC104 made AIA "should" for subscriber certs).
package aia

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Report describes the AIA / chain state of a leaf certificate.
type Report struct {
	Host                           string   `json:"host,omitempty"`
	Subject                        string   `json:"subject"`
	Issuer                         string   `json:"issuer"`
	NotAfter                       string   `json:"notAfter"`
	HasAIA                         bool     `json:"hasAIA"`
	AIAURIs                        []string `json:"aiaURIs"`
	PresentedIntermediateCount     int      `json:"presentedIntermediateCount"`
	ChainCompleteAgainstSystemRoots bool    `json:"chainCompleteAgainstSystemRoots"`
	WouldNeedAIAFetch              bool     `json:"wouldNeedAIAFetch"`
	RepairedViaAIA                 bool     `json:"repairedViaAIA,omitempty"`
	VerifyError                    string   `json:"verifyError,omitempty"`
}

// Options controls how a report is built.
type Options struct {
	Host               string        // e.g. "example.com:443"
	CertFile           string        // path to leaf PEM
	ChainFile          string        // path to intermediate PEM(s)
	Insecure           bool          // skip verification during dial
	FetchAIA           bool          // attempt HTTP fetch of caIssuers
	FetchAllowHTTP     bool          // allow http:// AIA URIs (default HTTPS only)
	Timeout            time.Duration // dial / fetch timeout
	Roots              *x509.CertPool // optional override (for tests)
	FetchClient        *http.Client   // optional override (for tests)
}

// ErrNoLeaf is returned when no leaf certificate could be sourced.
var ErrNoLeaf = errors.New("no leaf certificate presented or loaded")

// Analyze collects a Report from either --host or --cert/--chain.
func Analyze(opts Options) (*Report, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	var leaf *x509.Certificate
	var intermediates []*x509.Certificate

	switch {
	case opts.Host != "":
		var err error
		leaf, intermediates, err = dialHost(opts.Host, opts.Insecure, opts.Timeout)
		if err != nil {
			return nil, err
		}
	case opts.CertFile != "":
		var err error
		leaf, err = loadLeaf(opts.CertFile)
		if err != nil {
			return nil, err
		}
		if opts.ChainFile != "" {
			intermediates, err = loadCerts(opts.ChainFile)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("must supply --host or --cert")
	}

	if leaf == nil {
		return nil, ErrNoLeaf
	}

	r := &Report{
		Host:                       opts.Host,
		Subject:                    leaf.Subject.String(),
		Issuer:                     leaf.Issuer.String(),
		NotAfter:                   leaf.NotAfter.UTC().Format(time.RFC3339),
		AIAURIs:                    append([]string{}, leaf.IssuingCertificateURL...),
		HasAIA:                     len(leaf.IssuingCertificateURL) > 0,
		PresentedIntermediateCount: len(intermediates),
	}

	// Try to verify using only the presented intermediates.
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: pool,
		Roots:         opts.Roots, // nil → system roots
	}
	if _, err := leaf.Verify(verifyOpts); err == nil {
		r.ChainCompleteAgainstSystemRoots = true
	} else {
		r.ChainCompleteAgainstSystemRoots = false
		r.VerifyError = err.Error()
		if r.HasAIA {
			r.WouldNeedAIAFetch = true
		}
	}

	// Optional: fetch AIA caIssuers and retry Verify.
	if opts.FetchAIA && !r.ChainCompleteAgainstSystemRoots && r.HasAIA {
		fetched, ferr := fetchFirstCAIssuer(leaf.IssuingCertificateURL, opts)
		if ferr == nil && fetched != nil {
			pool.AddCert(fetched)
			if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: pool, Roots: opts.Roots}); err == nil {
				r.ChainCompleteAgainstSystemRoots = true
				r.RepairedViaAIA = true
				r.VerifyError = ""
			}
		}
	}

	return r, nil
}

func dialHost(address string, insecure bool, timeout time.Duration) (*x509.Certificate, []*x509.Certificate, error) {
	if !strings.Contains(address, ":") {
		address += ":443"
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, fmt.Errorf("bad host: %w", err)
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, ErrNoLeaf
	}
	return certs[0], certs[1:], nil
}

func loadLeaf(path string) (*x509.Certificate, error) {
	certs, err := loadCerts(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrNoLeaf
	}
	return certs[0], nil
}

// loadCerts parses one or more PEM-encoded certificates from a file.
func loadCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no PEM CERTIFICATE blocks found in %s", path)
	}
	return out, nil
}

func fetchFirstCAIssuer(uris []string, opts Options) (*x509.Certificate, error) {
	client := opts.FetchClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}
	for _, u := range uris {
		if strings.HasPrefix(u, "http://") && !opts.FetchAllowHTTP {
			continue
		}
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			continue
		}
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
		resp.Body.Close()
		if err != nil {
			continue
		}
		// Try DER first, then PEM.
		if c, err := x509.ParseCertificate(body); err == nil {
			return c, nil
		}
		block, _ := pem.Decode(body)
		if block != nil {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				return c, nil
			}
		}
	}
	return nil, errors.New("no usable AIA certificate fetched")
}
