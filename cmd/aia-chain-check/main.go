// Command aia-chain-check reports AIA presence and chain completeness
// for a TLS endpoint or local PEM file.
//
// Exit codes: 0 chain verifies with presented certs;
// 1 incomplete chain (when --fail-on-incomplete-chain) or no AIA (when --fail-on-missing-aia);
// 2 bad args / dial error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tigertrust/aia-chain-check/internal/aia"
)

const usage = `aia-chain-check — TigerTrust AIA + chain completeness check

Usage:
  aia-chain-check --host example.com:443 [flags]
  aia-chain-check --cert leaf.pem [--chain intermediates.pem] [flags]

Examples:
  # Check a live host (default: fails if the presented chain is incomplete)
  aia-chain-check --host example.com:443

  # Check local PEMs before a deploy
  aia-chain-check --cert leaf.pem --chain intermediates.pem

  # Demonstrate the SC104 failure mode — leaf alone, no intermediates
  aia-chain-check --cert leaf-only.pem

  # Attempt the AIA fetch anyway (what browsers may stop doing)
  aia-chain-check --cert leaf-only.pem --fetch-aia

  # Also require the leaf to publish an AIA caIssuers URI
  aia-chain-check --host example.com:443 --fail-on-missing-aia

  # JSON output for pipelines
  aia-chain-check --host example.com:443 --json

Exit codes:
  0  chain verifies against system roots using only the presented certs
  1  incomplete chain, or --fail-on-missing-aia triggered
  2  bad arguments or dial error

Flags:
`

func main() {
	fs := flag.NewFlagSet("aia-chain-check", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	host := fs.String("host", "", "hostname[:port] to dial (default port 443)")
	cert := fs.String("cert", "", "path to leaf certificate PEM")
	chain := fs.String("chain", "", "path to intermediate certificate PEM(s)")
	jsonOut := fs.Bool("json", false, "emit JSON")
	failMissing := fs.Bool("fail-on-missing-aia", false, "exit 1 if the leaf has no AIA caIssuers URI")
	failIncomplete := fs.Bool("fail-on-incomplete-chain", true, "exit 1 if the presented chain does not verify")
	fetchAIA := fs.Bool("fetch-aia", false, "attempt to fetch AIA caIssuers and retry verification")
	insecure := fs.Bool("insecure", false, "skip TLS verification during dial")
	timeout := fs.Duration("timeout", 10*time.Second, "dial / fetch timeout")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *host == "" && *cert == "" {
		fs.Usage()
		os.Exit(2)
	}

	r, err := aia.Analyze(aia.Options{
		Host:      *host,
		CertFile:  *cert,
		ChainFile: *chain,
		Insecure:  *insecure,
		FetchAIA:  *fetchAIA,
		Timeout:   *timeout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printText(r)
	}

	// Default policy: SC104 says missing AIA is fine as long as the chain is complete.
	if !r.ChainCompleteAgainstSystemRoots {
		if *failIncomplete {
			os.Exit(1)
		}
	}
	if !r.HasAIA {
		if *failMissing {
			os.Exit(1)
		}
		if r.ChainCompleteAgainstSystemRoots {
			fmt.Fprintln(os.Stderr, "warn: leaf has no AIA caIssuers URI (OK under SC104 because the chain is complete)")
		}
	}
	if r.RepairedViaAIA {
		fmt.Fprintln(os.Stderr, "warn: chain repaired via AIA (browsers may not do this post-SC104)")
	}
}

func printText(r *aia.Report) {
	if r.Host != "" {
		fmt.Printf("Host:                        %s\n", r.Host)
	}
	fmt.Printf("Subject:                     %s\n", r.Subject)
	fmt.Printf("Issuer:                      %s\n", r.Issuer)
	fmt.Printf("NotAfter:                    %s\n", r.NotAfter)
	fmt.Printf("Has AIA (caIssuers):         %t\n", r.HasAIA)
	if len(r.AIAURIs) > 0 {
		fmt.Printf("AIA URIs:\n")
		for _, u := range r.AIAURIs {
			fmt.Printf("  - %s\n", u)
		}
	}
	fmt.Printf("Presented intermediates:     %d\n", r.PresentedIntermediateCount)
	fmt.Printf("Chain complete (no AIA fetch): %t\n", r.ChainCompleteAgainstSystemRoots)
	if r.WouldNeedAIAFetch {
		fmt.Printf("Would need AIA fetch:        true (browsers may not do this post-SC104)\n")
	}
	if r.RepairedViaAIA {
		fmt.Printf("Repaired via AIA:            true\n")
	}
	if r.VerifyError != "" {
		fmt.Printf("Verify error:                %s\n", r.VerifyError)
	}
}
