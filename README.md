# aia-chain-check

Fail CI when a TLS endpoint does not send its full intermediate chain — the state most browsers will stop silently repairing after **CA/B Forum ballot SC104**.

> Built by [TigerTrust](https://tigertrust.io).

## Why this exists

[SC104](https://cabforum.org/2026/09/03/ballot-sc104-set-presence-of-aia-extension-to-should-for-subscriber-certificates/)
changed the `AIA` extension from *required* to *should* for subscriber
certificates, effective ~4 Oct 2026. Browsers that used to repair incomplete
chains by fetching `caIssuers` over HTTP may stop doing so. If your server
only ships the leaf, users running the new browsers will see `ERR_CERT_AUTHORITY_INVALID`.

This tool answers one question for a given host or PEM: **does the chain
verify against the system roots using only what the server presented, without
any AIA fetching?**

## Install

```sh
go install github.com/tigertrust/aia-chain-check/cmd/aia-chain-check@latest
```

## Quick start

### Check a live host

```sh
aia-chain-check --host example.com:443
```

```
Host:                        example.com:443
Subject:                     CN=example.com
Issuer:                      CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
NotAfter:                    2027-01-14T23:59:59Z
Has AIA (caIssuers):         true
AIA URIs:
  - http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
Presented intermediates:     1
Chain complete (no AIA fetch): true
```

### Check a local PEM bundle (pre-deploy)

```sh
aia-chain-check --cert leaf.pem --chain intermediates.pem
```

### Demonstrate the SC104 failure mode — leaf alone, no intermediates

```sh
aia-chain-check --cert leaf-only.pem
echo "exit: $?"   # 1 — WouldNeedAIAFetch=true
```

### Attempt the AIA fetch anyway (what browsers may stop doing)

```sh
aia-chain-check --cert leaf-only.pem --fetch-aia
# stderr: warn: chain repaired via AIA (browsers may not do this post-SC104)
```

### Also require the leaf to publish an AIA caIssuers URI

```sh
aia-chain-check --host example.com:443 --fail-on-missing-aia
```

### JSON output for pipelines

```sh
aia-chain-check --host example.com:443 --json | jq '.chainCompleteAgainstSystemRoots'
```

### From a Go source checkout

```sh
go run ./cmd/aia-chain-check --host example.com:443
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--host HOST[:PORT]` | — | TLS endpoint to dial (port defaults to 443) |
| `--cert PATH` | — | Leaf PEM to inspect |
| `--chain PATH` | — | Optional intermediate PEM(s) |
| `--json` | `false` | Emit JSON report |
| `--fail-on-incomplete-chain` | `true` | Exit 1 if chain does not verify |
| `--fail-on-missing-aia` | `false` | Exit 1 if leaf has no AIA caIssuers URI |
| `--fetch-aia` | `false` | Attempt the AIA fetch (what browsers may stop doing) |
| `--insecure` | `false` | Skip verification during dial |
| `--timeout DUR` | `10s` | Dial / fetch timeout |

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Chain verifies against system roots using only the presented certs |
| `1` | Incomplete chain, or `--fail-on-missing-aia` triggered |
| `2` | Bad arguments or dial error |

## JSON schema

```json
{
  "host": "example.com:443",
  "subject": "CN=example.com",
  "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
  "notAfter": "2027-01-14T23:59:59Z",
  "hasAIA": true,
  "aiaURIs": ["http://cacerts.digicert.com/..."],
  "presentedIntermediateCount": 1,
  "chainCompleteAgainstSystemRoots": true,
  "wouldNeedAIAFetch": false
}
```

## Use in GitHub Actions

```yaml
jobs:
  chain-check:
    runs-on: ubuntu-latest
    steps:
      - uses: tigertrust/aia-chain-check@v0.1
        with:
          host: api.example.com:443
          fail_on_incomplete_chain: 'true'
```

Default policy: fail on incomplete chain, warn on missing AIA when the chain
is already complete — because SC104 explicitly allows that case.

## FAQ

**Does this replace OpenSSL's `verify`?** No. It wraps `crypto/x509.Verify`
against the system root store on the runner, using *only* the certificates
the server presented. That is what browsers will enforce after SC104.

**Should I turn on `--fetch-aia`?** Only if you want to confirm that an AIA
URL still returns a valid certificate; a repaired result is labelled clearly
because it does not reflect what browsers now do.

**Can I trust the system roots on the runner?** The default `ubuntu-latest`
runner uses `ca-certificates` from Ubuntu, which tracks the Mozilla store.
Pin the runner image or supply your own roots if you need stricter control.

## Related

- [`47-day-readiness-score`](https://github.com/tigertrust/47-day-readiness-score) — overall short-lived-cert readiness score
- [`cert-expiry-action`](https://github.com/tigertrust/cert-expiry-action) — fail CI when a cert is close to expiry

## License

Apache-2.0. See [LICENSE](./LICENSE) and [SECURITY.md](./SECURITY.md).
