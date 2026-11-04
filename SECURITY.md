# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes.

## Reporting a vulnerability

Please email **security@tigertrust.io** with a description of the issue, steps
to reproduce, and any proof-of-concept. We acknowledge reports within 3
business days and aim to ship fixes within 30 days for critical findings.

Do **not** file public GitHub issues for vulnerabilities.

## Scope

This tool makes outbound TLS connections to hosts you specify and, with
`--fetch-aia`, HTTPS GETs to URIs embedded in the leaf certificate's AIA
extension. Fetches are size-capped (1 MiB) and timeout-bounded. `http://`
URIs are refused unless `--fetch-aia` is combined with explicit opt-in.
