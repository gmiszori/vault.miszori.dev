# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately by email to [gergo@miszori.dev](mailto:gergo@miszori.dev), not in a public issue. The full policy, with what to include in a report, the testing rules and the scope, is at [miszori.dev/security](https://miszori.dev/security/).

Only the latest commit on `main` is supported. Test against your own local deployment (see the [README](README.md#quick-start)), never against `vault.miszori.dev`.

## Scope

In scope: the Go API, browser encryption and download code in `web/`, proxy configuration, and the WireGuard container.

Out of scope: denial-of-service volume testing, attacks that require a compromised administrator device, and the limitations already documented under [Trust boundaries](docs/security.md#trust-boundaries), such as a compromised server or Cloudflare serving modified JavaScript.

## Audit status

This project has not been independently audited. Automated checks (`govulncheck`, Dependabot, and the test suite) are not a substitute for a security review.
