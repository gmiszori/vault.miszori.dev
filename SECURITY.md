# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Report a vulnerability** button on the [Security tab](https://github.com/gmiszori/vault.miszori.dev/security/advisories/new). Do not open a public issue for security problems.

Include the affected component, steps to reproduce, and the impact you expect. I aim to acknowledge reports within 7 days. Only the latest commit on `main` is supported.

## Scope

In scope: the Go API, browser encryption and download code in `web/`, proxy configuration, and the WireGuard container.

Out of scope: denial-of-service volume testing, attacks that require a compromised administrator device, and the limitations already documented under [Trust boundaries](README.md#trust-boundaries), such as a compromised server serving modified JavaScript.

Please test against your own deployment, not `vault.miszori.dev`.

## Audit status

This project has not been independently audited. Automated checks (`govulncheck`, Dependabot, and the test suite) are not a substitute for a security review.
