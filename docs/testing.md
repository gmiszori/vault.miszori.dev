# Development and testing

## Unit and standalone tests

Use Docker, Node.js 22+, and Python 3 for ZIP interoperability checks. Go need not be installed on the host; the commands below run it in disposable containers. Python is a test dependency, not an application runtime dependency.

```bash
# Backend unit tests/static checks inside Docker
docker run --rm -v "$PWD:/src" -w /src golang:1.26-alpine \
  sh -c 'go test ./cmd/vault && go vet ./cmd/vault'

# Race detector needs the C compiler only in this disposable test container
docker run --rm -v "$PWD:/src" -w /src golang:1.26-alpine \
  sh -c 'apk add --no-cache gcc musl-dev >/dev/null && CGO_ENABLED=1 go test -race ./cmd/vault'

# Browser-module tests
node --test web/*.test.mjs

# Standalone proxy capability/TLS/routing regression
node --test tests/proxy-isolation.test.mjs tests/vpn-tls.test.mjs

# WireGuard configuration, persistence and invalid-input tests
node --test wireguard/*.test.mjs

# Disposable production topology with a real WireGuard peer and admin TLS/API
node --test tests/wireguard.test.mjs
```

## Integration stack

Run the disposable loopback-only stack separately from production. Plain HTTP is suitable for WebCrypto on loopback only; never deploy the test configuration publicly.

```bash
docker compose -p vault-test -f tests/compose.yaml up --build -d --wait
node --test tests/*.test.mjs

# Remove only this test stack and its disposable data when finished
docker compose -p vault-test -f tests/compose.yaml down -v
```

While it is running, the admin UI is `http://localhost:18081/admin`; public links use `http://localhost:18080/package/...#key`. The bare root redirects to https://gergo.miszori.dev.

Tests automatically enroll username `admin`, password `integration-admin-password-with-zero-server-knowledge`, and setup token `integration-setup-token-never-deploy-1234567890`. **These fixed credentials are test-only and must never be deployed.** For manual first-setup testing, use the same values before the suite or start with a fresh disposable test volume.

The local stack uses `172.30.0.0/24`. Do not run it where that range is already allocated, including on the default production host. Choose a free private `/24` and update all test addresses together, leaving other projects untouched:

```bash
export TEST_PUBLIC_SUBNET=172.29.0.0/25 TEST_PRIVATE_SUBNET=172.29.0.128/25
export TEST_PUBLIC_API_IP=172.29.0.2 TEST_PRIVATE_API_IP=172.29.0.130
export TEST_ADMIN_PROXY_IP=172.29.0.131 TEST_TRUSTED_PROXY_CIDR=172.29.0.0/24
docker compose -p vault-test -f tests/compose.yaml up --build -d --wait
node --test tests/*.test.mjs
docker compose -p vault-test -f tests/compose.yaml down -v
```

The standalone WireGuard test uses its own disposable project and `172.28.0.0/24`; reserve that range when running the suite. It leaves other projects untouched. Fixtures retain production capability drops while permitting directory traversal on Linux; exported peer keys remain root-owned and owner-readable only.

## Large-transfer checks

With the integration stack running, these optional tests write a real archive and validate its entries with Python's independent ZIP reader:

```bash
# Real 20 GiB transfer and ZIP64 validation:
# requires >21 GiB free in Docker AND >21 GiB in the host temporary directory
LARGE_TEST_MIB=20480 node --test --test-name-pattern='optional large transfer' tests/integration.test.mjs

# Throttled transfer lasting about 165 seconds to check long-transfer deadlines
LARGE_TEST_MIB=192 SLOW_RECORD_MS=6500 node --test --test-name-pattern='optional large transfer' tests/integration.test.mjs
```

## Coverage and deployment checks

Backend tests cover authentication, listener boundaries, concurrent claims, quotas/admission, recovery, deletion/expiry, and transfer deadlines. Browser tests cover cryptographic derivation/framing, ZIP/ZIP64 interoperability, backpressure, text rendering, and lifecycle cleanup. Docker tests exercise real proxies/API, previews, encrypted file/text round trips, and public/admin isolation. WireGuard tests add an encrypted peer handshake, admin HTTPS/API access, forwarding rejection, and host-port checks.

Automated tests do not establish native save-dialog behavior on every browser, production ACME issuance, remote VPN reachability, or host firewall correctness. Verify these on the deployment and actual admin/recipient devices. Docker Desktop can run namespace/tunnel tests, but does not replace Linux deployment checks.
