# Security and privacy

## Threat model

Each package is encrypted in the uploader's browser with a fresh random 256-bit AES-GCM key. The key travels only in the share link's `#` fragment, which browsers never send to the server. Details are in [Architecture and encryption](architecture.md) and the sections below.

| Attacker | Cannot | Can |
| --- | --- | --- |
| Network observer | Read content, keys, or links (HTTPS) | See that a transfer happened and its approximate size |
| Someone with a link but no `#` key, such as a preview bot | Decrypt, or claim and consume a one-time package | Load the landing page |
| Copy of the server's disk | Decrypt content, package names, or retrieval activity (IP and browser); reconstruct links; claim packages from stored hashes; sign in with the stored verifier | Read sizes, creation/expiry times, retrieval counts, and file modification times; read activity recorded before the admin first signs in after upgrading; brute-force the admin password offline at 600,000 PBKDF2 rounds per guess |
| Malicious server operator during a compromise | Recover keys for links never opened during the compromise | Serve modified JavaScript that captures keys of links opened during the compromise |

Design choices behind these properties:

- **Per-chunk integrity.** Files are split into 8 MiB chunks. Each uses a unique counter IV and AAD binding it to its package and position, so tampered, reordered, or substituted chunks fail decryption.
- **Truncation detection.** Chunk 0 is an encrypted manifest of file names and sizes, so missing or extra chunks are detected and the server never learns file names.
- **Proof of key possession.** Recipients prove they hold the key with an HKDF-derived claim token; the server stores only its SHA-256 hash.
- **Password never sent.** The admin password is stretched with PBKDF2 in the browser and split by HKDF into a sign-in secret and keys for package names and retrieval activity that never leave the browser.
- **Write-only activity log.** The server encrypts each retrieval record to the administrator's public key as it writes it, and cannot decrypt it afterward.


## Trust boundaries

**Client-side encryption does not defend against a compromised server serving modified JavaScript.** Protect deployment credentials, review changes, and keep dependencies patched. An independently distributed client is needed if server-delivered code must be excluded from the trust model. No independent external security audit has been performed; automated vulnerability scans are not an audit or a security guarantee.

- **Share links grant access.** Anyone holding the complete link can retrieve the content. A package ID or stored claim verifier alone cannot authorize a claim. One-time content cannot be restored after an authorized attempt fails, including network, decryption, or save failures. Retain a trusted original for irreplaceable data.
- **Metadata remains visible.** The server learns ciphertext sizes and record boundaries, transfer timing, expiry, package format/mode, and retrieval IP/browser details; it stores the latter only in sealed records. IPs may represent a proxy, NAT, or VPN; size patterns may reveal approximate file counts and sizes.
- **Delivered plaintext cannot be revoked.** Recipients, extensions, clipboard managers, messaging providers, screenshots, and endpoint malware are outside the application's control.
- **Deletion is not forensic erasure.** Unlinking files does not erase SSD remnants, snapshots, backups, RAID copies, or host caches. Exclude the package volume from backups/snapshots when destruction is required. Storage failures can prevent deletion, and offline storage cannot enforce real-time expiry; monitor cleanup errors.
- **Host access remains privileged.** Docker does not protect against a malicious host administrator. Protect the initial setup token and Docker access; use encrypted disks, encrypted/disabled swap, and disabled core dumps.
- **Avoid additional data collection.** Caddy access logging is disabled, and the public proxy's error log drops client IPs and User-Agent headers. Do not add request-body logging, key/URL telemetry, analytics, external error collection, or third-party scripts.

HTTPS protects transport, AES-GCM protects stored content, and the VPN/interface boundary restricts administration. CSP, same-origin checks, cache restrictions, and throttling provide additional safeguards, not absolute protection. Host patching, firewall policy, access-layer MFA where applicable, backup policy, and independent review remain operator responsibilities.

## Runtime safeguards

- Claim proofs and capacity are checked before state changes or ciphertext deletion. HTTP 429 responses occur before consumption, allowing retry with the original link.
- Per-IP request limits, a shared budget for *failed* public requests, and an authentication-failure budget accompany nonblocking request/upload/download admission. Only unknown or expired package IDs, invalid claim proofs, and malformed requests spend the shared public budget, so exhausting it does not block recipients holding valid links. Each package also accepts at most 30 claims per minute, which bounds audit growth from a leaked reusable link; excess claims receive HTTP 429 before anything is claimed or audited. VPN authentication discovery/setup has a separate budget from public package traffic. Authenticated chunk uploads are exempt from the public per-minute budget; valid credentials are not rejected solely because the global failure budget is exhausted. These controls are not DDoS protection.
- Chunk uploads reserve quota and write ciphertext without holding the server-wide lock, so a slow upload does not delay recipients, cleanup, or other admin requests. Each package accepts one in-flight chunk at a time, and finalization waits for it.
- The API runs as UID/GID 10001 in a shell-free `scratch` image, with a read-only root, dropped capabilities, `no-new-privileges`, resource caps, and an internal `/vault healthcheck` command.
- Both Caddy services retain only `NET_BIND_SERVICE` and `no-new-privileges`; the management API is disabled. Keep that capability: the pinned binary's file capability otherwise causes Linux startup to fail with `operation not permitted`.
- Proxies limit header size/read time, idle time, and upstream connections. Error logs strip claim/upload/authentication/cookie credentials; container logs rotate at 10 MiB × 3 per service.
- Base images and Caddy are digest-pinned; WireGuard tools use Alpine's signed repositories. GitHub Actions are SHA-pinned with read-only permissions and no retained checkout credentials. CI checks Go source and the exact production binary with `govulncheck`, plus race/static, browser, and Docker/WireGuard tests. Review Dependabot proposals and Caddy digest updates; pins do not replace rebuilding and vulnerability monitoring.

Slow request bodies and individual response-record writes have two-minute I/O deadlines. Advancing downloads have no fixed overall duration limit, but cannot resume. Keep backend networks private and health checks local.

## Resource controls

| Environment variable | Default |
| --- | --- |
| `MAX_STORAGE_BYTES` | `107374182400` (100 GiB of ciphertext) |
| `MAX_CONCURRENT_REQUESTS` | `64` |
| `MAX_CONCURRENT_DOWNLOADS` | `4` |
| `MAX_CONCURRENT_UPLOADS` | `2` |
| `MAX_BACKEND_CONNECTIONS` | `128` per listener |
| `PUBLIC_REQUESTS_PER_MINUTE` | `600` failed public requests per shared budget, with a fixed 120 per-IP limit on all public requests |
| `AUTH_FAILURES_PER_MINUTE` | `60` globally, with a fixed 20 per-IP limit |

Values must be positive. Upload/download concurrency cannot exceed request concurrency, which cannot exceed backend connections.

The admin **Transfer activity** meter reports quota-counted ciphertext and the configured limit in decimal GB (1 GB = 1,000,000,000 bytes), refreshed with the package list. Uploading, ready, and active-download ciphertext count toward usage until cleanup releases it, as does the declared size of a chunk being written (the full 8 MiB record limit when no length is declared). Historical audit records do not count. This is neither total filesystem usage nor free disk space: audit logs and other workloads require additional headroom, especially for frequently retrieved reusable packages.
