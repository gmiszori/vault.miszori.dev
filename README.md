# drive.miszori.dev

Private, client-encrypted, one-time file packages. Both pages use a minimal dark interface with blue accents, branded `drive.miszori.dev`. Docker runs a small Go API and Caddy; the browser encrypts/decrypts with WebCrypto. No JavaScript frameworks, third-party scripts, analytics, database service, or build step for the web pages.

## What it does

- A **VPN-only admin page** creates packages from files or folders, sets an expiry, and displays download audit records.
- The public page displays a destructive-download warning. **Opening a link does not consume it**; clicking **Download and destroy** does. This avoids previews and link scanners accidentally destroying packages.
- A package can be claimed exactly once, including during concurrent requests. The server deletes its ciphertext during/after the attempt, even if the download fails. There is no retry or recovery.
- Unclaimed packages expire after 1 minute–30 days. The cleanup job runs every 15 seconds; expired packages are immediately unavailable even before cleanup runs.
- Up to **20 GiB per package**, 20,000 files, and 100 active packages. Encryption/upload uses 8 MiB records, not whole-file buffers. The default aggregate ciphertext quota is 100 GiB.
- Recipients download one **`.zip` archive**, preserving folder paths. ZIP64 supports files and archive offsets above 4 GiB. Entries use ZIP's uncompressed (store) method to keep large downloads streaming and avoid wasting CPU on already-compressed files. Use a current ZIP utility for very large archives.

## Network design

The admin interface is **not publicly reachable**, even with a correct password.

| Listener on the host | Purpose |
| --- | --- |
| Public-facing interface, TCP 80/443 | Public landing/download page, ACME certificate validation, public API |
| VPN interface `10.0.0.1`, TCP 80 | Redirect to `https://drive.miszori.dev/admin` |
| VPN interface `10.0.0.1`, TCP 443 | Admin login, upload interface, audit API |
| Go API | Private Docker network only; no host port |

For admin devices, private DNS or a hosts entry maps **the same domain** to `10.0.0.1`. The VPN TLS listener uses the same publicly trusted certificate as the public listener. The public listener explicitly returns 404 for admin pages, assets, and API paths. The VPN listener also serves package downloads, so generated links work while connected to the VPN. Caddy internally uses port 8443 for VPN HTTPS; users still use ordinary HTTPS port 443.

HTTPS is mandatory: browser WebCrypto does not work on plain HTTP VPN addresses. VPN HTTP redirects to the domain, rather than serving an insecure encryption page. Do not put a CDN or external reverse proxy in front without redesigning the IP/audit and trust boundaries.

## Deploy

Requirements: Linux server, Docker Engine with Compose v2, a working VPN with `10.0.0.1` assigned to the host, DNS control, and adequate free disk space. Docker Desktop is suitable for the local tests, not a substitute for the production VPN/network setup.

1. Point the domain's public A record to the server. Only publish an AAAA record if you also configure IPv6 listeners and firewall rules; the provided bindings are IPv4.
2. Forward/open public TCP 80 and 443. Allow the VPN ports only over your VPN. Do **not** forward VPN address/ports from the internet. Docker-published ports can bypass ordinary UFW rules; enforce restrictions at the upstream firewall and Docker's supported firewall chain as well as binding to the correct interface.
3. Configure the environment:

```bash
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

Put the generated password in `ADMIN_PASSWORD`. Set `ACME_EMAIL`, `DOMAIN`, and `PUBLIC_BIND_IP` to a **specific local interface address**. If the server is behind NAT, use the host's LAN address, not the router's external address. Never use `0.0.0.0`: it conflicts with, and defeats the separation from, the VPN binding. `PUBLIC_BIND_IP` and `VPN_BIND_IP` must be different addresses.

4. Start:

```bash
docker compose config --quiet
docker compose up --build -d --wait
docker compose logs --tail=30 api caddy
```

Caddy obtains/renews a certificate automatically. Certificate issuance requires public DNS and inbound ACME access. Deployment will fail to bind if the VPN address is not present. The backend network uses `172.30.0.0/24`; ensure it does not overlap existing networks. Only Caddy and the API should join it.

5. On each admin device, connect to the VPN and configure split DNS, or add:

```text
10.0.0.1 drive.miszori.dev
```

Then visit `https://drive.miszori.dev/admin` and log in. Username defaults to `admin`. Use a unique long password (the application requires at least 16 characters; the example generation produces 64). Credentials are retained only in page memory; reload/log out to clear the application's copy. HTTP Basic credentials accompany each private API request over HTTPS. This is deliberately a single-admin, VPN-protected application, not a public multi-user identity system or MFA provider.

6. Verify **from a device outside the VPN** that `/admin`, `/admin/api/packages`, and `/api/admin/packages` return 404. Public recipients must use public DNS, not the admin's private mapping.

Do not run the local test stack on a production host with this network already allocated.

## Using it

1. Log in on the VPN page; choose files or a folder and an expiry. Expiry starts when the package is created, **including upload time**; allow enough time for large transfers.
2. The browser creates a fresh encryption key, encrypts filenames and file bytes, and uploads encrypted records sequentially. Do not close the tab during upload. Failed uploads are removed when possible; interrupted uploads are discarded on server restart or expire normally.
3. Copy the generated link and send it over a trusted channel. The key is after `#`, **not** in the request path/query. Whoever has the whole link can claim the package. The admin cannot recover a link/key after losing it; recreate the package instead.
4. The recipient sees the warning and expiry, chooses a destination, then confirms the destructive transfer. Do not close/sleep the device during a large transfer. The page removes the fragment from the current address/history entry immediately after capturing it; the key remains only in page memory, so reloading requires reopening the original link.
5. The admin audit lists status, opening/claim time, and the request IP. A `consumed` status means the server completed its response, **not** proof the user successfully saved, extracted, or read the archive. `failed` includes aborted downloads and interrupted uploads.

**Large-download browser requirement:** desktop Chromium (Chrome/Edge) with the File System Access API, a secure context, enough destination disk space, and a filesystem supporting files above 4 GiB (not FAT32). Browsers without that API use a strictly capped small-package memory fallback. They cannot safely handle 10–20 GiB; use desktop Chromium. Browser encryption still occurs in chunks on both paths. Folder selection includes files, but empty folders are not preserved.

## Encryption and storage protocol

1. A package gets an independent, random 256-bit ID from the server. A separate random upload token authorizes its upload; only its SHA-256 hash is persisted, and that hash is cleared when finalized. The VPN password is additionally required for upload operations.
2. The browser generates a **fresh random 256-bit AES key per package**. It must never reuse it for another upload.
3. Record 0 is an encrypted JSON manifest: `{version:1, files:[{path,size,lastModified}], chunkSize:8388608}`. Subsequent records contain each file's bytes, split at 8 MiB, in manifest order. Empty files need no data records.
4. Every record uses **AES-256-GCM** with its 128-bit authentication tag. Its 96-bit IV is four zero bytes followed by the record index as an unsigned 64-bit big-endian integer. Unique indices under a fresh package key prevent IV reuse. Additional authenticated data is UTF-8 `packageID:recordIndex`; changing record order, package ID, key, or ciphertext fails authentication. Failed/ambiguous uploads are aborted rather than re-encrypted with a reused IV.
5. The share link is `https://drive.miszori.dev/package/<256-bit-id>#<base64url-key>`. Browsers do not send fragments in HTTP requests. No key is sent to the API, stored in browser storage, or retained by the server.
6. A POST claim atomically changes `ready` to `consuming` and persists the time/IP before returning any content. The binary response consists of repeated **4-byte big-endian ciphertext length + ciphertext** records. Each record is unlinked before it is streamed; remaining records are removed when the handler completes or fails. A crashed `consuming` package is purged at startup before serving requests. Multiple backend replicas are **not supported**: the in-process claim lock requires exactly one API instance.
7. The browser authenticates and decrypts every record and writes an uncompressed ZIP stream. CRC-32 checksums and data descriptors allow each file to be written without buffering it; ZIP64 records support sizes and offsets above 4 GiB. UTF-8 names preserve nested and Unicode paths. Only central-directory metadata is retained in memory, bounded by the manifest/file-count limits. Filename validation rejects unsafe traversal paths and duplicate names. CRC-32 is ZIP compatibility checking, not a security primitive: AES-GCM supplies authenticity. There is no trusted plaintext manifest on the server. Archive generation is entirely local, so existing encrypted packages also download as ZIP without migration.

The Docker `packages` volume stores one directory per package. Its `meta.json` contains ID, state, creation/expiry/opening times, request IP, ciphertext byte/record counts, and (only during upload) the token hash. Numbered `.bin` files contain ciphertext. Temporary writes are synced and atomically renamed. Metadata is retained until 90 days after the package's expiry, then removed. It never contains original filenames, file contents, or decryption keys.

## Privacy boundaries and operational limits

**Client-side encryption is not a guarantee against a compromised server.** The server supplies the JavaScript; an attacker controlling it could serve modified code to steal future keys. Protect deployment credentials and dependencies, inspect changes, keep images patched, and consider independently distributed clients if that threat must be excluded. No external security audit has been performed.

- The server necessarily learns ciphertext size/record boundaries, upload/download timing, expiry, and the network request IP (which may be a VPN/NAT/proxy address, not proof of a person's identity). Size patterns may reveal rough file counts and sizes. Admin passwords exist in the API process environment and must be protected from host/Docker administrators. Docker is isolation, not protection from a malicious host administrator.
- HTTPS protects transport; AES-GCM protects stored content. The VPN and private route boundary protect administration. CSP, same-origin checks, no third-party resources, no caching, and login/public request throttles reduce exposure; none gives absolute security.
- The share link itself is a bearer capability. Anyone receiving/stealing it can download first, and anyone who learns its package ID can deliberately consume ciphertext without knowing the key. GCM failure after a claim does not restore the package.
- Caddy access logging is not enabled. Do not add request-body logging, analytics, external error collection, URL/key telemetry, or third-party scripts. Browser extensions, clipboard managers, messaging apps, screenshots, endpoint malware, and the recipient's saved copy are outside this application's control.
- Deletion means unlinking live filesystem files. It is **not forensic erasure** on SSDs, snapshots, backups, RAID, or host caches. Do not back up/snapshot the package volume if destruction is required. Avoid plaintext swap/core dumps; use encrypted host disks and encrypted/disabled swap. A storage failure may prevent deletion; monitor API error logs and resolve immediately. Offline disks cannot enforce real-time expiry; startup cleanup runs before requests are accepted.
- The recipient can retain/redistribute downloaded files. The application cannot revoke plaintext once delivered or prove a human viewed it.
- An intentionally disconnected browser still destroys the package. Caddy/OS networking can buffer bytes; successful server delivery cannot prove successful client persistence. Do not use for irreplaceable data without a separate trusted original.
- Slow/stalled individual request bodies and response records have a two-minute I/O deadline; the entire multi-hour package transfer has no fixed overall timeout. Resume is intentionally unsupported. Quotas limit aggregate storage, not the free space shared with other host workloads: monitor disk headroom.

## Filesystem

```text
.
├── .github/workflows/test.yml  Go, browser-module, Docker integration CI
├── .env.example          Environment template (real .env is ignored)
├── .gitignore            Excludes secrets and local artifacts
├── .dockerignore         Keeps secrets out of Docker builds
├── compose.yaml          Production services, volumes, network/port boundaries
├── Dockerfile            Multi-stage Go build; non-root minimal runtime
├── Caddyfile             Public HTTPS and separate VPN admin HTTPS routes
├── go.mod                Go version/module; standard library only
├── package.json          ES-module/test metadata; no browser dependencies
├── cmd/drive/
│   ├── main.go           Auth, encrypted storage, atomic claims, audit, cleanup
│   └── main_test.go      Backend lifecycle, races, auth, failure/expiry tests
├── web/
│   ├── index.html        Public landing/destructive-download page
│   ├── admin.html        VPN login/upload/audit page
│   ├── styles.css        Responsive UI; no remote fonts or assets
│   ├── admin.js          Upload UI and private API interaction
│   ├── public.js         Warning, one-time download, local archive saving
│   ├── crypto.js         Chunk encryption, manifest/path validation, framing
│   ├── zip.js            Bounded-memory ZIP/ZIP64 archive writer
│   └── *.test.mjs        Browser-module protocol/archive tests
├── tests/
│   ├── compose.yaml      Isolated loopback-only development/test stack
│   ├── Caddyfile         HTTP loopback test listeners (never deploy publicly)
│   └── integration.test.mjs  Actual Caddy/API encryption/claim/large-transfer tests
└── README.md             Architecture, setup, protocol, limits, verification
```

## Testing

Go is not required on the host. Use Docker, Node 22+, and Python 3 for native ZIP interoperability checks. Python is only a test dependency, not part of the application runtime.

```bash
# Backend unit tests/static checks inside Docker
docker run --rm -v "$PWD:/src" -w /src golang:1.26-alpine \
  sh -c 'go test ./cmd/drive && go vet ./cmd/drive'

# Race detector needs the C compiler only in this disposable test container
docker run --rm -v "$PWD:/src" -w /src golang:1.26-alpine \
  sh -c 'apk add --no-cache gcc musl-dev >/dev/null && CGO_ENABLED=1 go test -race ./cmd/drive'

# Browser-module tests
node --test web/*.test.mjs

# Local stack; HTTP is safe for WebCrypto on loopback only
docker compose -p drive-test -f tests/compose.yaml up --build -d --wait
node --test tests/integration.test.mjs

# Optional real 20 GiB transfer + ZIP64 CRC validation with Python 3:
# needs >21 GiB free Docker disk AND >21 GiB in the host temporary directory
LARGE_TEST_MIB=20480 node --test --test-name-pattern='optional large transfer' tests/integration.test.mjs

# Deletes ONLY the named test stack and its disposable data
docker compose -p drive-test -f tests/compose.yaml down -v
```

While the test stack is running, public UI is `http://localhost:18080` and admin UI is `http://localhost:18081/admin`. Test credentials are deliberately fixed and **must never be deployed**. Production certificate issuance, real VPN reachability, split DNS, firewall enforcement, and multiple real browser/OS combinations must be verified on the deployment server separately.

### Verification performed

An actual **20 GiB** package was AES-GCM encrypted, uploaded through Caddy to Docker storage, downloaded once, authenticated/decrypted record by record, and byte-compared successfully (about 195 seconds on the development machine). Sampled container memory during this transfer was approximately 24–28 MiB for the API and 20–26 MiB for Caddy; the transfer did not require buffering the package. This is a protocol/storage test, not a claim that every browser/device can save a 20 GiB archive. The production Caddy configuration was also exercised with a local TLS certificate and reduced container capabilities: public admin requests returned 404 while the separate private admin API returned 200 with credentials. Browser-module tests and the Go race detector/static checks passed. Docker integration tests verified concurrent one-time claims, tamper detection, IP spoof rejection, deletion, and a real 60-second expiry followed by background cleanup. Browser checks covered the responsive pages, real login/file/folder uploads, independent decryption of a browser-created package, fragment removal, and decrypted archive generation. The streaming UI path was exercised with a test writable destination; native OS Save dialogs and large-browser filesystem saves still need a real-device check.

The ZIP update was additionally tested with another **actual 20 GiB** encrypted round trip written to a streaming ZIP64 archive (about 212 seconds). Python's independent ZIP reader validated every entry CRC, a file above 4 GiB, subsequent entry offsets above 4 GiB, Unicode paths, and an empty file. The generated archive and ciphertext test data were cleaned up afterward. Regular ZIP headers, exact archive sizing, backpressure, and incomplete/sink-error handling are also covered by tests. A real browser-created Unicode-file package was uploaded, downloaded as ZIP, and independently checked with Python for original contents and CRC validity. Mobile admin and download pages were checked at 390 pixels wide with no horizontal page overflow; the audit table scrolls internally.

## Maintenance

```bash
# Update/rebuild, preserving named volumes
docker compose pull
docker compose up --build -d --wait
# Rebind/reload updated Caddy routing (including the ZIP module allowlist)
docker compose up -d --force-recreate caddy
```

Restarting intentionally destroys incomplete uploads and interrupted downloads. Ready packages survive until consumed/expired/deleted. `docker compose down` preserves data; `docker compose down -v` irreversibly removes packages and Caddy certificate state. Do not scale the API above one replica. Rotate the admin password by changing `.env` and recreating the API container; loaded admin tabs must log in again. Audit records are sensitive personal data: disclose IP/time collection to users and choose retention/deployment practices appropriate to your jurisdiction.
