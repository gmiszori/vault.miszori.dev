# drive.miszori.dev

Private, client-encrypted, one-time file packages. Both pages use a minimal black interface with blue accents, branded `drive.miszori.dev`. Docker runs a small Go API and Caddy; the browser encrypts/decrypts with WebCrypto. No JavaScript frameworks, third-party scripts, analytics, database service, or build step for the web pages.

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
| Public-facing interface, TCP 80/443 | Package download pages, ACME certificate validation, public API |
| VPN interface `10.0.0.1`, TCP 80 | HTTPS redirect for non-root paths |
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

Put the generated **one-time enrollment token** in `ADMIN_SETUP_TOKEN` (at least 32 characters). This is not the admin password; choose a different password in the browser during first setup. Set `ACME_EMAIL`, `DOMAIN`, and `PUBLIC_BIND_IP` to a **specific local interface address**. If the server is behind NAT, use the host's LAN address, not the router's external address. Never use `0.0.0.0`: it conflicts with, and defeats the separation from, the VPN binding. `PUBLIC_BIND_IP` and `VPN_BIND_IP` must be different addresses.

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

Then visit `https://drive.miszori.dev/admin`. On first use, enter the setup token and choose/confirm a **different strong admin password** (16–1,024 Unicode characters). Username defaults to `admin`. The password is never sent to the server: the browser derives independent authentication and name-encryption keys. Later sign-ins use only that password and automatically unlock package names. The one-time token cannot replace or reset an enrolled password; remove `ADMIN_SETUP_TOKEN` from `.env` after enrollment if desired. Keep the data volume, including `auth.json` and `label-salt`.

All sessions and name keys stay in tab memory and are cleared on sign-out/leaving. Private API requests carry a derived authentication value over HTTPS, not the password. This is deliberately a single-admin VPN application, not a public identity/MFA provider. Both public and VPN `/` return an **empty 404**; there is no landing page. Use `/admin` explicitly.

6. Verify **from a device outside the VPN** that `/admin`, `/admin/api/packages`, and `/api/admin/packages` return 404. Public recipients must use public DNS, not the admin's private mapping.

Do not run the local test stack on a production host with this network already allocated.

## Using it

1. Log in on the VPN page; choose files or a folder and an expiry. Expiry starts when the package is created, **including upload time**; allow enough time for large transfers.
2. The browser creates a fresh encryption key, encrypts filenames and file bytes, and uploads encrypted records sequentially. Do not close the tab during upload. Failed uploads are removed when possible; interrupted uploads are discarded on server restart or expire normally.
3. Copy the generated link and send it over a trusted channel. The key is after `#`, **not** in the request path/query. Whoever has the whole link can claim the package. The admin cannot recover a link/key after losing it; recreate the package instead.
4. The recipient sees the warning and expiry, chooses a destination, then confirms the destructive transfer. Do not close/sleep the device during a large transfer. The page removes the fragment from the current address/history entry immediately after capturing it; the key remains only in page memory, so reloading requires reopening the original link.
5. The admin audit lists status, optional decrypted admin name, opening/claim time, request IP, and reported browser/OS/device type. A `consumed` status means the server completed its response, **not** proof the user successfully saved, extracted, or read the archive. `failed` includes aborted downloads and interrupted uploads.

### Private package names

Names are optional and **admin-only**. They unlock automatically at sign-in using a key derived from the admin password; there is no separate name passphrase or unlock panel. Name packages while uploading or use each package row's name controls to rename/remove labels. Neither the password nor the name key belongs in `.env` or server-side configuration. Sign-out, leaving the page, or an authentication failure clears the name key and displayed plaintext. Reloading requires signing in again.

The browser derives a 256-bit root with PBKDF2-SHA256, **600,000 iterations**, and the instance's persistent random 16-byte salt. HKDF-SHA256 then separates two independent values, using that salt and UTF-8 info `drive.miszori.dev:admin-auth:v1` (32-byte authentication value) versus `drive.miszori.dev:admin-names:v1` (non-extractable AES-256-GCM name key). Learning the authentication value does not reveal the root, password, or name key. The server stores only SHA-256 of the decoded authentication value in `auth.json`; that verifier itself cannot authenticate. A unique strong password is important because a stolen verifier/salt still permits expensive offline password guesses.

Every name uses a fresh random 12-byte IV, a 128-bit authentication tag, and AAD `drive.miszori.dev:admin-name:v1:<package-id>`. Only its version, IV, and ciphertext are stored. Names are absent from the file manifest, shared link, recipient page, ZIP filename, downloaded files, and preview metadata. Their approximate length can be inferred from ciphertext size.

The salt is stored as `label-salt`; preserve it and `auth.json` with package metadata. Losing the password makes existing names unrecoverable, **not** the package contents (those have independent share-link keys). This pre-deployment revision intentionally has no recovery/migration UI for names encrypted with the older separate-passphrase scheme; they appear unavailable until renamed. Old file packages and unnamed records remain compatible. Names stay encrypted in historical audit records through the existing retention period.

### Browser/device audit

Browser and device details are inferred **only when a package is explicitly claimed**, from the request's User-Agent and supplied low-entropy client hints. There is no canvas fingerprint, extra browser script, high-entropy client-hint request, geolocation, or device identifier. Unsupported profiles show unknown values. These headers can be absent or forged; they are diagnostic reports, **not reliable proof of identity**, precise hardware model, or physical location. Raw User-Agent text is bounded and shown only to the admin. Page visits and link-preview fetches do not create an opening record.

### Messaging previews

Public package HTML contains server-rendered Open Graph and Twitter-card metadata with only the generic title and a 1200×630 image. Description fields are empty, and the image contains only the folder icon/title—no subtitle or divider. A versioned image URL avoids reusing the previous artwork in newly fetched cards. Cards never include names, filenames, keys, package contents, recipient audit details, or even package-specific availability. Preview bots fetch only public HTML/image; those requests cannot consume the package. An explicit recipient download is still required.

No canonical or `og:url` replacement is emitted, so clients can retain the **original fragment-bearing link** rather than replacing it with a URL missing the decryption key. Actual preview rendering/caching depends on the messaging app; some apps disable previews or require a new message after changes. Generic artwork may remain in third-party preview caches after package deletion.

**Sharing the complete URL with a messaging provider also shares the key in the message text**, even though URL fragments are never sent in HTTP preview requests. Use a trusted/end-to-end-encrypted channel; generic previews do not make an untrusted messaging service safe. No real share link is submitted to any external preview/debugging service by this application.

Preview image URLs use Caddy's configured `PUBLIC_ORIGIN` (set automatically by Compose), not request headers or private VPN addresses. Regenerate the generic artwork with `python3 tools/generate-preview.py` if needed; this development-only command requires Pillow and does not run in production.

### Large downloads across browsers

A secure context, adequate free destination space, and a filesystem supporting files above 4 GiB (not FAT32) are required. Desktop Chrome/Edge's File System Access API is preferred. Other compatible browsers can stream through a **local same-origin Service Worker** into their native download mechanism, without buffering the entire ZIP in application memory. The worker's script may remain registered, but it never caches files, keys, or plaintext in browser storage.

Before claiming, the page verifies worker activation, control, MessageChannel communication, and a disposable synthetic-route probe. The actual ZIP then flows through a random, single-use `/local-download/<capability>` route using pull/ack backpressure; headers include the exact ZIP size after manifest decryption. Only plaintext ZIP bytes cross the local message channel—never the encryption key—and none are uploaded to the server. Other routes, including admin APIs and `/`, are not intercepted. Cancellation, errors, idle deadlines, and tab exit clean up sessions and abort the underlying claim. Worker updates do not force-replace active transfers.

**No web implementation can guarantee a 10–20 GiB save on every browser/device.** Safari/iOS, embedded/private browsers, storage policies, download restrictions, background suspension, and native OS limits vary. Keep the tab open and the device awake. If streaming is unavailable, a strict **128 MiB** Blob fallback remains. If worker preparation fails after the initial capability check, the first click stops **without claiming** and displays the size warning; renewed consent is required before accepting that fallback. Unsupported browsers show the warning from the outset. Unknown/large packages should only be accepted with working streaming support.

Folder selection includes files, but not empty folders. The application still cannot resume a claimed package or prove that the OS successfully saved the completed response.

## Encryption and storage protocol

1. A package gets an independent, random 256-bit ID from the server. A separate random upload token authorizes its upload; only its SHA-256 hash is persisted, and that hash is cleared when finalized. The VPN password is additionally required for upload operations.
2. The browser generates a **fresh random 256-bit AES key per package**. It must never reuse it for another upload.
3. Record 0 is an encrypted JSON manifest: `{version:1, files:[{path,size,lastModified}], chunkSize:8388608}`. Subsequent records contain each file's bytes, split at 8 MiB, in manifest order. Empty files need no data records.
4. Every record uses **AES-256-GCM** with its 128-bit authentication tag. Its 96-bit IV is four zero bytes followed by the record index as an unsigned 64-bit big-endian integer. Unique indices under a fresh package key prevent IV reuse. Additional authenticated data is UTF-8 `packageID:recordIndex`; changing record order, package ID, key, or ciphertext fails authentication. Failed/ambiguous uploads are aborted rather than re-encrypted with a reused IV.
5. The share link is `https://drive.miszori.dev/package/<256-bit-id>#<base64url-key>`. Browsers do not send fragments in HTTP requests. No key is sent to the API, stored in browser storage, or retained by the server.
6. A POST claim atomically changes `ready` to `consuming` and persists the time/IP and passive browser profile before returning any content. The binary response consists of repeated **4-byte big-endian ciphertext length + ciphertext** records. Each record is unlinked before it is streamed; remaining records are removed when the handler completes or fails. A crashed `consuming` package is purged at startup before serving requests. Multiple backend replicas are **not supported**: the in-process claim lock requires exactly one API instance.
7. The browser authenticates and decrypts every record and writes an uncompressed ZIP stream. CRC-32 checksums and data descriptors allow each file to be written without buffering it; ZIP64 records support sizes and offsets above 4 GiB. UTF-8 names preserve nested and Unicode paths. Only central-directory metadata is retained in memory, bounded by the manifest/file-count limits. Filename validation rejects unsafe traversal paths and duplicate names. CRC-32 is ZIP compatibility checking, not a security primitive: AES-GCM supplies authenticity. There is no trusted plaintext manifest on the server. Archive generation is entirely local, so existing encrypted packages also download as ZIP without migration.

The Docker `packages` volume stores one directory per package plus the public `label-salt` KDF salt and verifier-only `auth.json` at its root. Each package's `meta.json` contains ID, state, creation/expiry/opening times, request IP, bounded reported browser/device details, an optional encrypted-name envelope, ciphertext byte/record counts, and (only during upload) the token hash. Numbered `.bin` files contain ciphertext. Temporary writes are synced and atomically renamed. Metadata is retained until 90 days after the package's expiry, then removed. It never contains readable admin package names, original filenames, file contents, or decryption keys.

## Privacy boundaries and operational limits

**Client-side encryption is not a guarantee against a compromised server.** The server supplies the JavaScript; an attacker controlling it could serve modified code to steal future keys. Protect deployment credentials and dependencies, inspect changes, keep images patched, and consider independently distributed clients if that threat must be excluded. No external security audit has been performed.

- The server necessarily learns ciphertext size/record boundaries, upload/download timing, expiry, reported User-Agent/browser/OS/device details, and the network request IP (which may be a VPN/NAT/proxy address, not proof of a person's identity). Size patterns may reveal rough file counts and sizes. The one-time setup token exists in the initial API environment and must be protected from host/Docker administrators. The actual admin password never enters that environment or the API. Docker is isolation, not protection from a malicious host administrator.
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
│   ├── browser.go        Bounded passive browser/device header interpretation
│   ├── labels.go         Persistent KDF salt and encrypted-name validation
│   ├── auth.go           One-time enrollment and verifier-only login state
│   ├── main_test.go      Backend lifecycle, races, auth, failure/expiry tests
│   └── *_test.go         Browser, encrypted-label, retention and recovery tests
├── web/
│   ├── index.html        Package-only destructive-download page (root is 404)
│   ├── admin.html        VPN login/upload/audit page
│   ├── styles.css        Responsive UI; no remote fonts or assets
│   ├── admin.js          Upload UI and private API interaction
│   ├── public.js         Warning, one-time download, local archive saving
│   ├── crypto.js         Chunk encryption, manifest/path validation, framing
│   ├── zip.js            Bounded-memory ZIP/ZIP64 archive writer
│   ├── names.js          Authenticated admin-name envelope encryption
│   ├── auth.js           Password-to-auth/name key derivation
│   ├── download.js       Local worker-stream readiness and bounded sink
│   ├── download-worker.js Single-use synthetic ZIP download responses
│   ├── share-preview.png Generic public messaging-preview artwork
│   └── *.test.mjs        Browser-module protocol/archive/name/UI tests
├── tools/
│   └── generate-preview.py  Optional development-only PNG generator
├── tests/
│   ├── compose.yaml      Isolated loopback-only development/test stack
│   ├── Caddyfile         HTTP loopback test listeners (never deploy publicly)
│   ├── integration.test.mjs  Actual Caddy/API encryption/claim/large-transfer tests
│   ├── metadata.test.mjs Encrypted-name privacy, browser audit and preview tests
│   └── auth-helper.mjs   Independent test enrollment/key-derivation fixture
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
node --test tests/*.test.mjs

# Optional real 20 GiB transfer + ZIP64 CRC validation with Python 3:
# needs >21 GiB free Docker disk AND >21 GiB in the host temporary directory
LARGE_TEST_MIB=20480 node --test --test-name-pattern='optional large transfer' tests/integration.test.mjs

# Deletes ONLY the named test stack and its disposable data
docker compose -p drive-test -f tests/compose.yaml down -v
```

While the test stack is running, use a generated `http://localhost:18080/package/...#key` link for the public UI; the bare root intentionally returns an empty 404. Admin UI is `http://localhost:18081/admin`. Tests automatically enroll user `admin`, password `integration-admin-password-with-zero-server-knowledge`, using token `integration-setup-token-never-deploy-1234567890`. These test-only values are deliberately fixed and **must never be deployed**. For manual first-setup testing, use those same values before running the suite, or start with a new disposable test volume. Production certificate issuance, real VPN reachability, split DNS, firewall enforcement, and multiple real browser/OS combinations must be verified on the deployment server separately.

### Verification performed

An actual **20 GiB** package was AES-GCM encrypted, uploaded through Caddy to Docker storage, downloaded once, authenticated/decrypted record by record, and byte-compared successfully (about 195 seconds on the development machine). Sampled container memory during this transfer was approximately 24–28 MiB for the API and 20–26 MiB for Caddy; the transfer did not require buffering the package. This is a protocol/storage test, not a claim that every browser/device can save a 20 GiB archive. The production Caddy configuration was also exercised with a local TLS certificate and reduced container capabilities: public admin requests returned 404 while the separate private admin API returned 200 with credentials. Browser-module tests and the Go race detector/static checks passed. Docker integration tests verified concurrent one-time claims, tamper detection, IP spoof rejection, deletion, and a real 60-second expiry followed by background cleanup. Browser checks covered the responsive pages, real login/file/folder uploads, independent decryption of a browser-created package, fragment removal, and decrypted archive generation. The streaming UI path was exercised with a test writable destination; native OS Save dialogs and large-browser filesystem saves still need a real-device check.

The ZIP update was additionally tested with another **actual 20 GiB** encrypted round trip written to a streaming ZIP64 archive (about 212 seconds). Python's independent ZIP reader validated every entry CRC, a file above 4 GiB, subsequent entry offsets above 4 GiB, Unicode paths, and an empty file. The generated archive and ciphertext test data were cleaned up afterward. Regular ZIP headers, exact archive sizing, backpressure, and incomplete/sink-error handling are also covered by tests. A real browser-created Unicode-file package was uploaded, downloaded as ZIP, and independently checked with Python for original contents and CRC validity. Mobile admin and download pages were checked at 390 pixels wide with no horizontal page overflow; the audit table scrolls internally.

The private-metadata update passed 42 browser-module tests, nine Docker integration tests, and backend race/static checks. Browser testing verified black page/panel backgrounds, no mobile overflow, real encrypted-name upload, cleared passphrase inputs, and name removal after locking. The browser-created label was independently decrypted with Node and confirmed absent from server metadata and public HTML in plaintext. A real browser claim recorded Chrome/macOS/desktop; a Docker restart preserved the KDF salt, encrypted label, and audit. Preview bot requests returned rendered generic cards and valid PNG artwork without claiming or recording an opening.

The unified-login/portable-download revision passed **65 browser-module tests** and ten Docker integration tests, plus backend race/static checks. Real browser first-use enrollment succeeded; an independent Node derivation authenticated against that browser-created account and verified the stored file contains only the expected SHA-256 verifier, never the password, setup token, or authentication value. The UI automatically decrypted independently created names, displayed matching 1232px upload/audit panels in a 1280px viewport, and had a 0px header divider.

Service Worker registration/control/probe and an actual synthetic ZIP response were verified in an independent installed Chrome profile (HTTP 200, exact byte count, ZIP attachment headers). VS Code's integrated Electron browser stalled worker activation, so the safe fallback path was also exercised; this is why feature detection alone is not treated as successful streaming support. Native Save dialogs and Firefox/Safari/iOS large-file saves still need real-device verification; no universal browser guarantee is made.

## Maintenance

```bash
# Update/rebuild, preserving named volumes
docker compose pull
docker compose up --build -d --wait
# Rebind/reload updated Caddy routing (ZIP/names modules and preview templates)
docker compose up -d --force-recreate caddy
```

Restarting intentionally destroys incomplete uploads and interrupted downloads. Ready packages survive until consumed/expired/deleted. `docker compose down` preserves data; `docker compose down -v` irreversibly removes packages and Caddy certificate state. Do not scale the API above one replica. `ADMIN_PASSWORD` is no longer supported. Enrollment is one-time; changing `.env` does not change an enrolled password or its name key. There is no online password-reset/change flow. Deliberate offline re-enrollment requires stopping the API, removing only `auth.json`, preserving `label-salt`, and supplying a new setup token. Choosing a different password will not decrypt previous names; independent file share links remain unaffected. Audit records are sensitive personal data: disclose IP/time and browser/device-header collection to users and choose retention/deployment practices appropriate to your jurisdiction.
