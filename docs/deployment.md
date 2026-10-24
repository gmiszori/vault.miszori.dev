# Deployment

## Prerequisites

- A Linux host with kernel WireGuard and IPv4/IPv6 netfilter support.
- Docker Engine with Compose v2.
- A public domain, DNS control, and inbound TCP 80/443 plus a WireGuard UDP port.
- The shared [webserver-proxy](https://github.com/gmiszori/webserver-proxy) proxy, deployed first with `VAULT_DOMAIN` set to this domain. It owns host ports 80/443 and creates the external `webserver` network this stack joins.
- Sufficient disk space for ciphertext, audit metadata, and other host workloads.

WireGuard requires `NET_ADMIN` inside its container namespace, not privileged mode, host networking, a Docker socket, or `SYS_MODULE`. Install any missing kernel support on the host before deployment; the container fails closed if it is unavailable.

The Compose project is named `vault-miszori-dev`. Use fresh named volumes for an initial deployment, and check for port and subnet conflicts without modifying other projects. The default backend ranges are `172.30.0.0/25` and `172.30.0.128/25`; keep Docker, tunnel, host, and client LAN networks non-overlapping.

## 1. Configure DNS and ingress

Point the domain's A record to the server. Publish an AAAA record only after configuring IPv6 listeners and firewall rules; the supplied deployment binds IPv4 addresses.

| Interface | Port | Purpose |
| --- | --- | --- |
| Host `PUBLIC_BIND_IP` | TCP 80/443 | Public HTTPS, redirects, and ACME; published by the webserver proxy, which passes TLS through to public Caddy |
| Host `PUBLIC_BIND_IP` | UDP `WIREGUARD_PORT` (default 51821) | WireGuard transport; container port 51820 |
| Tunnel `VPN_BIND_IP` (default `10.13.13.1`) | TCP 80/443 | VPN-only admin HTTPS and redirect; no host-published TCP port |
| Docker backend networks | TCP 8080/8081 | Public/admin API listeners; no host-published ports |

If the server is behind NAT, forward these public ports to its local interface address. Do not publish extra admin TCP ports or forward the tunnel IP. Enforce ingress policy at the upstream firewall as well: Docker forwarding can bypass ordinary UFW rules.

## 2. Configure the environment

Create a private environment file from [`.env.example`](../.env.example) and generate an enrollment token:

```bash
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

| Variable | Configuration |
| --- | --- |
| `DOMAIN` | Public hostname; defaults to `vault.miszori.dev` |
| `ACME_EMAIL` | Email for public certificate issuance |
| `PUBLIC_BIND_IP` | A specific IPv4 address assigned to the host; use its LAN address behind NAT, never `0.0.0.0` or the router's external address |
| `ADMIN_SETUP_TOKEN` | Generated one-time enrollment token, at least 32 characters; **not** the admin password |
| `ADMIN_USER` | Single administrator username; defaults to `admin` |
| `WIREGUARD_ENDPOINT` | Public DNS name or IP, without a scheme or port |
| `WIREGUARD_PORT` | Public UDP port; defaults to `51821`; must match firewall/NAT rules |
| `WIREGUARD_PEERS` | Distinct comma-separated alphanumeric device names; defaults to `admin`, for example `laptop,phone` |
| `WIREGUARD_SUBNET` | Non-overlapping IPv4 `/24`; defaults to `10.13.13.0/24` |
| `VPN_BIND_IP` | Server address inside that tunnel; defaults to `10.13.13.1`; do not assign it to the host |

No host VPN interface, extra VPN service, hosts-file entry, or DNS override is required. For storage and admission settings, see [Resource controls](security.md#resource-controls).

## 3. Start the services

```bash
docker compose config --quiet
docker compose up --build -d --wait
docker compose logs --tail=30 wireguard api caddy caddy-vpn
```

WireGuard generates persistent device identities. The VPN proxy waits for tunnel health before binding. Public Caddy obtains an ACME certificate using the configured domain and inbound access; VPN Caddy uses a separate internal certificate authority for the private tunnel address.

## 4. Enroll an admin device

Export the device profile through a trusted local channel. Replace `admin` with the configured peer name if needed.

```bash
install -d -m 700 ./vpn-export
docker compose cp wireguard:/config/peers/admin/admin.conf ./vpn-export/admin.conf
chmod 600 ./vpn-export/*
```

Import the profile into the official WireGuard client and activate the tunnel. HTTPS remains mandatory inside the VPN for WebCrypto and Service Workers; do not disable secure-context checks.

Each profile contains a private key. Use one profile per device; never commit, publish, or paste it into chat. Delete exported copies after secure transfer. The default profile routes only `10.13.13.1/32`; other device traffic is unchanged, and server-side rules block forwarding to the LAN, Internet, Docker networks, and other peers.

## 5. Set up the administrator

Open **https://10.13.13.1/admin** through the tunnel, or substitute the configured `VPN_BIND_IP`. Enter the setup token and choose a different, strong password of 16–1,024 Unicode characters. The browser derives separate authentication, name-encryption, and activity-key wrapping keys, and enrolls the activity key pair; the password itself is not sent to the API.

Enrollment is one-time. The setup token cannot reset an enrolled password and may be removed from the environment after enrollment. Preserve the `packages` volume, including `auth.json`, `label-salt`, and `audit-key.json`. Subsequent sign-ins use the chosen password. This is a single-admin application; WireGuard device authentication is not MFA.

The public `/` serves a homepage that explains how a package is encrypted and shared, and the VPN `/` redirects to `/admin`. Recipients use generated package URLs.

## 6. Verify access boundaries

```bash
docker compose ps
docker compose exec wireguard wg show wg0
```

A connected device should show a recent handshake. Verify that:

- Outside the VPN, public `/admin`, `/admin/api/packages`, and `/api/admin/packages` return 404, and the tunnel admin URL is unreachable.
- Through the VPN, the admin page loads over trusted HTTPS and sign-in works.
- Public recipients can retrieve a test package without WireGuard.

Container health confirms local service readiness, not remote reachability. If no handshake appears, check endpoint DNS, UDP ports, firewalls, and NAT. If the tunnel connects but administration fails, check peer routes, subnet overlap, and VPN Caddy logs.
