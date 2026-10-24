# Operations and maintenance

## Apply updates

Review code, image, and configuration updates before applying them. Retain named volumes:

```bash
git pull --ff-only
docker compose pull
docker compose up --build -d --wait

# Explicitly apply proxy configuration changes when needed
docker compose up -d --force-recreate caddy caddy-vpn
```

Check public retrieval and VPN admin access end to end after updates and host reboots. Keep exactly one API replica, monitor disk headroom, and investigate cleanup errors promptly.

## Manage VPN devices and recover admin access

For peer additions/removals, endpoint changes, or UDP-port changes, edit the environment, adjust firewall/NAT rules as needed, and recreate **both** namespace-sharing services:

```bash
docker compose up -d --force-recreate --wait wireguard caddy-vpn
```

**Independent WireGuard restarts require proxy recovery.** When `wireguard` restarts independently, including after a crash, Docker gives it a new network namespace. A running `caddy-vpn` can remain in the old namespace, breaking admin access even when WireGuard is healthy. Compose's `depends_on.restart` does not cover automatic container restarts. Recreate both services with the command above, reconnect the client, and verify admin HTTPS. Public downloads are unaffected; no Docker-socket-based auto-healer is provided.

Re-export changed profiles through a trusted channel; imported profiles do not update themselves. To revoke a device, remove its name from `WIREGUARD_PEERS` and recreate both services. Keys and address reservations persist across removal/reordering, so re-adding a name re-enables its old identity. Use a **new peer name** when replacing a lost or compromised device. A maximum of 253 addresses can be reserved; removed reservations are not reused.

Tunnel subnet/server-address changes require a new WireGuard configuration volume and device re-enrollment. Preserve identity and VPN CA volumes during normal maintenance; deleting them changes device identities and the VPN certificate. Never publish profiles or server/CA private keys.

## Preserve and remove data

Restarting discards incomplete uploads and interrupted one-time claims. Ready, unexpired packages survive; reusable downloads can restart from the beginning. Audit metadata persists independently of ciphertext until its retention deadline.

`docker compose down` preserves named volumes. **`docker compose down -v` irreversibly removes packages, enrollment, audits, certificates, and VPN keys.** Do not use it for routine production maintenance.

## Administrator re-enrollment

There is no online password change/reset flow. Changing environment variables does not change an enrolled password or its name key.

Deliberate offline re-enrollment requires stopping the API, removing `auth.json` and `audit-key.json`, preserving `label-salt`, and supplying a new setup token. The API refuses to start with `audit-key.json` but no `auth.json`, because the new password could not unwrap it. A different password cannot decrypt previous private names or retrieval activity; existing package share links use independent keys and remain unaffected. Protect audit records as sensitive personal data and disclose their collection and retention.
