# Play Store listing — mTLS Bridge (EN)

## App name (50 chars max)

mTLS Bridge — mTLS wrapper for self-hosted apps

## Short description (80 chars max)

Add mTLS to any client app without modifying it. Hardware-backed key. Local-only.

## Full description (4000 chars max)

mTLS Bridge is a local mTLS (mutual TLS) proxy for Android. It lets you connect
official client apps (Jellyfin, Nextcloud, Home Assistant, custom dashboards…)
to a self-hosted backend that requires client-certificate authentication —
without modifying the client app.

You point your app at a local URL like `http://127.0.0.1:34521`. mTLS Bridge
intercepts the request, wraps it in TLS using your client certificate, and
forwards it to your real backend. Your client app sees a normal HTTP server
on localhost; your backend sees a properly authenticated mTLS connection.

### Why mTLS Bridge?

Most self-hosted backends behind a reverse proxy (Caddy, Nginx, Traefik) can
require client certificates for an extra layer of authentication. But official
mobile apps rarely support mTLS — leaving you stuck between security and
usability. mTLS Bridge closes that gap, transparently for the app.

### Key features

• **Hardware-backed key storage.** Your private key is imported once into
  Android Keystore (StrongBox / TEE when available) and never leaves the
  device. Even mTLS Bridge itself can only request signatures, never read the
  key material.

• **Per-app isolation.** Each configuration has its own local port and is
  protected by a strict UID check: only the configured target app can
  connect to its proxy. Other apps are rejected at accept-time, fail-closed.

• **Always-on loopback proxies.** Add a config once, it runs in the
  background indefinitely with negligible battery impact (epoll-driven,
  zero CPU at rest). Toggle on/off per config.

• **VPN mode** for the rare app that refuses a localhost URL. Per-app
  allow-list enforced by the OS kernel.

• **Encrypted at rest.** All configs and audit logs in an AES-256-GCM
  SQLCipher database, passphrase wrapped by a hardware-backed master key.

• **Audit log per config.** See exactly which app connected when, with
  what UID, and what events fired (rejected connections, bridge errors).
  Automatic 7-day rolling purge.

• **Deployment bundles for IT admins.** Generate a `.zip` from a bash +
  openssl script and distribute it to employees. One click + passphrase
  = full setup. The format is documented and reproducible.

• **Personal backup / restore.** Export your configs (without the private
  key) to a portable `.zip` to migrate between devices.

### Compatibility

• Android 10 (API 29) or higher.
• Works with any backend that does mTLS over HTTPS.
• Tested with Jellyfin and Nextcloud official Android clients behind
  Caddy / Nginx reverse proxies.

### Privacy

mTLS Bridge doesn't phone home, doesn't include analytics or trackers, and
doesn't connect to any server you didn't configure. It needs INTERNET
permission to reach your backend, NETWORK_STATE for connection-owner
lookup, and FOREGROUND_SERVICE to maintain the proxies in background.

### Open documentation and tooling

While the app itself is proprietary, the **deployment-bundle format is
documented and open** so IT admins can generate bundles from a simple
bash + openssl script, without ever installing the app on their build
server. See the public documentation repository for the format spec
and a reference script.

## Categories

Primary: Tools
Secondary: Productivity

## Keywords / tags (for ASO)

mTLS, mutual TLS, client certificate, reverse proxy, self-hosted,
Jellyfin, Nextcloud, Home Assistant, VPN, network, security, sysadmin,
proxy, mTLS proxy, mTLS wrapper, mTLS Android, mTLS client

## Content rating

Everyone (no UGC, no ads, no inappropriate content)

## Required permissions and justifications

• **INTERNET** — to relay requests to your configured backend.
• **ACCESS_NETWORK_STATE** — used by `ConnectivityManager.getConnectionOwnerUid`
  to validate that connections to local proxies come from the registered
  target app (UID check, defense in depth).
• **CHANGE_NETWORK_STATE** — required by Android 14+ to use
  `foregroundServiceType="connectedDevice"` for the proxy services.
• **FOREGROUND_SERVICE** + **FOREGROUND_SERVICE_CONNECTED_DEVICE** —
  to keep the loopback / VPN proxies alive in background with a persistent
  notification.
• **POST_NOTIFICATIONS** (Android 13+) — for the persistent service
  notification, which exposes a Stop button.
• **QUERY_ALL_PACKAGES** — to populate the target-app picker in the
  config form. Used at config-creation time only.
• **BIND_VPN_SERVICE** — only requested if you choose VPN mode (rare).

## Data safety form (Play Console)

• Data collected: none.
• Data shared: none.
• Data encrypted in transit: yes (mTLS).
• Data encrypted at rest: yes (SQLCipher AES-256-GCM + Android Keystore).
• User can request deletion: not applicable (no data sent off-device).

## Screenshots (titles)

1. "Add an mTLS-protected app in three taps"
2. "One proxy per app, isolated by UID"
3. "Hardware-backed key — visible in the security badge"
4. "Built-in deployment for sysadmins"
5. "Real-time audit log, per config"
6. "Open and use your app — it just works"
