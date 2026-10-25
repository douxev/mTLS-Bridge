# Threat model — mTLS Bridge

This page describes the threat model of mTLS Bridge, the underlying
assumptions, the defenses in place and the accepted trade-offs. It reflects
the state of the code as of the latest commit.

## 1. Goals and non-goals

**Goals.** Let a user run an existing Android client app (Jellyfin,
Nextcloud, Home Assistant…) against a self-hosted backend that requires mTLS
authentication, **without modifying** the client app, and without exposing
the client private key to an attacker who has obtained app-level access to
the device.

**Non-goals.**
- Authenticating or attesting *the wrapper itself* to the backend.
- Preventing an attacker with root on the device from signing requests (root
  can always ask the Keystore to sign arbitrary data, even without extracting
  the key).
- Wrapping apps that do strict HTTPS to their real hostname (the wrapper does
  not do MITM; see §6).

## 2. Asset inventory

| Asset | Sensitivity |
|---|---|
| mTLS client private key (imported from a .p12) | **Critical** — carries the user's TLS identity |
| Client certificate chain + pinned upstream CA | Low (public certificates) |
| .p12 passphrase (entered in the UI) | High *temporarily* — used during import, then wiped |
| Stored configurations (name, host, port, mode) | Low (routing information) |
| Encrypted audit logs | Moderate (reveals usage) |
| Byte tunnel (plaintext HTTP on loopback ↔ HTTPS+mTLS upstream) | High (carries authenticated requests) |

## 3. Actors and capabilities

| Actor | Capability model |
|---|---|
| **Official client app** (Jellyfin Android, etc.) | Closed-source code. Considered honest but potentially chatty. Can send any HTTP request it wants to the backend once the session is established. |
| **Other, malicious app installed on the device** | Distinct Linux UID. Can try to connect to 127.0.0.1, scan ports, abuse public APIs. Has neither root nor access to mTLS Bridge's Keystore entries. |
| **Compromised self-hosted backend** | Out of scope for the wrapper. The user controls their own backend; if it is compromised, mTLS saves nothing. |
| **Network attacker (public Wi-Fi, MITM)** | Can observe and modify packets between the device and the backend. Blocked by TLS + CA pinning + mTLS. |
| **Compromised Android OS (root, system malware)** | Out of scope. Root can sign arbitrary data even without extracting the key. |
| **The mTLS Bridge wrapper itself** | Bounded by the hardware defenses: the key stays non-exportable in the TEE, and signing always goes through the Keystore. See §5. |

## 4. Attack surface and defenses per mode

### Loopback mode (recommended default)

```
Client app —http→ 127.0.0.1:N —Rust mTLS+TLS→ backend
```

- **Always-on per config**: `LoopbackProxyService` hosts one proxy per
  `enabled` config, started automatically by `LoopbackCoordinator`. Nothing
  is bound when `enabled=false`.
- **Fail-closed UID check on every accept**: we call
  `ConnectivityManager.getConnectionOwnerUid(IPPROTO_TCP, peer_local, peer_remote)`
  to resolve the peer's UID. If the UID differs from the registered app's
  (or the lookup returns `INVALID_UID`), the connection is dropped and
  `RejectedUidMismatch` / `RejectedUidUnknown` is logged.
- **One port per config**: each proxy has its own ephemeral or fixed port.
  The services are isolated at the process level (distinct Android services
  living in the same `LoopbackProxyService`).
- **Coexists with other VPNs** (WireGuard, Mullvad…): it does not take the
  device's single VPN slot.
- **Idle cost**: ≈ 0 — the `TcpListener` sleeps on `epoll`, no network
  parsing happens until a connection arrives.

### VPN mode (edge case)

```
Client app —http→ virtual tun (192.0.2.0/24) —smoltcp→ Rust mTLS+TLS —→ backend
```

- **OS-enforced isolation through `addAllowedApplication(pkg)`**: the
  Android kernel filters packets — only the listed apps can send into the
  tun. No other app on the device can reach the proxy.
- **Soft-fail UID check**: for two allow-listed apps in the same tun, we try
  to verify that a connection to a config's synthetic IP comes from the
  expected UID (cross-certificate leak). The `getConnectionOwnerUid` API does
  not support VPN-routed sockets on most Android kernels (it returns
  `INVALID_UID`), so we accept by default when the lookup fails and only
  reject an explicit mismatch. **Consequence**: if two apps are active at the
  same time in the same VPN, one can potentially use the other's certificate
  by targeting its synthetic IP. Mitigation: only allow apps you consider
  honest (the same rule as for any per-app VPN on Android).
- **Only one VPN at a time**: Android limitation.
- **Side effect**: all traffic of the allow-listed apps goes through our
  tun. Requests to other servers (image CDNs, analytics) enter the tun,
  match no synthetic route and are dropped. This breaks the target app's
  ancillary features.
- **Cost**: continuous — smoltcp parses every packet and the tokio runner
  loops as long as the VPN is running.

### Recommendation

**Loopback mode** is strictly better for isolation, battery and
compatibility with other VPNs, and has no functional drawback as long as the
target app accepts an `http://127.0.0.1:PORT` URL. This is the case for the
official Jellyfin and Nextcloud apps. VPN mode is only useful for an app that
explicitly refuses a localhost URL — a rare case in practice.

## 5. Hardware guarantees for the key

The .p12 key is imported into the Android Keystore through `setKeyEntry`. On
modern devices that support import into the TEE, the key is then
hardware-backed and **non-exportable**.

`KeyInfo.getSecurityLevel()` returns one of the following levels, **shown
truthfully to the user in the UI**:

- `STRONGBOX`: dedicated secure element (Pixel 3+, some Samsung devices).
- `TRUSTED_ENVIRONMENT`: TEE (ARM TrustZone) — nearly all Android 9+
  devices.
- `SOFTWARE`: no TEE available or non-compliant OEM — the key is only
  protected in software.

**Accepted limitation of the .p12 choice**: the key existed in clear on disk
(on the backend side or on the user's device) before the import. Google's
attestation chain therefore cannot provide the "this key was born in the TEE
and never existed anywhere else" guarantee that a generate-plus-CSR flow
would. Explicit trade-off: only .p12 import is supported because it is the
standard mTLS onboarding workflow.

## 6. Known limitations

- **Strict HTTPS in the target app**: if the app refuses to talk in
  plaintext (strict network-security-config), it cannot use the wrapper.
  The official Jellyfin and Nextcloud apps accept `http://` for their server
  configuration, which is the common case.
- **Cross-certificate leak in multi-app VPN mode**: see §4.
- **No protection against a malicious target app**: if the official client
  app decides to send harmful requests to the backend, the wrapper cannot
  detect them (it pipes bytes after rewriting the Host header). Mitigation:
  configure minimal permissions on the backend for the user tied to the
  client certificate. Optionally, application-level filters in the wrapper
  (allow-listed methods/paths) — not implemented.
- **Per-request HTTP/1.1 rewriting**: the `Host:` header of every keep-alive
  request is rewritten (Caddy/Nginx route by Host). If a request uses
  `Transfer-Encoding: chunked` for its body (rare for client requests), the
  proxy falls back to raw copy for the rest of the session, so subsequent
  requests are no longer rewritten. To be addressed when a real case shows
  up.

## 7. Additional defense-in-depth strategies

To be added by priority:

1. **Opt-in request filters** in the wrapper: allow-list of HTTP methods +
   path prefixes per config.
2. **Browsable audit + alerts**: already persisted in the encrypted DB; to
   be surfaced through notifications when a `RejectedUidMismatch` event
   occurs.
3. **Biometric gating**: require user authentication before the Keystore
   signs (`setUserAuthenticationRequired(true)`). Trade-off: adds friction
   to every session.
4. **Reproducible builds** + verifiable signatures for the wrapper.

## 8. Local storage

- **Configs**: SQLCipher (AES-256-GCM), random 32-byte passphrase stored in
  EncryptedSharedPreferences (non-exportable AES Keystore master key).
- **Audit logs**: same DB. Automatic purge at app startup through
  `LoopbackCoordinator` (7-day rolling window by default).
- **Android backup**: disabled through `android:allowBackup="false"` +
  `data_extraction_rules.xml` (excludes root/database/sharedpref).

## 9. Config export / import

To migrate between devices, the app provides a JSON export containing:
metadata (name, target app, host/port, SNI, mode, synthetic IP/loopback
port), the **client certificate chain (PEM)** and the **pinned upstream CA
(PEM)**.

**The private key is NOT exported** — this is deliberate (it is
non-exportable from the hardware Keystore). On import on the target device,
each config is flagged "key missing" and the user has to provide their .p12
again through the key import button on the config's detail screen.

The export file is not encrypted by mTLS Bridge: it contains (public)
certificates but no secrets. If the user wants to share it (cloud,
email…), it is their responsibility to use a secure channel.
