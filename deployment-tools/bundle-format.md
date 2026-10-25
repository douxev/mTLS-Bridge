# mTLS Bridge bundle format — schema v2

An mTLS Bridge deployment bundle is a standard `.zip` archive. The mTLS Bridge
Android app reads it through the system Storage Access Framework.

## Top-level layout

```
mtls-bridge-bundle.zip
├── README.txt              # optional, plain text, informational only
├── configs.json            # required, the manifest
├── <id>-cert.pem           # per config, client certificate chain (PEM)
├── <id>-ca.pem             # per config, pinned upstream CA (PEM)
└── <id>.p12                # per config, optional PKCS#12 (cert + private key)
```

Filenames inside `<id>-...` use the `id` field from `configs.json` so the
manifest can reference them unambiguously.

## `configs.json`

The file itself is strict JSON (RFC 8259), UTF-8: no comments, and
strings escaped (`\"`, `\\`, control characters as `\n` or `\u00XX`).
The comments below are documentation only.

```jsonc
{
  "schema": 2,                          // integer, mandatory
  "exportedAtMs": 1717000000000,        // epoch millis, informational

  "configs": [                          // 1..N entries
    {
      "id": "jellyfin-alice",           // stable identifier, ASCII slug or UUID
      "displayName": "Jellyfin",        // shown in the app's list
      "targetPackage": "org.jellyfin.mobile",
                                        // Android package the proxy serves

      "upstreamHost": "media.example.com",
      "upstreamPort": 443,              // TCP port the wrapper connects to
      "sni": null,                      // optional override; null = use host

      "keystoreAlias": "mtls_bridge-jellyfin-alice",
                                        // alias under which the key is stored
                                        // in the device's Android Keystore;
                                        // convention "mtls_bridge-<id>"

      "mode": "LOOPBACK",               // "LOOPBACK" (recommended) or "VPN"

      // LOOPBACK fields ----------------------------------------------------
      "loopbackPort": 23817,            // fixed port, 10001..32767;
                                        // 0 or absent: drawn on import

      // VPN fields ---------------------------------------------------------
      "syntheticIp": null,              // e.g. "192.0.2.1" (TEST-NET)
      "syntheticPort": null,            // matching port

      "enabled": true,                  // start the proxy after import

      "certPemFile": "jellyfin-alice-cert.pem",
      "caPemFile":   "jellyfin-alice-ca.pem",
      "p12File":     "jellyfin-alice.p12",
                                        // OPTIONAL; presence triggers
                                        // immediate Keystore import
      "pathToken":   "Kx7P2mNqRtVy"
                                        // OPTIONAL, LOOPBACK only.
                                        // URL-safe secret. The proxy will
                                        // only accept requests whose path
                                        // starts with /<pathToken>/.
                                        // Effective URL =
                                        // http://127.0.0.1:LOOPBACK_PORT
                                        //   /<pathToken>/
    }
  ]
}
```

### Field reference

| field           | type    | required | notes |
|-----------------|---------|----------|-------|
| `schema`        | int     | yes      | must be `2` |
| `exportedAtMs`  | int     | no       | informational |
| `id`            | string  | yes      | stable, unique per device, ASCII recommended |
| `displayName`   | string  | yes      | unique per device |
| `targetPackage` | string  | yes      | unique per device, must be installed for the loopback UID check to resolve |
| `upstreamHost`  | string  | yes      | DNS name or IP |
| `upstreamPort`  | int     | yes      | 1..65535 |
| `sni`           | string? | no       | TLS SNI override; `null` = use `upstreamHost` |
| `keystoreAlias` | string  | yes      | Android Keystore alias to import the .p12 into |
| `mode`          | enum    | yes      | `"LOOPBACK"` or `"VPN"` |
| `loopbackPort`  | int?    | no       | LOOPBACK only; fixed port. Absent, `0`, out of range or already used on the device = drawn by the app on import — see below |
| `syntheticIp`   | string? | no       | VPN only; an IP from `192.0.2.0/24` (TEST-NET) is recommended |
| `syntheticPort` | int?    | no       | VPN only |
| `enabled`       | bool    | yes      | LOOPBACK: auto-start after import; ignored for VPN |
| `certPemFile`   | string  | yes      | zip-relative file name of the client cert chain |
| `caPemFile`     | string  | yes      | zip-relative file name of the pinned upstream CA |
| `p12File`       | string? | no       | zip-relative file name of the PKCS#12 — see below |
| `pathToken`     | string? | no       | LOOPBACK only. URL-safe secret (`[A-Za-z0-9]+` recommended, 12+ chars). Proxy validates `/<pathToken>/` prefix and strips it before forwarding — see below |

### `loopbackPort` semantics

The proxy listens on `127.0.0.1:<loopbackPort>`, and that URL is what the
user pastes into the target app, so it should not change:

- **Fixed port.** `bundle-generator.sh` draws one at random in
  `10001..32767`, like the app does when a config is created by hand:
  above the busy "registered" ports, below the Linux ephemeral range
  (`32768+`). Ports below 1024 cannot be bound by an Android app.
- **Reassigned on import** when absent, outside `1..65535` (`0`
  included), or already used by another loopback config on the device
  (or earlier in the same bundle): the app draws a free port in
  `10001..32767`. The URL printed by the generator is then stale; the
  one shown in the config details in the app is authoritative.

### `pathToken` semantics (loopback isolation)

When set, the proxy will:

- Accept only HTTP requests whose path starts with `/<pathToken>/` (or
  equals `/<pathToken>`), or that carry the proxy's session cookie (below).
- Strip the `/<pathToken>` prefix before forwarding to the upstream
  (so the upstream sees a regular relative path).
- Answer a request accepted through the prefix with a session cookie
  `Set-Cookie: mtlsb_<config id prefix>=<random secret>; HttpOnly;
  SameSite=Strict; Path=/`. Webviews (jellyfin-web, Nextcloud) that load
  absolute paths such as `/web/main.js` send it back and are accepted
  without the prefix. The secret only lives in memory and changes every
  time the proxy starts; `mtlsb_*` cookies are never forwarded upstream.
- Close the connection (fail-closed) on any request without the prefix or
  a valid cookie. The upstream connection (TCP + mTLS handshake, hence the
  Keystore signature) is only opened once the first request of a
  connection has passed this check.

The end user's URL in the target app is then
`http://127.0.0.1:LOOPBACK_PORT/<pathToken>/`. The mTLS Bridge UI
displays this URL with a copy button.

This is the **loopback-only isolation primitive** that replaces the
UID check (which the Android `ConnectivityManager.getConnectionOwnerUid`
API doesn't support reliably for non-VPN apps). With a 12-character
token from an unambiguous alphabet, an attacker app scanning the
random loopback port would still need to guess one of ~10²⁰
possibilities to hijack the proxy.

Omit `pathToken` to disable the check (URL stays plain
`http://127.0.0.1:LOOPBACK_PORT/`).

### `p12File` semantics

- **Present** → "deployment" bundle. On import, mTLS Bridge prompts once for
  the bundle passphrase (shared across all `.p12` in the bundle, by
  convention) and immediately imports each `.p12` into Android Keystore
  under its `keystoreAlias`. The config becomes operational right after.

- **Absent** → "personal backup" bundle. On import, the config is created
  in a "needs key refresh" state; the user must provide the matching
  `.p12` separately through the app's UI (the key import action on each
  config's detail screen).

### Cert chain validation

When `p12File` is present, the cert chain in the imported `.p12` must
match the `certPemFile` exactly (byte-equal). This prevents an attacker
from swapping the .p12 for a different cert + key while keeping the
metadata legitimate. The app rejects the config silently if the check
fails (logged in the audit DB).

## Why a single shared passphrase for multi-config?

The deployment scenario is "one IT admin generates N configs for one
employee". A single passphrase per bundle simplifies the flow — the
employee types it once. For higher security at the cost of UX, you can
ship one bundle per config, each with its own passphrase.

## Reserved file names

The app reads `configs.json` and `README.txt` from the zip. All other
file names should match what `configs.json` references — extra files are
ignored.

Future schema versions may use additional reserved names; treat the
zip as opaque beyond what's documented here.
