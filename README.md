# mTLS Bridge

mTLS Bridge lets Android apps that do not support client certificates talk to
servers protected by **mutual TLS** (mTLS). It runs a small local proxy on the
device: the app connects to it over plain HTTP, and the proxy forwards each
request to your server over TLS, authenticating with a client certificate whose
private key never leaves the Android Keystore.

Typical use: putting a self-hosted Jellyfin, Nextcloud or Home Assistant behind
a reverse proxy that requires a client certificate, and still using the
official mobile or TV apps.

- One APK for phones, tablets and **Android TV / Google TV**
- Client keys imported from a `.p12` into the **Android Keystore** (TEE or
  StrongBox when available), non-exportable
- Server CA **pinning** for every configuration
- **Remote configuration console**: configure the device from a browser on the
  same network (handy on a TV)
- Deployment bundles for IT: one `.zip` with certificates and settings
- Core written in **Rust** (tokio, rustls); Android app in Kotlin / Jetpack
  Compose

## How it works

```
 target app ──HTTP──> mTLS Bridge (127.0.0.1:port) ──mTLS──> reverse proxy ──> service
                          │
                          └─ signs the TLS handshake with the Keystore key
```

Each configuration ties **one target app** to **one upstream server** with its
client certificate and pinned CA. Two modes are available:

| Mode | How the app reaches the proxy | Notes |
|------|-------------------------------|-------|
| **Loopback** (default) | `http://127.0.0.1:<port>/<token>/` | Works alongside any VPN. Isolated by a secret path token and a session cookie. |
| **VPN** | `http://192.0.2.x:<port>` through a local, per-app VpnService | Only the selected apps are routed; the OS enforces the isolation. Uses the device's single VPN slot. |

In loopback mode the proxy rewrites the upstream's absolute URLs (redirects,
JSON/HTML bodies, cookies) so that OAuth-style login flows keep going through
the bridge.

## Requirements

- Android 10 (API 29) or later; targets Android 16 (API 36), tested on
  Android 17 and on Google TV with 16 KB memory pages
- A server that accepts a client certificate signed by your CA, and that CA's
  certificate (PEM or DER) to pin

## Installation

Download the latest `mtls-bridge-<version>.apk` from the
[Releases](https://github.com/douxev/mTLS-Bridge/releases) page and install it
(allow installing from unknown sources when asked). A `.sha256` checksum is
published next to each APK:

```bash
sha256sum -c mtls-bridge-<version>.apk.sha256
```

On Android TV, install the APK with a file manager, `adb install`, or by
sideloading from a phone.

## Usage

1. **Create a configuration**: give it a name, pick the target app, enter the
   upstream host and port, import the client `.p12` and its passphrase, and the
   CA to pin. You can do this in the app or from the
   [remote console](#remote-configuration-console).
2. **Copy the client URL** shown in the configuration details (for example
   `http://127.0.0.1:18231/AbCd23EfGh45/`) and use it as the server address in
   the target app.
3. The proxy starts automatically while the configuration is enabled, and again
   after a reboot or an app update.

The configuration details screen shows recent events (bind, accepted
connections, rejected tokens, upstream errors) to help with troubleshooting.

### Remote configuration console

Typing hostnames and passphrases with a TV remote is painful, and many TVs have
no file picker. Open **Remote configuration** in the app menu: the device shows
an HTTPS address, a QR code and a one-time PIN. Open the address in a browser on
the same network, accept the self-signed certificate (check that its SHA-256
fingerprint matches the one displayed), enter the PIN, and manage
configurations, upload `.p12`/CA files or deployment bundles from there.

The console only runs while that screen is open and stops after 15 minutes of
inactivity. On Android 17 the app asks for the *Nearby devices* (local network)
permission, without which the browser cannot reach it.

### Deployment bundles

Administrators can prepare a `.zip` bundle containing one or more
configurations with their encrypted `.p12`, to be imported in one step. See
[`deployment-tools/`](deployment-tools/README.md) and
[`docs/deployment-bundle.md`](docs/deployment-bundle.md).

## Security

- Private keys are imported into the Android Keystore and cannot be exported;
  the Rust core asks the Keystore to sign the TLS handshake.
- The configuration database is encrypted with SQLCipher; its key is protected
  by the Keystore.
- The server certificate is validated against the pinned CA only.
- Loopback mode: any app on the device can reach `127.0.0.1`, so each
  configuration uses a secret path token (and a session cookie for web views).
  Requests without them are rejected before any connection to the upstream is
  made. VPN mode relies on per-app routing enforced by Android.
- Android cannot attribute loopback connections to an app (UID) unless the app
  is the active VPN, so the token is the isolation mechanism in loopback mode.

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

## Building from source

Requirements:

- Rust (stable, see `rust-toolchain.toml`) with the Android targets
  `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`
- [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk): `cargo install --locked cargo-ndk`
- Android SDK with platform 36, and NDK `27.2.12479018`
- JDK 21

```bash
# Rust core tests (host)
cargo test -p mtls-bridge-core

# Debug APK (builds the Rust core for the three ABIs and the Kotlin bindings)
cd android
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
./gradlew :app:assembleDebug
```

The APK is written to `android/app/build/outputs/apk/debug/`.

### Release builds

Release builds are signed with a key that is never stored in the repository.
Gradle reads the signing settings from environment variables
(`MTLS_KEYSTORE_FILE`, `MTLS_KEYSTORE_PASSWORD`, `MTLS_KEY_ALIAS`,
`MTLS_KEY_PASSWORD`) or, if they are not set, from
`~/keystores/mtls-bridge-release.properties`:

```properties
storeFile=/home/you/keystores/mtls-bridge-release.jks
storePassword=...
keyAlias=mtls-bridge
keyPassword=...
```

```bash
cd android && ./gradlew :app:assembleRelease
```

Pushing a `v*` tag runs the [Release workflow](.github/workflows/release.yml),
which builds the signed APK and attaches it, with its checksum, to a GitHub
Release. It needs the repository secrets `RELEASE_KEYSTORE_BASE64`,
`RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS` and `RELEASE_KEY_PASSWORD`.

## Project layout

```
core/               Rust core: proxy, HTTP rewriting, TLS, VPN netstack, FFI (uniffi)
android/            Android app (Kotlin, Jetpack Compose, Room + SQLCipher)
  app/src/main/assets/remote/   remote configuration console (HTML/JS/CSS)
deployment-tools/   bundle generator script and bundle format
docs/               threat model, deployment bundles, store listing
```

## License

The app and the Rust core are licensed under the
[Mozilla Public License 2.0](LICENSE). The scripts in `deployment-tools/` are
licensed under the [MIT License](deployment-tools/LICENSE).
