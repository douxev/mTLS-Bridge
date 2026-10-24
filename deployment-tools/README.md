# mTLS Bridge deployment tools

Tools to create [mTLS Bridge](https://github.com/<your-org>/mtls-bridge)
deployment bundles for distributing mTLS configurations + client
certificates to end users (typically employees of a small company
running self-hosted services behind a Caddy/Nginx/Traefik reverse
proxy with mutual-TLS authentication).

[🇫🇷 Version française](README.fr.md)

## What's in this repo

- `bundle-generator.sh` — generates one `mtls-bridge-bundle.zip` from a
  client CSR you sign with your backend CA. Pure bash + openssl + zip,
  no dependency on mTLS Bridge itself.
- `examples/` — example invocations.
- `bundle-format.md` — full specification of the zip format consumed
  by mTLS Bridge (schema v2).

## Quick start

```bash
git clone https://github.com/<your-org>/mTLS-Bridge-doc.git
cd mTLS-Bridge-doc

# Point the script at your backend CA (private key + cert)
export BACKEND_CA_CRT=/path/to/backend-ca.crt
export BACKEND_CA_KEY=/path/to/backend-ca.key

# Adapt the rest to your service
export CONFIG_ID=jellyfin-alice
export DISPLAY_NAME="Jellyfin"
export TARGET_PACKAGE=org.jellyfin.mobile
export UPSTREAM_HOST=media.example.com
export UPSTREAM_PORT=443
export CN=alice

./bundle-generator.sh
# → mtls-bridge-bundle.zip, plus the random passphrase and the loopback
#   URL printed at end
```

Send the resulting `mtls-bridge-bundle.zip` to your user (email, MDM,
Drive…) and the **passphrase via a separate channel** (Signal, Matrix,
voice call). Never put them in the same message.

## Settings

Every setting is an environment variable.

| Variable | Default | Notes |
|----------|---------|-------|
| `BACKEND_CA_CRT`, `BACKEND_CA_KEY` | `backend-ca.crt`, `backend-ca.key` | CA that signs the client certificate |
| `CONFIG_ID` | `jellyfin-$USER` | `[A-Za-z0-9][A-Za-z0-9._-]*`; also names the files inside the zip |
| `DISPLAY_NAME`, `TARGET_PACKAGE`, `UPSTREAM_HOST`, `SNI` | `Jellyfin`, `org.jellyfin.mobile`, `media.example.com`, empty | escaped in `configs.json`: quotes, backslashes, accents are fine. Empty `SNI` = use `UPSTREAM_HOST` |
| `UPSTREAM_PORT` | `443` | |
| `MODE` | `LOOPBACK` | `LOOPBACK` or `VPN` |
| `LOOPBACK_PORT` | random in 10001–32767 | Fixed port, drawn in the same range as the app does: the URL pasted in the target app stays valid when the proxy restarts. `0` = let the app draw one on import (the URL is then only shown in the app). Below 1024 is refused (an Android app can't listen there) |
| `PATH_TOKEN` | random, 12 chars | URL-safe (`[A-Za-z0-9._~-]`). `PATH_TOKEN_DISABLE=1` to leave it out |
| `SYNTHETIC_IP`, `SYNTHETIC_PORT` | empty | VPN only; when empty, the app picks a free pair on import |
| `CN`, `VALIDITY_DAYS`, `KEY_SIZE` | `$USER`, `365`, `3072` | client certificate |
| `OUTPUT` | `mtls-bridge-bundle.zip` | May contain a directory (`bundles/alice.zip`, an absolute path…), created if missing. An existing file is overwritten |
| `P12_PASSPHRASE` | random (`openssl rand -base64 32`) | protects the `.p12` |

## What the user does

1. Installs **mTLS Bridge** from the Play Store.
2. Taps on the received `.zip` file.
3. Picks "mTLS Bridge" as the opener, or opens mTLS Bridge and chooses
   menu ⋮ → Importer.
4. Enters the passphrase you sent separately.
5. The config is imported, the private key is moved into Android
   Keystore (hardware-backed when supported), the proxy starts.
6. They open their target app (Jellyfin in the example) and use the
   loopback URL printed by the script and shown by mTLS Bridge
   (`http://127.0.0.1:23817/Kx7P2mNqRtVy/`). The port is fixed, so this
   URL keeps working after the proxy restarts.

## Security properties

- The .p12 file is encrypted with the passphrase. AES-256 with modern
  openssl (≥3.0).
- Once imported into Android Keystore, the key becomes **non-exportable
  from the device**. mTLS Bridge itself can only request signatures
  through the Keystore — never read the key material.
- The `mtls-bridge-bundle.zip` and the passphrase **must travel through
  separate channels**. The bundle alone is useless without the
  passphrase ; the passphrase alone is useless without the bundle.
- The script never writes the cleartext client key to disk past the
  `.p12` packaging step; intermediate `.key` and `.csr` are deleted
  before the zip is built.
- The passphrase reaches openssl through its environment
  (`-passout env:`), never on its command line, which any local user
  can read with `ps`.

## Generating multiple bundles in one run

Loop over employees and call the script with different env vars per
user. Each bundle gets its own `CONFIG_ID` (typically `<service>-<user>`)
to avoid clashes on the device.

```bash
mkdir -p bundles   # needed by the log redirection below
for user in alice bob charlie; do
  export CONFIG_ID="jellyfin-$user" CN="$user" \
         OUTPUT="bundles/${user}.zip" \
         P12_PASSPHRASE="$(openssl rand -base64 24)"
  ./bundle-generator.sh > "bundles/${user}.log"
done
```

(Each bundle has its own random passphrase, loopback port and path
token, printed in its log file. The logs hold the passphrases in clear:
delete them once the passphrases are sent.)

## Multi-config bundles

A single bundle can contain several configs (e.g., Jellyfin AND
Nextcloud for the same employee). All `.p12` files in the bundle
must share the **same passphrase** — the app prompts only once.

For the multi-config case, the script as shipped covers one config.
Multi-config is a 30-line extension : generate the artifacts in a loop
and emit a `configs.json` with multiple entries pointing at the
respective files — `examples/multi-config.sh` does it for two configs.
A `loopbackPort` already used on the device (or by another config of the
bundle) is reassigned on import: the URL to paste is then the one shown
in the app. See `bundle-format.md` for the JSON schema.

## License

MIT.
