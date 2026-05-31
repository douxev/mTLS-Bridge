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
git clone https://github.com/<your-org>/mtls-bridge-deployment-tools.git
cd mtls-bridge-deployment-tools

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
# → mtls-bridge-bundle.zip + a random passphrase printed at end
```

Send the resulting `mtls-bridge-bundle.zip` to your user (email, MDM,
Drive…) and the **passphrase via a separate channel** (Signal, Matrix,
voice call). Never put them in the same message.

## What the user does

1. Installs **mTLS Bridge** from the Play Store.
2. Taps on the received `.zip` file.
3. Picks "mTLS Bridge" as the opener, or opens mTLS Bridge and chooses
   menu ⋮ → Importer.
4. Enters the passphrase you sent separately.
5. The config is imported, the private key is moved into Android
   Keystore (hardware-backed when supported), the proxy starts.
6. They open their target app (Jellyfin in the example) and use the
   loopback URL shown by mTLS Bridge (`http://127.0.0.1:34521`).

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

## Generating multiple bundles in one run

Loop over employees and call the script with different env vars per
user. Each bundle gets its own `CONFIG_ID` (typically `<service>-<user>`)
to avoid clashes on the device.

```bash
for user in alice bob charlie; do
  export CONFIG_ID="jellyfin-$user" CN="$user" \
         OUTPUT="bundles/${user}.zip" \
         P12_PASSPHRASE="$(openssl rand -base64 24)"
  ./bundle-generator.sh > "bundles/${user}.log"
done
```

(Each bundle has its own random passphrase printed in the log file.)

## Multi-config bundles

A single bundle can contain several configs (e.g., Jellyfin AND
Nextcloud for the same employee). All `.p12` files in the bundle
must share the **same passphrase** — the app prompts only once.

For the multi-config case, the script as shipped covers one config.
Multi-config is a 30-line extension : generate the artifacts in a loop
and emit a `configs.json` with multiple entries pointing at the
respective files. See `bundle-format.md` for the JSON schema.

## License

MIT.
