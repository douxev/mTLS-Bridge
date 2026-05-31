#!/usr/bin/env bash
# Example: generate one bundle with TWO configs (Jellyfin + Nextcloud) for
# the same employee, sharing a single passphrase.
#
# Run this from the repo root, after setting BACKEND_CA_CRT / BACKEND_CA_KEY.

set -euo pipefail

: "${BACKEND_CA_CRT:?set BACKEND_CA_CRT to your backend CA cert path}"
: "${BACKEND_CA_KEY:?set BACKEND_CA_KEY to your backend CA private key path}"

USER_NAME="${1:-alice}"
P12_PASSPHRASE="$(openssl rand -base64 24)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

emit_artifacts() {
  local cfg_id="$1" upstream_host="$2"

  openssl req -new -newkey rsa:3072 -nodes \
    -keyout "$WORK/${cfg_id}.key" \
    -out "$WORK/${cfg_id}.csr" \
    -subj "/CN=${USER_NAME}" 2>/dev/null
  openssl x509 -req -in "$WORK/${cfg_id}.csr" \
    -CA "$BACKEND_CA_CRT" -CAkey "$BACKEND_CA_KEY" -CAcreateserial \
    -days 365 \
    -out "$WORK/${cfg_id}-cert.pem" 2>/dev/null
  cp "$BACKEND_CA_CRT" "$WORK/${cfg_id}-ca.pem"
  openssl pkcs12 -export \
    -in "$WORK/${cfg_id}-cert.pem" \
    -inkey "$WORK/${cfg_id}.key" \
    -out "$WORK/${cfg_id}.p12" \
    -passout "pass:${P12_PASSPHRASE}"
  rm -f "$WORK/${cfg_id}.key" "$WORK/${cfg_id}.csr"
}

emit_artifacts "jellyfin-${USER_NAME}"   "media.example.com"
emit_artifacts "nextcloud-${USER_NAME}"  "cloud.example.com"

cat > "$WORK/configs.json" <<EOF
{
  "schema": 2,
  "exportedAtMs": $(date +%s)000,
  "configs": [
    {
      "id": "jellyfin-${USER_NAME}",
      "displayName": "Jellyfin",
      "targetPackage": "org.jellyfin.mobile",
      "upstreamHost": "media.example.com",
      "upstreamPort": 443,
      "sni": null,
      "keystoreAlias": "mtls_bridge-jellyfin-${USER_NAME}",
      "mode": "LOOPBACK",
      "syntheticIp": null,
      "syntheticPort": null,
      "loopbackPort": 0,
      "enabled": true,
      "certPemFile": "jellyfin-${USER_NAME}-cert.pem",
      "caPemFile": "jellyfin-${USER_NAME}-ca.pem",
      "p12File": "jellyfin-${USER_NAME}.p12"
    },
    {
      "id": "nextcloud-${USER_NAME}",
      "displayName": "Nextcloud",
      "targetPackage": "com.nextcloud.client",
      "upstreamHost": "cloud.example.com",
      "upstreamPort": 443,
      "sni": null,
      "keystoreAlias": "mtls_bridge-nextcloud-${USER_NAME}",
      "mode": "LOOPBACK",
      "syntheticIp": null,
      "syntheticPort": null,
      "loopbackPort": 0,
      "enabled": true,
      "certPemFile": "nextcloud-${USER_NAME}-cert.pem",
      "caPemFile": "nextcloud-${USER_NAME}-ca.pem",
      "p12File": "nextcloud-${USER_NAME}.p12"
    }
  ]
}
EOF

OUT="mtls_bridge-bundle-${USER_NAME}.zip"
( cd "$WORK" && zip -q "$OUT" ./* )
mv "$WORK/$OUT" "./$OUT"

echo "  ✓ bundle:     ./${OUT}"
echo "  ✓ passphrase: ${P12_PASSPHRASE}"
