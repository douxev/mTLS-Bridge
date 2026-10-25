package com.douxev.mtls_bridge.ui.help

/**
 * Bash script shown as is in the help screen: a short version of
 * `deployment-tools/bundle-generator.sh` (loopback mode only), duplicated
 * from `docs/deployment-bundle.md` so the APK stays self-contained.
 * When changing the bundle format (ConfigBackup.SCHEMA_VERSION) or the full
 * generator, keep the three files in sync.
 */
internal val DEPLOYMENT_SCRIPT_BASH: String = """#!/usr/bin/env bash
# Bundle generator for mTLS Bridge: short version, loopback mode.
# Full version (VPN mode, SNI, parameter validation):
# deployment-tools/bundle-generator.sh. Format: docs/deployment-bundle.md
set -euo pipefail

: "${'$'}{USER:=${'$'}(id -un)}"            # missing in some containers

# === To be adapted by the admin ====================
CONFIG_ID="jellyfin-${'$'}USER"        # [A-Za-z0-9._-]: zip file name
DISPLAY_NAME="Jellyfin"
TARGET_PKG="org.jellyfin.mobile"
UPSTREAM_HOST="media.example.com"
UPSTREAM_PORT=443
BACKEND_CA_CRT="backend-ca.crt"   # CA that signs the client certs
BACKEND_CA_KEY="backend-ca.key"
# ===================================================

[[ ${'$'}CONFIG_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*${'$'} ]] || { echo "invalid CONFIG_ID" >&2; exit 1; }
[[ ${'$'}UPSTREAM_PORT =~ ^[1-9][0-9]{0,4}${'$'} ]] && (( UPSTREAM_PORT <= 65535 )) \
  || { echo "invalid UPSTREAM_PORT" >&2; exit 1; }

# Fixed loopback port, drawn from 10001..32767 like the app does: the URL
# pasted into the target app stays valid when the proxy restarts.
LOOPBACK_PORT=${'$'}(( 10001 + ((RANDOM << 15) | RANDOM) % 22767 ))

# Path token (enabled by default): isolates the proxy from the other apps on
# the phone. 12 characters, same alphabet as the app (no 0/O nor 1/l/I).
gen_path_token() {
  local alphabet='ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
  local out='' b
  while (( ${'$'}{#out} < 12 )); do
    for b in ${'$'}(od -An -N32 -tu1 /dev/urandom); do
      (( b < 216 )) && out+=${'$'}{alphabet:b%54:1}
      (( ${'$'}{#out} == 12 )) && break
    done
  done
  printf '%s' "${'$'}out"
}
PATH_TOKEN="${'$'}(gen_path_token)"

# JSON string: quotes, backslashes and control characters escaped.
json_str() {
  local s=${'$'}1 out='' c i
  for (( i = 0; i < ${'$'}{#s}; i++ )); do
    c=${'$'}{s:i:1}
    case ${'$'}c in
      '"')         out+='\"' ;;
      '\')         out+='\\' ;;
      [[:cntrl:]]) printf -v c '\\u%04x' "'${'$'}c"; out+=${'$'}c ;;
      *)           out+=${'$'}c ;;
    esac
  done
  printf '"%s"' "${'$'}out"
}

P12_PASSPHRASE="${'$'}(openssl rand -base64 32)"   # to be sent out of band
WORK=${'$'}(mktemp -d)
trap 'rm -rf "${'$'}WORK"' EXIT
BUNDLE="${'$'}WORK/bundle"                          # zip contents, nothing else
mkdir "${'$'}BUNDLE"

# Client key + signature by the backend CA
openssl req -new -newkey rsa:3072 -nodes \
  -keyout "${'$'}WORK/client.key" -out "${'$'}WORK/client.csr" \
  -subj "/CN=${'$'}USER" 2>/dev/null
openssl x509 -req -in "${'$'}WORK/client.csr" \
  -CA "${'$'}BACKEND_CA_CRT" -CAkey "${'$'}BACKEND_CA_KEY" -CAcreateserial \
  -days 365 -out "${'$'}BUNDLE/${'$'}CONFIG_ID-cert.pem" 2>/dev/null
cp "${'$'}BACKEND_CA_CRT" "${'$'}BUNDLE/${'$'}CONFIG_ID-ca.pem"

# PKCS#12: passphrase passed through openssl's environment only (env:),
# never as an argument (readable by everyone via ps / /proc/<pid>/cmdline).
P12_PASSPHRASE="${'$'}P12_PASSPHRASE" openssl pkcs12 -export \
  -in "${'$'}BUNDLE/${'$'}CONFIG_ID-cert.pem" -inkey "${'$'}WORK/client.key" \
  -out "${'$'}BUNDLE/${'$'}CONFIG_ID.p12" -passout env:P12_PASSPHRASE
rm -f "${'$'}WORK/client.key" "${'$'}WORK/client.csr"   # plaintext key

# Manifest (schema v2)
cat > "${'$'}BUNDLE/configs.json" <<EOF
{
  "schema": 2,
  "exportedAtMs": ${'$'}(date +%s)000,
  "configs": [{
    "id": ${'$'}(json_str "${'$'}CONFIG_ID"),
    "displayName": ${'$'}(json_str "${'$'}DISPLAY_NAME"),
    "targetPackage": ${'$'}(json_str "${'$'}TARGET_PKG"),
    "upstreamHost": ${'$'}(json_str "${'$'}UPSTREAM_HOST"),
    "upstreamPort": ${'$'}UPSTREAM_PORT,
    "sni": null,
    "keystoreAlias": ${'$'}(json_str "mtls_bridge-${'$'}CONFIG_ID"),
    "mode": "LOOPBACK",
    "syntheticIp": null,
    "syntheticPort": null,
    "loopbackPort": ${'$'}LOOPBACK_PORT,
    "enabled": true,
    "certPemFile": ${'$'}(json_str "${'$'}CONFIG_ID-cert.pem"),
    "caPemFile": ${'$'}(json_str "${'$'}CONFIG_ID-ca.pem"),
    "p12File": ${'$'}(json_str "${'$'}CONFIG_ID.p12"),
    "pathToken": ${'$'}(json_str "${'$'}PATH_TOKEN")
  }]
}
EOF

# Final zip: entries at the root, without the uid/gid of the admin's machine.
zip -q -j -X "${'$'}WORK/bundle.zip" "${'$'}BUNDLE"/*
mv -f "${'$'}WORK/bundle.zip" ./mtls-bridge-bundle.zip

echo "Bundle ready: ./mtls-bridge-bundle.zip"
echo "Passphrase to send out of band: ${'$'}P12_PASSPHRASE"
echo "URL to paste into the target app: http://127.0.0.1:${'$'}LOOPBACK_PORT/${'$'}PATH_TOKEN/"
"""
