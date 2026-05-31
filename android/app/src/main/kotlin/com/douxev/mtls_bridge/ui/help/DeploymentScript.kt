package com.douxev.mtls_bridge.ui.help

/**
 * Script bash exposé tel quel dans l'écran d'aide. Dupliqué depuis
 * `docs/deployment-bundle.md` pour rester self-contained dans l'APK.
 * Quand on touche au format du bundle (ConfigBackup.SCHEMA_VERSION),
 * synchroniser les deux fichiers.
 */
internal val DEPLOYMENT_SCRIPT_BASH: String = """#!/usr/bin/env bash
set -euo pipefail

# Bundle generator pour mTLS Bridge — voir docs/deployment-bundle.md

BUNDLE_DIR=${'$'}(mktemp -d)
trap "rm -rf ${'$'}BUNDLE_DIR" EXIT

# === À adapter par l'admin =========================
CONFIG_ID="jellyfin-${'$'}USER"
DISPLAY_NAME="Jellyfin"
TARGET_PKG="org.jellyfin.mobile"
UPSTREAM_HOST="media.example.com"
UPSTREAM_PORT=443
BACKEND_CA_CRT="backend-ca.crt"   # CA qui signe les certs clients
BACKEND_CA_KEY="backend-ca.key"
# ===================================================

P12_PASSPHRASE="${'$'}(openssl rand -base64 32)"

# Génération clé client + signature par la CA backend
openssl req -new -newkey rsa:3072 -nodes \
  -keyout ${'$'}BUNDLE_DIR/client.key \
  -out ${'$'}BUNDLE_DIR/client.csr \
  -subj "/CN=${'$'}USER"
openssl x509 -req -in ${'$'}BUNDLE_DIR/client.csr \
  -CA ${'$'}BACKEND_CA_CRT -CAkey ${'$'}BACKEND_CA_KEY -CAcreateserial \
  -days 365 \
  -out ${'$'}BUNDLE_DIR/${'$'}{CONFIG_ID}-cert.pem
cp ${'$'}BACKEND_CA_CRT ${'$'}BUNDLE_DIR/${'$'}{CONFIG_ID}-ca.pem
openssl pkcs12 -export \
  -in ${'$'}BUNDLE_DIR/${'$'}{CONFIG_ID}-cert.pem \
  -inkey ${'$'}BUNDLE_DIR/client.key \
  -out ${'$'}BUNDLE_DIR/${'$'}{CONFIG_ID}.p12 \
  -passout pass:"${'$'}P12_PASSPHRASE"

# Manifest
cat > ${'$'}BUNDLE_DIR/configs.json <<EOF
{
  "schema": 2,
  "exportedAtMs": ${'$'}(date +%s)000,
  "configs": [{
    "id": "${'$'}CONFIG_ID",
    "displayName": "${'$'}DISPLAY_NAME",
    "targetPackage": "${'$'}TARGET_PKG",
    "upstreamHost": "${'$'}UPSTREAM_HOST",
    "upstreamPort": ${'$'}UPSTREAM_PORT,
    "sni": null,
    "keystoreAlias": "mtls_bridge-${'$'}CONFIG_ID",
    "mode": "LOOPBACK",
    "syntheticIp": null,
    "syntheticPort": null,
    "loopbackPort": 0,
    "enabled": true,
    "certPemFile": "${'$'}{CONFIG_ID}-cert.pem",
    "caPemFile": "${'$'}{CONFIG_ID}-ca.pem",
    "p12File": "${'$'}{CONFIG_ID}.p12"
  }]
}
EOF

# Nettoyage clé en clair
rm ${'$'}BUNDLE_DIR/client.key ${'$'}BUNDLE_DIR/client.csr

# Zip final
( cd ${'$'}BUNDLE_DIR && zip mtls-bridge-bundle.zip * )
mv ${'$'}BUNDLE_DIR/mtls-bridge-bundle.zip ./

echo "Bundle prêt : ./mtls-bridge-bundle.zip"
echo "Passphrase à transmettre hors-bande : ${'$'}P12_PASSPHRASE"
"""
