package com.douxev.mtls_bridge.ui.help

/**
 * Script bash exposé tel quel dans l'écran d'aide : version courte de
 * `deployment-tools/bundle-generator.sh` (mode loopback seul), dupliquée
 * depuis `docs/deployment-bundle.md` pour rester self-contained dans l'APK.
 * Quand on touche au format du bundle (ConfigBackup.SCHEMA_VERSION) ou au
 * générateur complet, synchroniser les trois fichiers.
 */
internal val DEPLOYMENT_SCRIPT_BASH: String = """#!/usr/bin/env bash
# Bundle generator pour mTLS Bridge — version courte, mode loopback.
# Version complète (mode VPN, SNI, contrôle des paramètres) :
# deployment-tools/bundle-generator.sh. Format : docs/deployment-bundle.md
set -euo pipefail

: "${'$'}{USER:=${'$'}(id -un)}"            # absent dans certains conteneurs

# === À adapter par l'admin =========================
CONFIG_ID="jellyfin-${'$'}USER"        # [A-Za-z0-9._-] : nom de fichier du zip
DISPLAY_NAME="Jellyfin"
TARGET_PKG="org.jellyfin.mobile"
UPSTREAM_HOST="media.example.com"
UPSTREAM_PORT=443
BACKEND_CA_CRT="backend-ca.crt"   # CA qui signe les certs clients
BACKEND_CA_KEY="backend-ca.key"
# ===================================================

[[ ${'$'}CONFIG_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*${'$'} ]] || { echo "CONFIG_ID invalide" >&2; exit 1; }
[[ ${'$'}UPSTREAM_PORT =~ ^[1-9][0-9]{0,4}${'$'} ]] && (( UPSTREAM_PORT <= 65535 )) \
  || { echo "UPSTREAM_PORT invalide" >&2; exit 1; }

# Port loopback fixe, tiré dans 10001..32767 comme le fait l'app : l'URL
# collée dans l'app cible reste valable quand le proxy redémarre.
LOOPBACK_PORT=${'$'}(( 10001 + ((RANDOM << 15) | RANDOM) % 22767 ))

# Token de path (activé par défaut) : isole le proxy des autres apps du
# téléphone. 12 caractères, même alphabet que l'app (ni 0/O ni 1/l/I).
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

# Chaîne JSON : guillemets, antislash et caractères de contrôle échappés.
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

P12_PASSPHRASE="${'$'}(openssl rand -base64 32)"   # à transmettre hors bande
WORK=${'$'}(mktemp -d)
trap 'rm -rf "${'$'}WORK"' EXIT
BUNDLE="${'$'}WORK/bundle"                          # contenu du zip, rien d'autre
mkdir "${'$'}BUNDLE"

# Clé client + signature par la CA backend
openssl req -new -newkey rsa:3072 -nodes \
  -keyout "${'$'}WORK/client.key" -out "${'$'}WORK/client.csr" \
  -subj "/CN=${'$'}USER" 2>/dev/null
openssl x509 -req -in "${'$'}WORK/client.csr" \
  -CA "${'$'}BACKEND_CA_CRT" -CAkey "${'$'}BACKEND_CA_KEY" -CAcreateserial \
  -days 365 -out "${'$'}BUNDLE/${'$'}CONFIG_ID-cert.pem" 2>/dev/null
cp "${'$'}BACKEND_CA_CRT" "${'$'}BUNDLE/${'$'}CONFIG_ID-ca.pem"

# PKCS#12 : passphrase passée par l'environnement d'openssl seul (env:),
# jamais en argument (lisible par tous via ps / /proc/<pid>/cmdline).
P12_PASSPHRASE="${'$'}P12_PASSPHRASE" openssl pkcs12 -export \
  -in "${'$'}BUNDLE/${'$'}CONFIG_ID-cert.pem" -inkey "${'$'}WORK/client.key" \
  -out "${'$'}BUNDLE/${'$'}CONFIG_ID.p12" -passout env:P12_PASSPHRASE
rm -f "${'$'}WORK/client.key" "${'$'}WORK/client.csr"   # clé en clair

# Manifest (schéma v2)
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

# Zip final : entrées à la racine, sans uid/gid de la machine de l'admin.
zip -q -j -X "${'$'}WORK/bundle.zip" "${'$'}BUNDLE"/*
mv -f "${'$'}WORK/bundle.zip" ./mtls-bridge-bundle.zip

echo "Bundle prêt : ./mtls-bridge-bundle.zip"
echo "Passphrase à transmettre hors bande : ${'$'}P12_PASSPHRASE"
echo "URL à coller dans l'app cible : http://127.0.0.1:${'$'}LOOPBACK_PORT/${'$'}PATH_TOKEN/"
"""
