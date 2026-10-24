#!/usr/bin/env bash
# mTLS Bridge bundle generator
# https://github.com/<your-org>/mtls-bridge-deployment-tools
#
# Génère un fichier mtls-bridge-bundle.zip déployable que l'employé importe
# en un clic dans l'app mTLS Bridge Android.
#
# Generates a mtls-bridge-bundle.zip file that the employee imports with one
# tap in the mTLS Bridge Android app.

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

# Valeur JSON (RFC 8259) d'une chaîne : guillemets, antislash et caractères de
# contrôle échappés. Le reste (UTF-8 compris) passe tel quel.
json_str() {
  local s=$1 out='' c i
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    case $c in
      '"')         out+='\"' ;;
      '\')         out+='\\' ;;
      $'\n')       out+='\n' ;;
      $'\r')       out+='\r' ;;
      $'\t')       out+='\t' ;;
      [[:cntrl:]]) printf -v c '\\u%04x' "'$c"; out+=$c ;;
      *)           out+=$c ;;
    esac
  done
  printf '"%s"' "$out"
}

# Chaîne JSON, ou null si vide.
json_opt_str() {
  if [[ -n $1 ]]; then json_str "$1"; else printf 'null'; fi
}

# Token URL-safe, même alphabet sans ambiguïté que l'app (PathTokenGen) :
# pas de 0/O, 1/l/I. Tirage par rejet (octet < 216 = 4 × 54) pour rester
# uniforme. Pas de `tr </dev/urandom | head` : sous pipefail, le SIGPIPE de
# tr fait échouer tout le script.
gen_path_token() {
  local alphabet='ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
  local out='' b
  while (( ${#out} < 12 )); do
    for b in $(od -An -N32 -tu1 /dev/urandom); do
      (( b < 216 )) && out+=${alphabet:b%54:1}
      (( ${#out} == 12 )) && break
    done
  done
  printf '%s' "$out"
}

# Entier décimal dans [min, max], renvoyé sans zéros de tête (interdits en
# JSON).
check_int() {
  local name=$1 value=$2 min=$3 max=$4
  [[ $value =~ ^[0-9]{1,9}$ ]] && (( 10#$value >= min && 10#$value <= max )) \
    || die "$name must be an integer in $min..$max (got '$value')"
  printf '%d' "$(( 10#$value ))"
}

for cmd in openssl zip od; do
  command -v "$cmd" >/dev/null || die "'$cmd' is required"
done

# ============================================================================
# Configuration — adapt to your setup
# Configuration — à adapter
# ============================================================================
: "${USER:=$(id -un)}"                   # absent in some containers / CI
CONFIG_ID="${CONFIG_ID:-jellyfin-${USER}}"
DISPLAY_NAME="${DISPLAY_NAME:-Jellyfin}"
TARGET_PACKAGE="${TARGET_PACKAGE:-org.jellyfin.mobile}"
UPSTREAM_HOST="${UPSTREAM_HOST:-media.example.com}"
UPSTREAM_PORT="${UPSTREAM_PORT:-443}"
SNI="${SNI:-}"                           # leave empty to default to UPSTREAM_HOST
MODE="${MODE:-LOOPBACK}"                 # LOOPBACK or VPN
# Port loopback fixe : l'URL collée dans l'app cible doit survivre aux
# redémarrages du proxy. Tiré au hasard dans 10001..32767 comme le fait l'app
# (au-dessus des ports « registered » courants, sous la plage éphémère Linux).
# LOOPBACK_PORT=0 = port tiré par l'app à l'import (comme un port déjà pris
# sur le téléphone).
LOOPBACK_PORT="${LOOPBACK_PORT:-$(( 10001 + ((RANDOM << 15) | RANDOM) % 22767 ))}"
SYNTHETIC_IP="${SYNTHETIC_IP:-}"         # VPN only, e.g. "192.0.2.1"
SYNTHETIC_PORT="${SYNTHETIC_PORT:-}"     # VPN only
# Loopback only : token URL-safe à inclure dans le path HTTP pour isoler ce
# proxy des autres apps du device. Recommandé. Génère par défaut un token
# aléatoire de 12 chars d'alphabet sans ambiguïté. Set PATH_TOKEN_DISABLE=1
# pour désactiver complètement.
if [[ -z "${PATH_TOKEN:-}" && "${PATH_TOKEN_DISABLE:-0}" != "1" ]]; then
  PATH_TOKEN="$(gen_path_token)"
fi
PATH_TOKEN="${PATH_TOKEN:-}"

BACKEND_CA_CRT="${BACKEND_CA_CRT:-backend-ca.crt}"
BACKEND_CA_KEY="${BACKEND_CA_KEY:-backend-ca.key}"
CN="${CN:-${USER}}"                      # subject CN of the client cert
VALIDITY_DAYS="${VALIDITY_DAYS:-365}"
KEY_SIZE="${KEY_SIZE:-3072}"

OUTPUT="${OUTPUT:-mtls-bridge-bundle.zip}"  # may include a directory

# Random passphrase if not provided. Print at end. Transmit out of band.
P12_PASSPHRASE="${P12_PASSPHRASE:-$(openssl rand -base64 32)}"

# ============================================================================
# Sanity checks
# ============================================================================
for f in "$BACKEND_CA_CRT" "$BACKEND_CA_KEY"; do
  [[ -r "$f" ]] || die "$f not found / not readable"
done
case "$MODE" in
  LOOPBACK|VPN) ;;
  *) die "MODE must be LOOPBACK or VPN" ;;
esac
# Sert de nom de fichier dans le zip : pas de « / » ni de nom caché.
[[ $CONFIG_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || die "CONFIG_ID must match [A-Za-z0-9][A-Za-z0-9._-]* (got '$CONFIG_ID')"
UPSTREAM_PORT="$(check_int UPSTREAM_PORT "$UPSTREAM_PORT" 1 65535)"
VALIDITY_DAYS="$(check_int VALIDITY_DAYS "$VALIDITY_DAYS" 1 36500)"
KEY_SIZE="$(check_int KEY_SIZE "$KEY_SIZE" 2048 16384)"
if [[ "$MODE" == "LOOPBACK" ]]; then
  LOOPBACK_PORT="$(check_int LOOPBACK_PORT "$LOOPBACK_PORT" 0 65535)"
  # Une app Android ne peut pas écouter sous 1024.
  (( LOOPBACK_PORT == 0 || LOOPBACK_PORT >= 1024 )) \
    || die "LOOPBACK_PORT must be 0 or >= 1024 (got $LOOPBACK_PORT)"
  [[ -z $PATH_TOKEN || $PATH_TOKEN =~ ^[A-Za-z0-9._~-]+$ ]] \
    || die "PATH_TOKEN must only contain URL-safe characters [A-Za-z0-9._~-]"
fi
if [[ "$MODE" == "VPN" && -n "$SYNTHETIC_PORT" ]]; then
  SYNTHETIC_PORT="$(check_int SYNTHETIC_PORT "$SYNTHETIC_PORT" 1 65535)"
fi
[[ -d "$OUTPUT" ]] && die "OUTPUT must be a file path, '$OUTPUT' is a directory"

# ============================================================================
# Bundle generation
# ============================================================================
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BUNDLE="$WORK/bundle"                    # zip content, nothing else
mkdir "$BUNDLE"

# Client key + CSR + cert signed by backend CA
openssl req -new -newkey "rsa:${KEY_SIZE}" -nodes \
  -keyout "$WORK/client.key" \
  -out "$WORK/client.csr" \
  -subj "/CN=${CN}" 2>/dev/null
openssl x509 -req -in "$WORK/client.csr" \
  -CA "$BACKEND_CA_CRT" -CAkey "$BACKEND_CA_KEY" -CAcreateserial \
  -days "$VALIDITY_DAYS" \
  -out "$BUNDLE/${CONFIG_ID}-cert.pem" 2>/dev/null
cp "$BACKEND_CA_CRT" "$BUNDLE/${CONFIG_ID}-ca.pem"

# PKCS#12 (cert + key) protected by passphrase. Passée par l'environnement
# d'openssl seul (env:), pas en argument : la ligne de commande d'un process
# est lisible par tous via ps / /proc/<pid>/cmdline.
P12_PASSPHRASE="$P12_PASSPHRASE" openssl pkcs12 -export \
  -in "$BUNDLE/${CONFIG_ID}-cert.pem" \
  -inkey "$WORK/client.key" \
  -out "$BUNDLE/${CONFIG_ID}.p12" \
  -passout env:P12_PASSPHRASE

# Strip the cleartext key file before building the manifest
rm -f "$WORK/client.key" "$WORK/client.csr"

# Manifest (configs.json, schema v2)
synth_ip_json="null"
synth_port_json="null"
if [[ "$MODE" == "VPN" ]]; then
  synth_ip_json="$(json_opt_str "$SYNTHETIC_IP")"
  synth_port_json="${SYNTHETIC_PORT:-null}"
fi
loopback_port_json="null"
path_token_json="null"
if [[ "$MODE" == "LOOPBACK" ]]; then
  loopback_port_json="$LOOPBACK_PORT"
  path_token_json="$(json_opt_str "$PATH_TOKEN")"
fi

cat > "$BUNDLE/configs.json" <<EOF
{
  "schema": 2,
  "exportedAtMs": $(date +%s)000,
  "configs": [
    {
      "id": $(json_str "$CONFIG_ID"),
      "displayName": $(json_str "$DISPLAY_NAME"),
      "targetPackage": $(json_str "$TARGET_PACKAGE"),
      "upstreamHost": $(json_str "$UPSTREAM_HOST"),
      "upstreamPort": ${UPSTREAM_PORT},
      "sni": $(json_opt_str "$SNI"),
      "keystoreAlias": $(json_str "mtls_bridge-${CONFIG_ID}"),
      "mode": $(json_str "$MODE"),
      "syntheticIp": ${synth_ip_json},
      "syntheticPort": ${synth_port_json},
      "loopbackPort": ${loopback_port_json},
      "enabled": true,
      "certPemFile": $(json_str "${CONFIG_ID}-cert.pem"),
      "caPemFile": $(json_str "${CONFIG_ID}-ca.pem"),
      "p12File": $(json_str "${CONFIG_ID}.p12"),
      "pathToken": ${path_token_json}
    }
  ]
}
EOF

# Optional README inside the bundle
cat > "$BUNDLE/README.txt" <<EOF
mTLS Bridge deployment bundle (schema v2)
Generated $(date -Iseconds) by $(whoami)@$(hostname)

To import: open this .zip with the mTLS Bridge Android app (menu ⋮ → Importer).
The app will prompt for the PKCS#12 passphrase, then install everything.

After successful import, the original .p12 can be safely deleted.
EOF

# Final zip. -j : entrées à la racine du zip ; -X : sans uid/gid ni attributs
# étendus de la machine de l'admin.
zip -q -j -X "$WORK/bundle.zip" "$BUNDLE"/*
mkdir -p -- "$(dirname -- "$OUTPUT")"
mv -f -- "$WORK/bundle.zip" "$OUTPUT"

echo ""
echo "  ✓ bundle:     ${OUTPUT}"
echo "  ✓ passphrase: ${P12_PASSPHRASE}"
if [[ "$MODE" == "LOOPBACK" ]]; then
  if (( LOOPBACK_PORT == 0 )); then
    echo "  ! URL :       port tiré par l'app à l'import (LOOPBACK_PORT=0) —"
    echo "                visible dans le détail de la config dans l'app"
  else
    echo "  ✓ URL :       http://127.0.0.1:${LOOPBACK_PORT}/${PATH_TOKEN:+${PATH_TOKEN}/}"
    echo "                (à coller dans l'app cible après import — visible aussi"
    echo "                 dans le détail de la config dans l'app mTLS Bridge,"
    echo "                 qui fait foi si le port était déjà pris sur le téléphone)"
  fi
fi
echo ""
echo "Send the bundle and the passphrase to the employee through"
echo "SEPARATE channels (e.g., email + Signal). The passphrase must"
echo "NEVER ship in the same channel as the bundle."
