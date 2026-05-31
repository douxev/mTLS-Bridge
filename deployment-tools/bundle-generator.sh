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

# ============================================================================
# Configuration — adapt to your setup
# Configuration — à adapter
# ============================================================================
CONFIG_ID="${CONFIG_ID:-jellyfin-${USER}}"
DISPLAY_NAME="${DISPLAY_NAME:-Jellyfin}"
TARGET_PACKAGE="${TARGET_PACKAGE:-org.jellyfin.mobile}"
UPSTREAM_HOST="${UPSTREAM_HOST:-media.example.com}"
UPSTREAM_PORT="${UPSTREAM_PORT:-443}"
SNI="${SNI:-}"                           # leave empty to default to UPSTREAM_HOST
MODE="${MODE:-LOOPBACK}"                 # LOOPBACK or VPN
LOOPBACK_PORT="${LOOPBACK_PORT:-0}"      # 0 = ephemeral (recommended)
SYNTHETIC_IP="${SYNTHETIC_IP:-}"         # VPN only, e.g. "192.0.2.1"
SYNTHETIC_PORT="${SYNTHETIC_PORT:-}"     # VPN only

BACKEND_CA_CRT="${BACKEND_CA_CRT:-backend-ca.crt}"
BACKEND_CA_KEY="${BACKEND_CA_KEY:-backend-ca.key}"
CN="${CN:-${USER}}"                      # subject CN of the client cert
VALIDITY_DAYS="${VALIDITY_DAYS:-365}"
KEY_SIZE="${KEY_SIZE:-3072}"

OUTPUT="${OUTPUT:-mtls-bridge-bundle.zip}"

# Random passphrase if not provided. Print at end. Transmit out of band.
P12_PASSPHRASE="${P12_PASSPHRASE:-$(openssl rand -base64 32)}"

# ============================================================================
# Sanity checks
# ============================================================================
for f in "$BACKEND_CA_CRT" "$BACKEND_CA_KEY"; do
  if [[ ! -r "$f" ]]; then
    echo "error: $f not found / not readable" >&2
    exit 1
  fi
done
case "$MODE" in
  LOOPBACK|VPN) ;;
  *) echo "error: MODE must be LOOPBACK or VPN" >&2; exit 1 ;;
esac

# ============================================================================
# Bundle generation
# ============================================================================
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Client key + CSR + cert signed by backend CA
openssl req -new -newkey "rsa:${KEY_SIZE}" -nodes \
  -keyout "$WORK/client.key" \
  -out "$WORK/client.csr" \
  -subj "/CN=${CN}" 2>/dev/null
openssl x509 -req -in "$WORK/client.csr" \
  -CA "$BACKEND_CA_CRT" -CAkey "$BACKEND_CA_KEY" -CAcreateserial \
  -days "$VALIDITY_DAYS" \
  -out "$WORK/${CONFIG_ID}-cert.pem" 2>/dev/null
cp "$BACKEND_CA_CRT" "$WORK/${CONFIG_ID}-ca.pem"

# PKCS#12 (cert + key) protected by passphrase
openssl pkcs12 -export \
  -in "$WORK/${CONFIG_ID}-cert.pem" \
  -inkey "$WORK/client.key" \
  -out "$WORK/${CONFIG_ID}.p12" \
  -passout "pass:${P12_PASSPHRASE}"

# Manifest (configs.json, schema v2)
sni_json="null"
[[ -n "$SNI" ]] && sni_json="\"$SNI\""
synth_ip_json="null"
[[ -n "$SYNTHETIC_IP" ]] && synth_ip_json="\"$SYNTHETIC_IP\""
synth_port_json="null"
[[ -n "$SYNTHETIC_PORT" ]] && synth_port_json="$SYNTHETIC_PORT"
loopback_port_json="null"
[[ "$MODE" == "LOOPBACK" ]] && loopback_port_json="$LOOPBACK_PORT"

cat > "$WORK/configs.json" <<EOF
{
  "schema": 2,
  "exportedAtMs": $(date +%s)000,
  "configs": [
    {
      "id": "${CONFIG_ID}",
      "displayName": "${DISPLAY_NAME}",
      "targetPackage": "${TARGET_PACKAGE}",
      "upstreamHost": "${UPSTREAM_HOST}",
      "upstreamPort": ${UPSTREAM_PORT},
      "sni": ${sni_json},
      "keystoreAlias": "mtls_bridge-${CONFIG_ID}",
      "mode": "${MODE}",
      "syntheticIp": ${synth_ip_json},
      "syntheticPort": ${synth_port_json},
      "loopbackPort": ${loopback_port_json},
      "enabled": true,
      "certPemFile": "${CONFIG_ID}-cert.pem",
      "caPemFile": "${CONFIG_ID}-ca.pem",
      "p12File": "${CONFIG_ID}.p12"
    }
  ]
}
EOF

# Optional README inside the bundle
cat > "$WORK/README.txt" <<EOF
mTLS Bridge deployment bundle (schema v2)
Generated $(date -Iseconds) by $(whoami)@$(hostname)

To import: open this .zip with the mTLS Bridge Android app (menu ⋮ → Importer).
The app will prompt for the PKCS#12 passphrase, then install everything.

After successful import, the original .p12 can be safely deleted.
EOF

# Strip the cleartext key file before zipping
rm -f "$WORK/client.key" "$WORK/client.csr"

# Final zip
( cd "$WORK" && zip -q "$OUTPUT" ./* )
mv "$WORK/$OUTPUT" "./$OUTPUT"

echo ""
echo "  ✓ bundle:     ./${OUTPUT}"
echo "  ✓ passphrase: ${P12_PASSPHRASE}"
echo ""
echo "Send the bundle and the passphrase to the employee through"
echo "SEPARATE channels (e.g., email + Signal). The passphrase must"
echo "NEVER ship in the same channel as the bundle."
