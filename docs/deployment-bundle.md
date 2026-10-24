# Bundle de déploiement mTLS Bridge

Format de fichier qu'un IT admin peut générer pour distribuer une (ou
plusieurs) configurations mTLS à des employés. L'employé clique sur le
fichier, saisit la passphrase une fois, et toutes les configs sont
immédiatement opérationnelles.

## Format

C'est un **zip standard**. Convention d'extension : `.zip` (ou `.mtlsw`
si tu veux une icône dédiée). Contenu :

```
mtls-bridge-bundle.zip
├── README.txt              # facultatif, généré par défaut
├── configs.json            # manifest (schéma v2)
├── <id1>-cert.pem          # chaîne de certs client
├── <id1>-ca.pem            # CA upstream pinné
├── <id1>.p12               # PKCS#12 chiffré (clé + cert)
├── <id2>-cert.pem
├── <id2>-ca.pem
└── <id2>.p12
```

## `configs.json`

```json
{
  "schema": 2,
  "exportedAtMs": 1717000000000,
  "configs": [
    {
      "id": "jellyfin-paris-2026",
      "displayName": "Jellyfin (Paris)",
      "targetPackage": "org.jellyfin.mobile",
      "upstreamHost": "media.example.com",
      "upstreamPort": 443,
      "sni": null,
      "keystoreAlias": "mtls_bridge-jellyfin-paris-2026",
      "mode": "LOOPBACK",
      "syntheticIp": null,
      "syntheticPort": null,
      "loopbackPort": 23817,
      "enabled": true,
      "certPemFile": "jellyfin-paris-2026-cert.pem",
      "caPemFile": "jellyfin-paris-2026-ca.pem",
      "p12File": "jellyfin-paris-2026.p12",
      "pathToken": "Kx7P2mNqRtVy"
    }
  ]
}
```

Notes :
- `id` : identifiant stable de la config (slug ou UUID). Utilisé en clé de
  routage côté wrapper et comme alias Keystore (`keystoreAlias`).
- `mode` : `"LOOPBACK"` ou `"VPN"`.
- `loopbackPort` : port fixe sur lequel le proxy écoute (`127.0.0.1`),
  tiré dans `10001..32767`. Il fait partie de l'URL collée dans l'app
  cible. À l'import, un port absent, hors `1..65535` (`0` compris) ou
  déjà pris par une autre config loopback est remplacé par un port tiré
  dans cette plage.
- `pathToken` : loopback uniquement, recommandé. Le proxy n'accepte que
  les requêtes dont le path commence par `/<pathToken>/` (ou qui portent
  le cookie de session posé en réponse), et retire ce préfixe avant
  l'upstream. Absent = pas de contrôle. Chaque refus est journalisé
  (`REJECTED_TOKEN`), sans le token ni le chemin.
- `syntheticIp` / `syntheticPort` : VPN uniquement (TEST-NET, ex.
  `192.0.2.X:5001`).
- `p12File` est **optionnel**. Sans, la config est importée en mode
  "backup" et l'employé doit re-fournir son .p12 manuellement.
- Tous les `.p12` du bundle doivent partager la **même passphrase**
  (convention déploiement).

## Script de génération (bash + openssl)

Version courte, mode loopback seul, reprise telle quelle dans l'écran
d'aide de l'app (`DeploymentScript.kt`). Le générateur complet
(`deployment-tools/bundle-generator.sh`) ajoute le mode VPN, le SNI, la
durée de validité et le contrôle de tous les paramètres.

```bash
#!/usr/bin/env bash
# Bundle generator pour mTLS Bridge — version courte, mode loopback.
# Version complète (mode VPN, SNI, contrôle des paramètres) :
# deployment-tools/bundle-generator.sh. Format : docs/deployment-bundle.md
set -euo pipefail

: "${USER:=$(id -un)}"            # absent dans certains conteneurs

# === À adapter par l'admin =========================
CONFIG_ID="jellyfin-$USER"        # [A-Za-z0-9._-] : nom de fichier du zip
DISPLAY_NAME="Jellyfin"
TARGET_PKG="org.jellyfin.mobile"
UPSTREAM_HOST="media.example.com"
UPSTREAM_PORT=443
BACKEND_CA_CRT="backend-ca.crt"   # CA qui signe les certs clients
BACKEND_CA_KEY="backend-ca.key"
# ===================================================

[[ $CONFIG_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo "CONFIG_ID invalide" >&2; exit 1; }
[[ $UPSTREAM_PORT =~ ^[1-9][0-9]{0,4}$ ]] && (( UPSTREAM_PORT <= 65535 )) \
  || { echo "UPSTREAM_PORT invalide" >&2; exit 1; }

# Port loopback fixe, tiré dans 10001..32767 comme le fait l'app : l'URL
# collée dans l'app cible reste valable quand le proxy redémarre.
LOOPBACK_PORT=$(( 10001 + ((RANDOM << 15) | RANDOM) % 22767 ))

# Token de path (activé par défaut) : isole le proxy des autres apps du
# téléphone. 12 caractères, même alphabet que l'app (ni 0/O ni 1/l/I).
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
PATH_TOKEN="$(gen_path_token)"

# Chaîne JSON : guillemets, antislash et caractères de contrôle échappés.
json_str() {
  local s=$1 out='' c i
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    case $c in
      '"')         out+='\"' ;;
      '\')         out+='\\' ;;
      [[:cntrl:]]) printf -v c '\\u%04x' "'$c"; out+=$c ;;
      *)           out+=$c ;;
    esac
  done
  printf '"%s"' "$out"
}

P12_PASSPHRASE="$(openssl rand -base64 32)"   # à transmettre hors bande
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BUNDLE="$WORK/bundle"                          # contenu du zip, rien d'autre
mkdir "$BUNDLE"

# Clé client + signature par la CA backend
openssl req -new -newkey rsa:3072 -nodes \
  -keyout "$WORK/client.key" -out "$WORK/client.csr" \
  -subj "/CN=$USER" 2>/dev/null
openssl x509 -req -in "$WORK/client.csr" \
  -CA "$BACKEND_CA_CRT" -CAkey "$BACKEND_CA_KEY" -CAcreateserial \
  -days 365 -out "$BUNDLE/$CONFIG_ID-cert.pem" 2>/dev/null
cp "$BACKEND_CA_CRT" "$BUNDLE/$CONFIG_ID-ca.pem"

# PKCS#12 : passphrase passée par l'environnement d'openssl seul (env:),
# jamais en argument (lisible par tous via ps / /proc/<pid>/cmdline).
P12_PASSPHRASE="$P12_PASSPHRASE" openssl pkcs12 -export \
  -in "$BUNDLE/$CONFIG_ID-cert.pem" -inkey "$WORK/client.key" \
  -out "$BUNDLE/$CONFIG_ID.p12" -passout env:P12_PASSPHRASE
rm -f "$WORK/client.key" "$WORK/client.csr"   # clé en clair

# Manifest (schéma v2)
cat > "$BUNDLE/configs.json" <<EOF
{
  "schema": 2,
  "exportedAtMs": $(date +%s)000,
  "configs": [{
    "id": $(json_str "$CONFIG_ID"),
    "displayName": $(json_str "$DISPLAY_NAME"),
    "targetPackage": $(json_str "$TARGET_PKG"),
    "upstreamHost": $(json_str "$UPSTREAM_HOST"),
    "upstreamPort": $UPSTREAM_PORT,
    "sni": null,
    "keystoreAlias": $(json_str "mtls_bridge-$CONFIG_ID"),
    "mode": "LOOPBACK",
    "syntheticIp": null,
    "syntheticPort": null,
    "loopbackPort": $LOOPBACK_PORT,
    "enabled": true,
    "certPemFile": $(json_str "$CONFIG_ID-cert.pem"),
    "caPemFile": $(json_str "$CONFIG_ID-ca.pem"),
    "p12File": $(json_str "$CONFIG_ID.p12"),
    "pathToken": $(json_str "$PATH_TOKEN")
  }]
}
EOF

# Zip final : entrées à la racine, sans uid/gid de la machine de l'admin.
zip -q -j -X "$WORK/bundle.zip" "$BUNDLE"/*
mv -f "$WORK/bundle.zip" ./mtls-bridge-bundle.zip

echo "Bundle prêt : ./mtls-bridge-bundle.zip"
echo "Passphrase à transmettre hors bande : $P12_PASSPHRASE"
echo "URL à coller dans l'app cible : http://127.0.0.1:$LOOPBACK_PORT/$PATH_TOKEN/"
```

## Distribution

- Email avec le zip + passphrase dans un canal SÉPARÉ (Signal, Matrix…).
- MDM (Intune, Jamf) push file + variable env pour la passphrase.
- QR code pour la passphrase, scan dans l'app au moment de l'import.

## Côté employé

1. Installer mTLS Bridge depuis le Play Store (ou le canal entreprise fourni).
2. Cliquer sur le .zip reçu.
3. L'app s'ouvre, propose "Importer", demande la passphrase, importe tout.
4. Lancer Jellyfin → configurer l'URL affichée par mTLS Bridge (par exemple
   `http://127.0.0.1:23817/Kx7P2mNqRtVy/` montré dans le détail de la config).

## Sécurité

- Le `.p12` est chiffré par PKCS#12 (AES256 avec openssl récent). La
  passphrase ne doit jamais être dans le même fichier ni le même canal
  que le bundle.
- Après import dans Keystore, la clé devient non-exportable du device
  (TEE/StrongBox quand dispo). Le .p12 d'origine peut être effacé.
- L'option "Supprimer après import" dans l'UI fait ça automatiquement
  via `ContentResolver.delete()` (best-effort selon le provider).
