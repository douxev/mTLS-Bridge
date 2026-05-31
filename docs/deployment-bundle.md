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
      "loopbackPort": 0,
      "enabled": true,
      "certPemFile": "jellyfin-paris-2026-cert.pem",
      "caPemFile": "jellyfin-paris-2026-ca.pem",
      "p12File": "jellyfin-paris-2026.p12"
    }
  ]
}
```

Notes :
- `id` : identifiant stable de la config (slug ou UUID). Utilisé en clé de
  routage côté wrapper et comme alias Keystore (`keystoreAlias`).
- `mode` : `"LOOPBACK"` ou `"VPN"`.
- `loopbackPort` : `0` = port éphémère choisi par l'OS au démarrage du
  proxy. Sinon port fixe.
- `syntheticIp` / `syntheticPort` : VPN uniquement (TEST-NET, ex.
  `192.0.2.X:5001`).
- `p12File` est **optionnel**. Sans, la config est importée en mode
  "backup" et l'employé doit re-fournir son .p12 manuellement.
- Tous les `.p12` du bundle doivent partager la **même passphrase**
  (convention déploiement).

## Script de génération (bash + openssl)

```bash
#!/usr/bin/env bash
set -euo pipefail

BUNDLE_DIR=$(mktemp -d)
trap "rm -rf $BUNDLE_DIR" EXIT

# Paramètres
CONFIG_ID="jellyfin-$USER"
DISPLAY_NAME="Jellyfin"
TARGET_PKG="org.jellyfin.mobile"
UPSTREAM_HOST="media.example.com"
UPSTREAM_PORT=443
P12_PASSPHRASE="$(openssl rand -base64 32)"  # à transmettre hors bande

# Génération de la clé + signature par la CA backend
openssl req -new -newkey rsa:3072 -nodes -keyout $BUNDLE_DIR/client.key \
    -out $BUNDLE_DIR/client.csr -subj "/CN=$USER"
openssl x509 -req -in $BUNDLE_DIR/client.csr -CA backend-ca.crt \
    -CAkey backend-ca.key -CAcreateserial -days 365 \
    -out $BUNDLE_DIR/${CONFIG_ID}-cert.pem
cp backend-ca.crt $BUNDLE_DIR/${CONFIG_ID}-ca.pem
openssl pkcs12 -export -in $BUNDLE_DIR/${CONFIG_ID}-cert.pem \
    -inkey $BUNDLE_DIR/client.key -out $BUNDLE_DIR/${CONFIG_ID}.p12 \
    -passout pass:"$P12_PASSPHRASE"

# Manifest
cat > $BUNDLE_DIR/configs.json <<EOF
{
  "schema": 2,
  "exportedAtMs": $(date +%s)000,
  "configs": [{
    "id": "$CONFIG_ID",
    "displayName": "$DISPLAY_NAME",
    "targetPackage": "$TARGET_PKG",
    "upstreamHost": "$UPSTREAM_HOST",
    "upstreamPort": $UPSTREAM_PORT,
    "sni": null,
    "keystoreAlias": "mtls_bridge-$CONFIG_ID",
    "mode": "LOOPBACK",
    "syntheticIp": null,
    "syntheticPort": null,
    "loopbackPort": 0,
    "enabled": true,
    "certPemFile": "${CONFIG_ID}-cert.pem",
    "caPemFile": "${CONFIG_ID}-ca.pem",
    "p12File": "${CONFIG_ID}.p12"
  }]
}
EOF

# Nettoyage des fichiers intermédiaires
rm $BUNDLE_DIR/client.key $BUNDLE_DIR/client.csr

# Zip final
( cd $BUNDLE_DIR && zip mtls-bridge-bundle.zip * )
mv $BUNDLE_DIR/mtls-bridge-bundle.zip ./

echo "Bundle : ./mtls-bridge-bundle.zip"
echo "Passphrase à transmettre hors bande : $P12_PASSPHRASE"
```

## Distribution

- Email avec le zip + passphrase dans un canal SÉPARÉ (Signal, Matrix…).
- MDM (Intune, Jamf) push file + variable env pour la passphrase.
- QR code pour la passphrase, scan dans l'app au moment de l'import.

## Côté employé

1. Installer mTLS Bridge depuis le Play Store / GitHub Releases / etc.
2. Cliquer sur le .zip reçu.
3. L'app s'ouvre, propose "Importer", demande la passphrase, importe tout.
4. Lancer Jellyfin → configurer l'URL affichée par mTLS Bridge (par exemple
   `http://127.0.0.1:34521` montré dans le détail de la config).

## Sécurité

- Le `.p12` est chiffré par PKCS#12 (AES256 avec openssl récent). La
  passphrase ne doit jamais être dans le même fichier ni le même canal
  que le bundle.
- Après import dans Keystore, la clé devient non-exportable du device
  (TEE/StrongBox quand dispo). Le .p12 d'origine peut être effacé.
- L'option "Supprimer après import" dans l'UI fait ça automatiquement
  via `ContentResolver.delete()` (best-effort selon le provider).
