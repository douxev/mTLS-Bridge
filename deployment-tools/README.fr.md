# mTLS Bridge — outils de déploiement

Outils pour générer des bundles de déploiement
[mTLS Bridge](https://github.com/<your-org>/mtls-bridge) — distribuer
configurations mTLS + certificats clients à des utilisateurs (typiquement
employés d'une petite structure qui héberge ses propres services
derrière un reverse proxy Caddy/Nginx/Traefik avec authentification
mTLS).

[🇬🇧 English version](README.md)

## Contenu du repo

- `bundle-generator.sh` — génère un `mtls-bridge-bundle.zip` à partir d'un
  CSR client signé par ta CA backend. Pure bash + openssl + zip, aucune
  dépendance à mTLS Bridge.
- `examples/` — exemples d'invocations.
- `bundle-format.md` — spec complète du format zip consommé par mTLS Bridge
  (schéma v2).

## Démarrage rapide

```bash
git clone https://github.com/<your-org>/mtls-bridge-deployment-tools.git
cd mtls-bridge-deployment-tools

# Pointer sur ta CA backend (clé privée + cert)
export BACKEND_CA_CRT=/chemin/vers/backend-ca.crt
export BACKEND_CA_KEY=/chemin/vers/backend-ca.key

# Adapter au service
export CONFIG_ID=jellyfin-alice
export DISPLAY_NAME="Jellyfin"
export TARGET_PACKAGE=org.jellyfin.mobile
export UPSTREAM_HOST=media.example.com
export UPSTREAM_PORT=443
export CN=alice

./bundle-generator.sh
# → mtls-bridge-bundle.zip + passphrase aléatoire imprimée à la fin
```

Envoie le `mtls-bridge-bundle.zip` à l'utilisatrice (mail, MDM, Drive…) et
la **passphrase par un canal séparé** (Signal, Matrix, appel vocal). Ne
les mets jamais dans le même message.

## Ce que fait l'utilisatrice

1. Installe **mTLS Bridge** depuis le Play Store.
2. Tape sur le `.zip` reçu.
3. Choisit "mTLS Bridge" comme app d'ouverture, ou ouvre mTLS Bridge et fait
   menu ⋮ → Importer.
4. Saisit la passphrase envoyée séparément.
5. La config est importée, la clé privée passe dans Android Keystore
   (matériel quand supporté), le proxy démarre.
6. Elle ouvre son app cible (Jellyfin dans l'exemple) et utilise l'URL
   loopback affichée par mTLS Bridge (`http://127.0.0.1:34521`).

## Propriétés de sécurité

- Le fichier .p12 est chiffré par la passphrase. AES-256 avec openssl
  récent (≥3.0).
- Une fois importée dans Android Keystore, la clé devient
  **non-exportable du device**. mTLS Bridge ne peut que demander des
  signatures via le Keystore — jamais lire le matériel cryptographique.
- Le `mtls-bridge-bundle.zip` et la passphrase **doivent transiter par
  des canaux séparés**. Le bundle seul est inutile sans la passphrase ;
  la passphrase seule est inutile sans le bundle.
- Le script n'écrit jamais la clé client en clair sur disque au-delà
  de l'étape de packaging `.p12` ; les `.key` et `.csr` intermédiaires
  sont supprimés avant le zip.

## Générer plusieurs bundles d'un coup

Boucle sur les utilisatrices et appelle le script avec des variables
d'environnement différentes par user. Chaque bundle a son propre
`CONFIG_ID` (typiquement `<service>-<user>`) pour éviter les collisions
sur le device.

```bash
for user in alice bob charlie; do
  export CONFIG_ID="jellyfin-$user" CN="$user" \
         OUTPUT="bundles/${user}.zip" \
         P12_PASSPHRASE="$(openssl rand -base64 24)"
  ./bundle-generator.sh > "bundles/${user}.log"
done
```

(Chaque bundle a sa propre passphrase aléatoire imprimée dans son log.)

## Bundles multi-config

Un seul bundle peut contenir plusieurs configs (par ex. Jellyfin ET
Nextcloud pour la même utilisatrice). Tous les `.p12` du bundle doivent
partager la **même passphrase** — l'app ne la demande qu'une fois.

Pour ce cas, le script tel quel ne gère qu'une seule config. Le
multi-config c'est ~30 lignes d'extension : génère les artefacts en
boucle et émets un `configs.json` avec plusieurs entrées pointant sur
les bons fichiers. Voir `bundle-format.md` pour le schéma JSON.

## Licence

MIT.
