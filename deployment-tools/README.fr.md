# mTLS Bridge — outils de déploiement

Outils pour générer des bundles de déploiement
[mTLS Bridge](https://github.com/douxev/mTLS-Bridge) — distribuer
configurations mTLS + certificats clients à des utilisateurs (typiquement
employés d'une petite structure qui héberge ses propres services
derrière un reverse proxy Caddy/Nginx/Traefik avec authentification
mTLS).

[English version](README.md)

## Contenu du repo

- `bundle-generator.sh` — génère un `mtls-bridge-bundle.zip` à partir d'un
  CSR client signé par ta CA backend. Pure bash + openssl + zip, aucune
  dépendance à mTLS Bridge.
- `examples/` — exemples d'invocations.
- `bundle-format.md` — spec complète du format zip consommé par mTLS Bridge
  (schéma v2).

## Démarrage rapide

```bash
git clone https://github.com/douxev/mTLS-Bridge.git
cd mTLS-Bridge/deployment-tools

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
# → mtls-bridge-bundle.zip, plus la passphrase aléatoire et l'URL
#   loopback imprimées à la fin
```

Envoie le `mtls-bridge-bundle.zip` à l'utilisatrice (mail, MDM, Drive…) et
la **passphrase par un canal séparé** (Signal, Matrix, appel vocal). Ne
les mets jamais dans le même message.

## Paramètres

Tous les paramètres sont des variables d'environnement.

| Variable | Défaut | Notes |
|----------|--------|-------|
| `BACKEND_CA_CRT`, `BACKEND_CA_KEY` | `backend-ca.crt`, `backend-ca.key` | CA qui signe le certificat client |
| `CONFIG_ID` | `jellyfin-$USER` | `[A-Za-z0-9][A-Za-z0-9._-]*` ; nomme aussi les fichiers du zip |
| `DISPLAY_NAME`, `TARGET_PACKAGE`, `UPSTREAM_HOST`, `SNI` | `Jellyfin`, `org.jellyfin.mobile`, `media.example.com`, vide | échappés dans `configs.json` : guillemets, antislashs, accents passent. `SNI` vide = `UPSTREAM_HOST` |
| `UPSTREAM_PORT` | `443` | |
| `MODE` | `LOOPBACK` | `LOOPBACK` ou `VPN` |
| `LOOPBACK_PORT` | aléatoire dans 10001–32767 | Port fixe, tiré dans la même plage que l'app : l'URL collée dans l'app cible reste valable quand le proxy redémarre. `0` = port tiré par l'app à l'import (l'URL n'est alors affichée que dans l'app). Refusé sous 1024 (une app Android ne peut pas y écouter) |
| `PATH_TOKEN` | aléatoire, 12 caractères | URL-safe (`[A-Za-z0-9._~-]`). `PATH_TOKEN_DISABLE=1` pour s'en passer |
| `SYNTHETIC_IP`, `SYNTHETIC_PORT` | vide | VPN uniquement ; vides, l'app choisit un couple libre à l'import |
| `CN`, `VALIDITY_DAYS`, `KEY_SIZE` | `$USER`, `365`, `3072` | certificat client |
| `OUTPUT` | `mtls-bridge-bundle.zip` | Peut contenir un dossier (`bundles/alice.zip`, un chemin absolu…), créé s'il manque. Un fichier existant est écrasé |
| `P12_PASSPHRASE` | aléatoire (`openssl rand -base64 32`) | protège le `.p12` |

## Ce que fait l'utilisatrice

1. Installe **mTLS Bridge** depuis le Play Store.
2. Tape sur le `.zip` reçu.
3. Choisit "mTLS Bridge" comme app d'ouverture, ou ouvre mTLS Bridge et fait
   menu ⋮ → Importer.
4. Saisit la passphrase envoyée séparément.
5. La config est importée, la clé privée passe dans Android Keystore
   (matériel quand supporté), le proxy démarre.
6. Elle ouvre son app cible (Jellyfin dans l'exemple) et utilise l'URL
   loopback imprimée par le script et affichée par mTLS Bridge
   (`http://127.0.0.1:23817/Kx7P2mNqRtVy/`). Le port est fixe : l'URL
   reste valable après un redémarrage du proxy.

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
- La passphrase arrive à openssl par son environnement
  (`-passout env:`), jamais par sa ligne de commande, que n'importe quel
  utilisateur local peut lire avec `ps`.

## Générer plusieurs bundles d'un coup

Boucle sur les utilisatrices et appelle le script avec des variables
d'environnement différentes par user. Chaque bundle a son propre
`CONFIG_ID` (typiquement `<service>-<user>`) pour éviter les collisions
sur le device.

```bash
mkdir -p bundles   # nécessaire à la redirection du log ci-dessous
for user in alice bob charlie; do
  export CONFIG_ID="jellyfin-$user" CN="$user" \
         OUTPUT="bundles/${user}.zip" \
         P12_PASSPHRASE="$(openssl rand -base64 24)"
  ./bundle-generator.sh > "bundles/${user}.log"
done
```

(Chaque bundle a sa propre passphrase, son port loopback et son token
de path aléatoires, imprimés dans son log. Les logs contiennent les
passphrases en clair : supprime-les une fois les passphrases envoyées.)

## Bundles multi-config

Un seul bundle peut contenir plusieurs configs (par ex. Jellyfin ET
Nextcloud pour la même utilisatrice). Tous les `.p12` du bundle doivent
partager la **même passphrase** — l'app ne la demande qu'une fois.

Pour ce cas, le script tel quel ne gère qu'une seule config. Le
multi-config c'est ~30 lignes d'extension : génère les artefacts en
boucle et émets un `configs.json` avec plusieurs entrées pointant sur
les bons fichiers — `examples/multi-config.sh` le fait pour deux
configs. Un `loopbackPort` déjà pris sur le téléphone (ou par une autre config
du bundle) est réattribué à l'import : l'URL à coller est alors celle
affichée dans l'app. Voir `bundle-format.md` pour le schéma JSON.

## Licence

MIT.
