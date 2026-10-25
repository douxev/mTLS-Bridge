# Fiche Play Store — mTLS Bridge (FR)

## Nom de l'app (50 caractères max)

mTLS Bridge — wrapper mTLS pour apps self-hostées

## Description courte (80 caractères max)

Ajoute du mTLS à n'importe quelle app cliente. Clé matérielle. 100% local.

## Description longue (4000 caractères max)

mTLS Bridge est un proxy local mTLS (TLS mutuel) pour Android. Il te permet de
connecter les apps officielles (Jellyfin, Nextcloud, Home Assistant,
dashboards custom…) à un backend self-hosted protégé par authentification
client par certificat — sans modifier l'app cliente.

Tu pointes ton app vers une URL locale type `http://127.0.0.1:34521`.
mTLS Bridge intercepte la requête, la chiffre en TLS avec ton certificat
client, et la relaie vers ton vrai backend. L'app cliente voit un serveur
HTTP normal sur localhost ; le backend voit une connexion mTLS authentifiée.

### Pourquoi mTLS Bridge ?

La plupart des backends self-hostés derrière un reverse proxy (Caddy,
Nginx, Traefik) peuvent exiger des certificats clients pour une couche
d'auth supplémentaire. Mais les apps mobiles officielles supportent
rarement mTLS — d'où le choix forcé entre sécurité et confort. mTLS Bridge
comble ce trou, de manière transparente pour l'app.

### Fonctionnalités clés

• **Clé stockée en hardware.** Ta clé privée est importée une seule fois
  dans Android Keystore (StrongBox / TEE quand dispo) et ne quitte jamais
  le device. Même mTLS Bridge ne peut que demander des signatures, jamais lire
  le matériel cryptographique.

• **Isolation par app.** Chaque configuration a son propre port local et
  est protégée par un check UID strict : seule l'app cible enregistrée peut
  se connecter à son proxy. Les autres apps sont refusées à l'accept,
  fail-closed.

• **Proxies loopback always-on.** Tu ajoutes une config une fois, elle
  tourne en arrière-plan indéfiniment avec un impact batterie négligeable
  (epoll, zéro CPU au repos). Toggle on/off par config.

• **Mode VPN** pour la rare app qui refuse une URL en localhost. Liste
  d'apps autorisées filtrée par le noyau Android.

• **Chiffré au repos.** Toutes les configs et les logs d'audit dans une
  DB SQLCipher AES-256-GCM, passphrase wrappée par un master-key matériel.

• **Logs d'audit par config.** Tu vois exactement quelle app s'est
  connectée quand, avec quel UID, et quels événements ont été émis
  (connexions refusées, erreurs de bridge). Purge auto à 7 jours glissants.

• **Bundles de déploiement pour les admins IT.** Génère un `.zip` depuis
  un script bash + openssl et distribue-le à tes employés. Un clic +
  passphrase = installation complète. Le format est documenté et
  reproductible.

• **Backup / restore perso.** Exporte tes configs (sans la clé privée)
  dans un `.zip` portable pour migrer entre devices.

### Compatibilité

• Android 10 (API 29) ou plus.
• Fonctionne avec tout backend qui fait du mTLS sur HTTPS.
• Testé avec les apps officielles Jellyfin et Nextcloud derrière des
  reverse proxies Caddy / Nginx.

### Vie privée

mTLS Bridge ne phone-home pas, n'inclut aucun tracker ni analytics, et ne
se connecte à aucun serveur que tu n'as pas configuré. Permission INTERNET
nécessaire pour joindre ton backend, NETWORK_STATE pour la résolution UID,
FOREGROUND_SERVICE pour maintenir les proxies en arrière-plan.

### Doc et outillage ouverts

L'app est open source (MPL-2.0), et le **format de bundle de
déploiement est documenté** pour qu'un admin IT puisse générer des
bundles depuis un simple script bash + openssl, sans même installer
l'app sur son serveur de build. La spec du format et un script de
référence sont dans le dossier `deployment-tools/` de
https://github.com/douxev/mTLS-Bridge.

## Catégories

Principale : Outils
Secondaire : Productivité

## Mots-clés / tags (ASO)

mTLS, TLS mutuel, certificat client, reverse proxy, self-hosted,
Jellyfin, Nextcloud, Home Assistant, VPN, réseau, sécurité, sysadmin,
proxy, mTLS proxy, mTLS wrapper, mTLS Android, mTLS client

## Classification de contenu

Tous publics (pas de contenu utilisateur, pas de pub, pas de contenu
inapproprié)

## Permissions requises et justifications

• **INTERNET** — pour relayer les requêtes vers ton backend configuré.
• **ACCESS_NETWORK_STATE** — utilisé par
  `ConnectivityManager.getConnectionOwnerUid` pour vérifier que les
  connexions au proxy local viennent bien de l'app cible enregistrée
  (UID check, défense en profondeur).
• **CHANGE_NETWORK_STATE** — requise par Android 14+ pour utiliser
  `foregroundServiceType="connectedDevice"` sur les services de proxy.
• **FOREGROUND_SERVICE** + **FOREGROUND_SERVICE_CONNECTED_DEVICE** —
  pour maintenir les proxies loopback / VPN actifs en arrière-plan
  avec une notification persistante.
• **POST_NOTIFICATIONS** (Android 13+) — pour la notification persistante
  du service, qui expose un bouton Arrêter.
• **QUERY_ALL_PACKAGES** — pour remplir le picker d'apps cibles dans
  le formulaire de config. Utilisée uniquement à la création.
• **BIND_VPN_SERVICE** — demandée uniquement si tu choisis le mode VPN
  (cas marginal).

## Formulaire de sécurité des données (Play Console)

• Données collectées : aucune.
• Données partagées : aucune.
• Données chiffrées en transit : oui (mTLS).
• Données chiffrées au repos : oui (SQLCipher AES-256-GCM + Android Keystore).
• L'utilisatrice peut demander la suppression : non applicable (aucune
  donnée n'est envoyée hors du device).

## Captures d'écran (titres)

1. « Ajoute une app protégée en mTLS en trois taps »
2. « Un proxy par app, isolé par UID »
3. « Clé stockée en hardware — visible dans le badge sécurité »
4. « Déploiement intégré pour les sysadmins »
5. « Audit en temps réel, par config »
6. « Ouvre ton app et utilise-la — c'est tout »
