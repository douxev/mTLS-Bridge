# Modèle de menaces — mTLS Bridge

Cette page décrit le modèle de menaces de mTLS Bridge, les hypothèses sous-jacentes,
les défenses en place et les compromis assumés. Reflète l'état du code à la date
du dernier commit.

## 1. Buts et non-buts

**Buts.** Permettre à une utilisatrice d'utiliser une app cliente Android
existante (Jellyfin, Nextcloud, Home Assistant…) avec un backend self-hosted
exigeant une authentification mTLS, **sans modifier** l'app cliente, et sans
exposer la clé privée client à un attaquant qui aurait obtenu un accès
applicatif au device.

**Non-buts.**
- Authentifier ou attester *le wrapper lui-même* auprès du backend.
- Empêcher un attaquant qui contrôle root sur le device de signer des
  requêtes (un root peut toujours demander au Keystore de signer
  arbitrairement même sans extraire la clé).
- Wrapper des apps qui font du HTTPS strict vers leur hostname réel (le
  wrapper ne fait pas de MITM ; voir §6).

## 2. Périmètre des actifs

| Actif | Sensibilité |
|---|---|
| Clé privée client mTLS (importée d'un .p12) | **Critique** — donne l'identité TLS de l'utilisatrice |
| Chaîne de certs client + CA upstream pinné | Faible (cert public) |
| Passphrase du .p12 (saisie UI) | Élevée *temporairement* — utilisée à l'import puis effacée |
| Configurations stockées (nom, hôte, port, mode) | Faible (informations de routage) |
| Logs d'audit chiffrés | Modérée (révèle l'usage) |
| Tunnel de bytes (HTTP plaintext loopback ↔ HTTPS+mTLS upstream) | Élevée (passe des requêtes authentifiées) |

## 3. Acteurs et capacités

| Acteur | Modèle de capacités |
|---|---|
| **App cliente officielle** (Jellyfin Android, etc.) | Code closed-source. Considérée comme honnête mais potentiellement bavarde. Peut faire toutes les requêtes HTTP qu'elle veut au backend une fois la session établie. |
| **Autre app malveillante installée sur le device** | UID Linux distinct. Peut tenter de se connecter à 127.0.0.1, scanner les ports, abuser des APIs publiques. Ne dispose ni de root ni de l'accès Keystore de mTLS Bridge. |
| **Backend self-hosted compromis** | Hors périmètre côté wrapper. La doxev a la main sur son backend ; en cas de compromission, le mTLS ne sauve rien. |
| **Attaquant réseau (WiFi public, MITM)** | Peut voir et modifier les paquets entre le device et le backend. Bloqué par TLS + pinning CA + mTLS. |
| **OS Android compromis (root, malware système)** | Hors périmètre. Un root peut signer arbitrairement même sans extraire la clé. |
| **Le wrapper mTLS Bridge lui-même** | Limité par les défenses matérielles : la clé reste non-exportable dans le TEE, signature toujours via Keystore. Voir §5. |

## 4. Surfaces et défenses par mode

### Mode loopback (recommandé par défaut)

```
App cliente —http→ 127.0.0.1:N —Rust mTLS+TLS→ backend
```

- **Always-on par config** : le `LoopbackProxyService` héberge un proxy par
  config `enabled`, démarré automatiquement par le `LoopbackCoordinator`.
  Pas de bind quand `enabled=false`.
- **UID check fail-closed à chaque accept** : on appelle
  `ConnectivityManager.getConnectionOwnerUid(IPPROTO_TCP, peer_local, peer_remote)`
  pour résoudre l'UID du pair. Si UID ≠ celui de l'app enregistrée (ou
  résolution = `INVALID_UID`), on droppe la connexion et on logue
  `RejectedUidMismatch` / `RejectedUidUnknown`.
- **Port unique par config** : chaque proxy a son port éphémère ou fixe.
  Les services sont isolés au niveau process (services Android distincts
  cohabitant dans le même `LoopbackProxyService`).
- **Cohabite avec d'autres VPN** (WireGuard, Mullvad…) : on n'occupe pas
  le slot VPN unique du device.
- **Conso au repos** : ≈ 0 — `TcpListener` dort sur `epoll`, aucun parsing
  réseau tant qu'aucune connexion n'arrive.

### Mode VPN (cas marginal)

```
App cliente —http→ tun virtuel (192.0.2.0/24) —smoltcp→ Rust mTLS+TLS —→ backend
```

- **Isolation OS-enforced via `addAllowedApplication(pkg)`** : le noyau
  Android filtre les paquets — seules les apps listées peuvent envoyer
  dans le tun. Aucune autre app du device ne peut atteindre le proxy.
- **UID check soft-fail** : pour deux apps allow-listées dans le même tun,
  on tente de vérifier que la connexion à l'IP synthétique d'une config
  vient bien de l'UID attendu (cross-cert leak). L'API
  `getConnectionOwnerUid` ne supporte pas les sockets VPN-routés sur la
  plupart des kernels Android (retourne `INVALID_UID`), donc on accepte
  par défaut quand la résolution échoue ; on ne refuse qu'un mismatch
  explicite. **Conséquence** : si deux apps sont actives simultanément
  dans la même VPN, l'une peut potentiellement utiliser le cert de l'autre
  en visant son IP synthétique. Mitigation : n'autoriser que des apps
  qu'on considère honnêtes (= même règle que toute VPN per-app sur Android).
- **Une seule VPN à la fois** : limitation Android.
- **Effet de bord** : tout le trafic des apps allow-listées passe par notre
  tun. Les requêtes vers d'autres serveurs (CDN d'images, analytics)
  arrivent dans le tun, ne matchent aucune route synthétique → on les
  drop. Casse les fonctionnalités collatérales de l'app cible.
- **Conso** : continue — smoltcp parse chaque paquet, runner tokio en
  boucle tant que la VPN tourne.

### Recommandation

Le **mode loopback** est strictement meilleur sur l'isolation, la batterie,
la compatibilité avec d'autres VPN, et n'a aucun désavantage fonctionnel
tant que l'app cible accepte une URL en `http://127.0.0.1:PORT`. C'est le
cas de Jellyfin et Nextcloud officiels. Le mode VPN n'est utile que pour
une app qui refuserait explicitement une URL en localhost — cas rare en
pratique.

## 5. Garanties matérielles de la clé

La clé .p12 est importée dans Android Keystore via `setKeyEntry`. Sur les
devices modernes supportant l'import-into-TEE, la clé est ensuite
hardware-backed et **non-exportable**.

`KeyInfo.getSecurityLevel()` renvoie l'un des niveaux suivants, **affiché
honnêtement à l'utilisatrice dans l'UI** :

- `STRONGBOX` : élément sécurisé dédié (Pixel 3+, certains Samsung).
- `TRUSTED_ENVIRONMENT` : TEE (ARM TrustZone) — la quasi-totalité des
  devices Android 9+.
- `SOFTWARE` : pas de TEE disponible ou OEM non conforme — la clé est
  protégée logiquement seulement.

**Limite assumée du choix .p12** : la clé a existé en clair sur disque
(côté backend ou device de l'utilisatrice) avant l'import. L'attestation
Google chain n'apporte donc pas la garantie "cette clé est née dans le
TEE et n'a jamais existé ailleurs" qu'on aurait avec un flux génération+CSR.
Compromis explicite : on ne supporte que l'import .p12 parce que c'est le
workflow standard d'intégration mTLS.

## 6. Limites connues

- **HTTPS strict côté app cible** : si l'app refuse de parler en clair
  (network-security-config strict), elle ne pourra pas utiliser le wrapper.
  Jellyfin et Nextcloud officiels acceptent `http://` pour leur configuration
  de serveur, c'est le cas commun.
- **Cross-cert leak en mode VPN multi-apps** : voir §4.
- **Pas de protection contre l'app cible malveillante** : si l'app cliente
  officielle décide de faire des requêtes nuisibles au backend, le wrapper
  ne peut pas les détecter (il pipe les bytes après réécriture du Host
  header). Mitigation : configurer côté backend des permissions minimales
  pour l'utilisateur lié au cert client. Optionnellement, filtres
  applicatifs côté wrapper (méthodes/chemins whitelistés) — non implémenté.
- **Réécriture HTTP/1.1 par-requête** : on réécrit le `Host:` header de
  chaque requête keepalive (Caddy/Nginx routent par Host). Si une requête
  utilise `Transfer-Encoding: chunked` côté body (rare en requête client),
  on bascule en raw-copy pour le reste de la session → les requêtes
  suivantes ne sont plus réécrites. À traiter quand un cas réel apparaîtra.

## 7. Stratégies de défense en profondeur additionnelles

À ajouter selon priorité :

1. **Filtres de requêtes opt-in** côté wrapper : whitelist méthodes HTTP +
   préfixes de chemin par config.
2. **Audit consultable + alertes** : déjà persisté en DB chiffrée, à
   exposer via notifications quand un événement `RejectedUidMismatch`
   arrive.
3. **Biometric gating** : exiger l'authentification utilisateur avant que
   Keystore signe (`setUserAuthenticationRequired(true)`). Compromis :
   ajoute une friction à chaque session.
4. **Reproducible builds** + signatures vérifiables côté wrapper.

## 8. Stockage local

- **Configs** : SQLCipher (AES-256-GCM), passphrase 32B aléatoire stockée
  dans EncryptedSharedPreferences (master key AES Keystore non-exportable).
- **Logs d'audit** : même DB. Purge automatique au démarrage de l'app via
  le `LoopbackCoordinator` (horizon glissant 7 jours par défaut).
- **Backup Android** : désactivé via `android:allowBackup="false"` +
  `data_extraction_rules.xml` (exclut root/database/sharedpref).

## 9. Export / import de configs

Pour migrer entre devices, l'app expose un export JSON contenant :
métadonnées (nom, app cible, hôte/port, SNI, mode, IP synth/port loopback),
**chaîne de certs client (PEM)**, **CA upstream pinné (PEM)**.

**La clé privée n'est PAS exportée** — c'est volontaire (elle est non-
exportable du Keystore matériel). À l'import sur le device cible, chaque
config est marquée "clé manquante" et la doxev doit re-fournir son .p12
via le bouton "Importer la clé" sur le détail de la config.

Le fichier d'export n'est pas chiffré par mTLS Bridge : il contient des certs
(publics) mais pas de secrets. Si la doxev veut le partager (cloud,
mail…), c'est sa responsabilité d'utiliser un canal sûr.
