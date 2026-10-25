// mTLS Bridge remote configuration console.
// Served by the device itself (no external dependency, strict CSP):
// the whole DOM is built through textContent, never innerHTML.
'use strict';

// ----- i18n ------------------------------------------------------------------

// UI strings. English is the default; French is picked when the browser
// language starts with "fr". Placeholders such as {name} are filled by t().
const I18N = {
  en: {
    'page.title': 'mTLS Bridge – console',
    'brand.sub': 'Configuration console',
    'logout': 'Sign out',

    'pair.title': 'Connect to the device',
    'pair.help': 'Enter the 6-digit PIN shown on the device\'s "Remote configuration" screen.',
    'pair.pin': 'PIN',
    'pair.submit': 'Connect',
    'pair.pinLength': 'The PIN is 6 digits long.',

    'main.title': 'Configurations',
    'main.newConfig': 'New config',
    'main.importBundle': 'Import a bundle',
    'main.export': 'Export',
    'main.empty': 'No configuration yet. Create one or import a deployment bundle.',

    'vpn.title': 'VPN tunnel',
    'vpn.running': 'VPN tunnel running',
    'vpn.stopped': 'VPN tunnel stopped',
    'vpn.consentNeeded': '{n} VPN config(s) · VPN permission must first be granted on the device',
    'vpn.count': '{n} config(s) in VPN mode',
    'vpn.stop': 'Stop',
    'vpn.start': 'Start',

    'form.name': 'Name',
    'form.clientApp': 'Client app',
    'form.otherPackagePlaceholder': 'org.example.app',
    'form.upstreamHost': 'Upstream host',
    'form.upstreamHostPlaceholder': 'media.example.com',
    'form.port': 'Port',
    'form.sni': 'SNI (optional)',
    'form.sniPlaceholder': 'default: the upstream host',
    'form.mode': 'Mode',
    'form.modeLoopback': 'Loopback (recommended)',
    'form.modeVpn': 'VPN',
    'form.loopbackPort': 'Loopback port',
    'form.pathToken': 'Isolation token in the URL (recommended, webviews included)',
    'form.extraHosts': 'Additional canonical hosts (optional)',
    'form.extraHostsPlaceholder': 'other.example.com, cdn.example.com',
    'form.regenerateToken': 'Generate a new token',
    'form.syntheticIp': 'Synthetic IP',
    'form.p12': 'Client certificate (.p12 / .pfx)',
    'form.p12Passphrase': '.p12 passphrase',
    'form.ca': 'Pinned upstream CA (.pem / .crt)',
    'form.editTitle': 'Edit "{name}"',
    'form.loading': 'Loading…',
    'form.chooseApp': '— Choose the target app —',
    'form.otherApp': 'Other (enter the package name)…',
    'form.required': 'Name, client app and upstream host are required.',
    'form.filesRequired': 'The .p12 and the pinned CA are required.',

    'common.cancel': 'Cancel',
    'common.save': 'Save',
    'common.close': 'Close',

    'bundle.title': 'Import a bundle',
    'bundle.hint': 'A .zip archive produced by the app\'s export or by',
    'bundle.file': '.zip file',
    'bundle.passphrase': 'Passphrase of the bundle\'s .p12 files',
    'bundle.submit': 'Import',
    'bundle.preview': '{total} config(s): {withKey} with key, {withoutKey} without key.',
    'bundle.imported': '{withKey} ready to use, {withoutKey} without key, {skipped} skipped.',

    'key.title': 'Provide the .p12',
    'key.titleFor': 'Provide the .p12 for "{name}"',
    'key.hint': 'The certificate in the .p12 must match the one of the config.',
    'key.file': '.p12 / .pfx file',
    'key.passphrase': 'Passphrase',
    'key.submit': 'Import the key',
    'key.chooseFile': 'Choose the .p12 file.',
    'key.imported': 'Key imported into the device Keystore.',

    'events.title': 'Events',
    'events.titleFor': 'Events – {name}',
    'events.time': 'Time',
    'events.type': 'Type',
    'events.details': 'Details',
    'events.refresh': 'Refresh',
    'events.none': 'No events.',

    'export.title': 'Export configs',
    'export.hint': 'Public certificates and metadata only: private keys stay in the device Keystore.',
    'export.submit': 'Download the .zip',

    'card.keyMissing': 'Key missing',
    'card.token': 'Token',
    'card.enableProxy': 'Enable the proxy',
    'card.active': 'Active',
    'card.inactive': 'Inactive',
    'card.app': 'App',
    'card.upstream': 'Upstream',
    'card.certificate': 'Certificate',
    'card.clientUrl': 'URL for the app:',
    'card.ephemeralPort': 'ephemeral port (see the events)',
    'card.copy': 'Copy',
    'card.copied': 'Copied',
    'card.copyFailed': 'Copy failed',
    'card.provideP12': 'Provide the .p12',
    'card.edit': 'Edit',
    'card.events': 'Events',
    'card.delete': 'Delete',

    'security.software': 'Software key',
    'security.unknown': 'Unknown security',

    'cert.expired': 'expired on {date}',
    'cert.expiresSoon': 'expires on {date} ({days} d)',
    'cert.validUntil': 'valid until {date}',

    'notice.enabled': '"{name}" enabled.',
    'notice.disabled': '"{name}" disabled.',
    'notice.deleted': '"{name}" deleted.',
    'notice.updated': '"{name}" updated.',
    'notice.created': '"{name}" created. The proxy is starting on the device.',
    'confirm.delete': 'Delete "{name}"?\n\nThe private key imported into the device Keystore ' +
      'will be destroyed: the original .p12 will be needed to recreate the config.',

    'error.unreachable': 'Device unreachable: is the "Remote configuration" screen still open?',
    'error.sessionExpired': 'Session expired: enter the new PIN.',
    'error.http': 'Error {status}',
    'error.fileRead': 'Unable to read the file',
  },
  fr: {
    'page.title': 'mTLS Bridge – console',
    'brand.sub': 'Console de configuration',
    'logout': 'Se déconnecter',

    'pair.title': 'Connexion à l\'appareil',
    'pair.help': 'Saisis le PIN à 6 chiffres affiché sur l\'écran « Configuration à distance » de l\'appareil.',
    'pair.pin': 'PIN',
    'pair.submit': 'Se connecter',
    'pair.pinLength': 'Le PIN fait 6 chiffres.',

    'main.title': 'Configurations',
    'main.newConfig': 'Nouvelle config',
    'main.importBundle': 'Importer un bundle',
    'main.export': 'Exporter',
    'main.empty': 'Aucune configuration pour l\'instant. Crée-en une ou importe un bundle de déploiement.',

    'vpn.title': 'Tunnel VPN',
    'vpn.running': 'Tunnel VPN actif',
    'vpn.stopped': 'Tunnel VPN arrêté',
    'vpn.consentNeeded': '{n} config(s) VPN · l\'autorisation VPN doit d\'abord être donnée sur l\'appareil',
    'vpn.count': '{n} config(s) en mode VPN',
    'vpn.stop': 'Arrêter',
    'vpn.start': 'Démarrer',

    'form.name': 'Nom',
    'form.clientApp': 'App cliente',
    'form.otherPackagePlaceholder': 'org.exemple.app',
    'form.upstreamHost': 'Hôte upstream',
    'form.upstreamHostPlaceholder': 'media.exemple.com',
    'form.port': 'Port',
    'form.sni': 'SNI (optionnel)',
    'form.sniPlaceholder': 'par défaut : l\'hôte upstream',
    'form.mode': 'Mode',
    'form.modeLoopback': 'Loopback (recommandé)',
    'form.modeVpn': 'VPN',
    'form.loopbackPort': 'Port loopback',
    'form.pathToken': 'Token d\'isolation dans l\'URL (recommandé, webviews comprises)',
    'form.extraHosts': 'Hôtes canoniques additionnels (optionnel)',
    'form.extraHostsPlaceholder': 'autre.exemple.com, cdn.exemple.com',
    'form.regenerateToken': 'Générer un nouveau token',
    'form.syntheticIp': 'IP synthétique',
    'form.p12': 'Certificat client (.p12 / .pfx)',
    'form.p12Passphrase': 'Passphrase du .p12',
    'form.ca': 'CA upstream épinglée (.pem / .crt)',
    'form.editTitle': 'Modifier « {name} »',
    'form.loading': 'Chargement…',
    'form.chooseApp': '— Choisir l\'app cible —',
    'form.otherApp': 'Autre (saisir le nom du package)…',
    'form.required': 'Nom, app cliente et hôte upstream sont obligatoires.',
    'form.filesRequired': 'Le .p12 et la CA épinglée sont obligatoires.',

    'common.cancel': 'Annuler',
    'common.save': 'Enregistrer',
    'common.close': 'Fermer',

    'bundle.title': 'Importer un bundle',
    'bundle.hint': 'Archive .zip générée par l\'export de l\'app ou par',
    'bundle.file': 'Fichier .zip',
    'bundle.passphrase': 'Passphrase des .p12 du bundle',
    'bundle.submit': 'Importer',
    'bundle.preview': '{total} config(s) : {withKey} avec clé, {withoutKey} sans clé.',
    'bundle.imported': '{withKey} prête(s) à l\'emploi, {withoutKey} sans clé, {skipped} ignorée(s).',

    'key.title': 'Fournir le .p12',
    'key.titleFor': 'Fournir le .p12 de « {name} »',
    'key.hint': 'Le certificat du .p12 doit correspondre à celui de la config.',
    'key.file': 'Fichier .p12 / .pfx',
    'key.passphrase': 'Passphrase',
    'key.submit': 'Importer la clé',
    'key.chooseFile': 'Choisis le fichier .p12.',
    'key.imported': 'Clé importée dans le Keystore de l\'appareil.',

    'events.title': 'Événements',
    'events.titleFor': 'Événements – {name}',
    'events.time': 'Heure',
    'events.type': 'Type',
    'events.details': 'Détails',
    'events.refresh': 'Rafraîchir',
    'events.none': 'Aucun événement.',

    'export.title': 'Exporter les configs',
    'export.hint': 'Certificats publics et métadonnées uniquement : les clés privées restent dans le Keystore de l\'appareil.',
    'export.submit': 'Télécharger le .zip',

    'card.keyMissing': 'Clé manquante',
    'card.token': 'Token',
    'card.enableProxy': 'Activer le proxy',
    'card.active': 'Actif',
    'card.inactive': 'Inactif',
    'card.app': 'App',
    'card.upstream': 'Upstream',
    'card.certificate': 'Certificat',
    'card.clientUrl': 'URL pour l\'app :',
    'card.ephemeralPort': 'port éphémère (voir les événements)',
    'card.copy': 'Copier',
    'card.copied': 'Copié',
    'card.copyFailed': 'Copie impossible',
    'card.provideP12': 'Fournir le .p12',
    'card.edit': 'Modifier',
    'card.events': 'Événements',
    'card.delete': 'Supprimer',

    'security.software': 'Clé logicielle',
    'security.unknown': 'Sécurité inconnue',

    'cert.expired': 'expiré le {date}',
    'cert.expiresSoon': 'expire le {date} ({days} j)',
    'cert.validUntil': 'valide jusqu\'au {date}',

    'notice.enabled': '« {name} » activée.',
    'notice.disabled': '« {name} » désactivée.',
    'notice.deleted': '« {name} » supprimée.',
    'notice.updated': '« {name} » mise à jour.',
    'notice.created': '« {name} » créée. Le proxy démarre sur l\'appareil.',
    'confirm.delete': 'Supprimer « {name} » ?\n\nLa clé privée importée dans le Keystore de l\'appareil ' +
      'sera détruite : il faudra le .p12 d\'origine pour recréer la config.',

    'error.unreachable': 'Appareil injoignable : l\'écran « Configuration à distance » est-il toujours ouvert ?',
    'error.sessionExpired': 'Session expirée : saisis le nouveau PIN.',
    'error.http': 'Erreur {status}',
    'error.fileRead': 'Lecture du fichier impossible',
  },
};

const LANG = String(navigator.language || '').toLowerCase().startsWith('fr') ? 'fr' : 'en';
// Locale for dates: the browser's own one when it matches the UI language,
// otherwise the bare UI language.
const LOCALE = String(navigator.language || '').toLowerCase().startsWith(LANG)
  ? navigator.language
  : LANG;

function t(key, params) {
  let s = I18N[LANG][key];
  if (s === undefined) s = I18N.en[key];
  if (s === undefined) return key;
  if (params) {
    s = s.replace(/\{(\w+)\}/g, (m, name) =>
      Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : m);
  }
  return s;
}

// Fills the static texts of index.html: data-i18n sets textContent,
// data-i18n-placeholder sets the placeholder attribute.
function applyStaticI18n() {
  document.documentElement.lang = LANG;
  document.title = t('page.title');
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
}

const TOKEN_KEY = 'mtls_bridge_token';
const $ = (id) => document.getElementById(id);

const state = {
  token: sessionStorage.getItem(TOKEN_KEY),
  configs: [],
  apps: null,
  vpnRunning: false,
  vpnConsentNeeded: false,
  editing: null, // config being edited, null = creation
  keyTarget: null,
  eventsTarget: null,
  pollTimer: null,
};

// ----- API -------------------------------------------------------------------

class AuthError extends Error {}

async function api(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = 'Bearer ' + state.token;
  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
    });
  } catch (e) {
    throw new Error(t('error.unreachable'));
  }
  if (res.status === 401 && path !== '/api/pair') {
    forgetSession();
    throw new AuthError(t('error.sessionExpired'));
  }
  const type = res.headers.get('content-type') || '';
  if (!type.includes('application/json')) {
    if (!res.ok) throw new Error(t('error.http', { status: res.status }));
    return res;
  }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || t('error.http', { status: res.status }));
  return data;
}

// ----- DOM helpers -----------------------------------------------------------

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function show(id, visible) { $(id).hidden = !visible; }

let noticeTimer = null;
function notice(msg) {
  const el = $('notice');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { el.hidden = true; }, 6000);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(',', 2)[1] || '');
    r.onerror = () => reject(new Error(t('error.fileRead')));
    r.readAsDataURL(file);
  });
}

async function copy(text, button) {
  let ok = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      ok = true;
    }
  } catch (_) { /* fallback below */ }
  if (!ok) {
    const buf = $('copy-buffer');
    buf.value = text;
    buf.select();
    ok = document.execCommand('copy');
  }
  if (button) {
    const old = button.textContent;
    button.textContent = ok ? t('card.copied') : t('card.copyFailed');
    setTimeout(() => { button.textContent = old; }, 1500);
  }
}

function fmtDate(ms) {
  return new Date(ms).toLocaleString(LOCALE, { dateStyle: 'short', timeStyle: 'medium' });
}

// ----- Session ---------------------------------------------------------------

function forgetSession() {
  state.token = null;
  sessionStorage.removeItem(TOKEN_KEY);
  clearInterval(state.pollTimer);
  state.pollTimer = null;
  showPair();
}

function showPair(message) {
  show('main-view', false);
  show('logout-btn', false);
  show('pair-view', true);
  $('pair-error').textContent = message || '';
  $('pin-input').focus();
}

async function pair(pin) {
  const clean = String(pin).replace(/\D/g, '');
  if (clean.length !== 6) {
    $('pair-error').textContent = t('pair.pinLength');
    return;
  }
  try {
    const r = await api('POST', '/api/pair', { pin: clean });
    state.token = r.token;
    sessionStorage.setItem(TOKEN_KEY, r.token);
    $('pin-input').value = '';
    await enterMain();
  } catch (e) {
    $('pair-error').textContent = e.message;
  }
}

async function enterMain() {
  show('pair-view', false);
  show('main-view', true);
  show('logout-btn', true);
  await refresh();
  // Token rejected during the first refresh: we are already back to pairing.
  if (!state.token) return false;
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(() => {
    if (document.visibilityState === 'visible' && !anyDialogOpen()) refresh().catch(() => {});
  }, 10000);
  return true;
}

function anyDialogOpen() {
  return [...document.querySelectorAll('dialog')].some((d) => d.open);
}

// ----- Rendering -------------------------------------------------------------

async function refresh() {
  try {
    const s = await api('GET', '/api/state');
    state.configs = s.configs;
    state.vpnRunning = s.vpnRunning;
    state.vpnConsentNeeded = s.vpnConsentNeeded;
    $('device-line').textContent = `${s.device} · v${s.version}${s.isTv ? ' · Android TV' : ''}`;
    render();
  } catch (e) {
    if (!(e instanceof AuthError)) notice(e.message);
    else showPair(e.message);
  }
}

// Security level -> [i18n key or literal label, badge class].
const SECURITY = {
  STRONGBOX: [null, 'StrongBox', 'ok'],
  TRUSTED_ENVIRONMENT: [null, 'TEE', 'ok'],
  SOFTWARE: ['security.software', null, 'warn'],
  UNKNOWN: ['security.unknown', null, ''],
};

function render() {
  const list = $('config-list');
  list.replaceChildren(...state.configs.map(renderCard));
  show('empty-state', state.configs.length === 0);

  const vpnCount = state.configs.filter((c) => c.mode === 'VPN').length;
  show('vpn-panel', vpnCount > 0);
  if (vpnCount > 0) {
    $('vpn-title').textContent = state.vpnRunning ? t('vpn.running') : t('vpn.stopped');
    $('vpn-sub').textContent = state.vpnConsentNeeded
      ? t('vpn.consentNeeded', { n: vpnCount })
      : t('vpn.count', { n: vpnCount });
    const btn = $('vpn-toggle');
    btn.textContent = state.vpnRunning ? t('vpn.stop') : t('vpn.start');
    btn.className = state.vpnRunning ? 'danger' : 'primary';
    btn.disabled = !state.vpnRunning && state.vpnConsentNeeded;
  }
}

function renderCard(c) {
  const [secKey, secLiteral, secClass] = SECURITY[c.securityLevel] || SECURITY.UNKNOWN;
  const secLabel = secKey ? t(secKey) : secLiteral;
  const badges = h('div', { class: 'badges' },
    h('span', { class: 'badge', text: c.mode === 'VPN' ? 'VPN' : 'Loopback' }),
    h('span', { class: 'badge ' + secClass, text: secLabel }),
    c.needsKeystoreRefresh ? h('span', { class: 'badge bad', text: t('card.keyMissing') }) : null,
    c.pathToken ? h('span', { class: 'badge', text: t('card.token') }) : null,
  );

  const toggle = c.mode === 'LOOPBACK'
    ? h('label', { class: 'switch' },
        h('input', {
          type: 'checkbox',
          checked: c.enabled,
          disabled: c.needsKeystoreRefresh,
          'aria-label': t('card.enableProxy'),
          onchange: (ev) => setEnabled(c, ev.target.checked, ev.target),
        }),
        c.enabled ? t('card.active') : t('card.inactive'))
    : null;

  const kv = h('dl', { class: 'kv' },
    h('dt', { text: t('card.app') }),
    h('dd', { text: c.targetLabel ? `${c.targetLabel} (${c.targetPackage})` : c.targetPackage || '—' }),
    h('dt', { text: t('card.upstream') }),
    h('dd', { text: `${c.upstreamHost}:${c.upstreamPort}${c.sni ? ` · SNI ${c.sni}` : ''}` }),
    c.certNotAfterMs ? h('dt', { text: t('card.certificate') }) : null,
    c.certNotAfterMs ? h('dd', {}, certExpiry(c.certNotAfterMs)) : null,
  );

  const urlRow = h('div', { class: 'url-row' },
    h('span', { class: 'muted', text: t('card.clientUrl') }),
    c.clientUrl ? h('code', { text: c.clientUrl }) : h('span', { class: 'muted', text: t('card.ephemeralPort') }),
    c.clientUrl ? h('button', {
      type: 'button', class: 'small', text: t('card.copy'),
      onclick: (ev) => copy(c.clientUrl, ev.currentTarget),
    }) : null,
  );

  const actions = h('div', { class: 'card-actions' },
    c.needsKeystoreRefresh
      ? h('button', { type: 'button', class: 'small primary', text: t('card.provideP12'), onclick: () => openKeyDialog(c) })
      : null,
    h('button', { type: 'button', class: 'small', text: t('card.edit'), onclick: () => openConfigDialog(c) }),
    h('button', { type: 'button', class: 'small', text: t('card.events'), onclick: () => openEvents(c) }),
    h('button', { type: 'button', class: 'small danger', text: t('card.delete'), onclick: () => removeConfig(c) }),
  );

  return h('article', { class: 'card' },
    h('div', { class: 'card-head' },
      h('div', {}, h('div', { class: 'card-title', text: c.displayName }), badges),
      toggle),
    kv, urlRow, actions);
}

function certExpiry(ms) {
  const days = Math.floor((ms - Date.now()) / 86400000);
  const date = new Date(ms).toLocaleDateString(LOCALE);
  if (days < 0) return h('span', { class: 'badge bad', text: t('cert.expired', { date }) });
  if (days < 30) return h('span', { class: 'badge warn', text: t('cert.expiresSoon', { date, days }) });
  return document.createTextNode(t('cert.validUntil', { date }));
}

// ----- Config actions --------------------------------------------------------

async function setEnabled(c, enabled, input) {
  input.disabled = true;
  try {
    await api('POST', `/api/configs/${encodeURIComponent(c.id)}/enabled`, { enabled });
    notice(t(enabled ? 'notice.enabled' : 'notice.disabled', { name: c.displayName }));
  } catch (e) {
    input.checked = !enabled;
    notice(e.message);
  } finally {
    await refresh();
  }
}

async function removeConfig(c) {
  const ok = confirm(t('confirm.delete', { name: c.displayName }));
  if (!ok) return;
  try {
    await api('DELETE', `/api/configs/${encodeURIComponent(c.id)}`);
    notice(t('notice.deleted', { name: c.displayName }));
  } catch (e) {
    notice(e.message);
  }
  await refresh();
}

async function toggleVpn() {
  try {
    await api('POST', '/api/vpn', { running: !state.vpnRunning });
  } catch (e) {
    notice(e.message);
  }
  // The service takes a moment to start / stop.
  setTimeout(refresh, 1200);
}

// ----- Config form -----------------------------------------------------------

async function loadApps() {
  if (state.apps) return state.apps;
  const r = await api('GET', '/api/apps');
  state.apps = r.apps;
  return state.apps;
}

function nextFreeSyntheticIp() {
  const used = new Set(state.configs.map((c) => c.syntheticIp).filter(Boolean));
  for (let i = 1; i < 254; i++) {
    const ip = `192.0.2.${i}`;
    if (!used.has(ip)) return ip;
  }
  return '';
}

function randomLoopbackPort() {
  return 10001 + Math.floor(Math.random() * (32767 - 10001));
}

async function openConfigDialog(cfg) {
  state.editing = cfg || null;
  const form = $('config-form');
  form.reset();
  $('config-error').textContent = '';
  $('config-dialog-title').textContent = cfg
    ? t('form.editTitle', { name: cfg.displayName })
    : t('main.newConfig');
  show('file-fields', !cfg);
  show('regen-token-row', !!(cfg && cfg.pathToken));

  const select = $('f-targetPackage');
  select.replaceChildren(h('option', { value: '', text: t('form.loading') }));
  $('config-dialog').showModal();

  let apps = [];
  try {
    apps = await loadApps();
  } catch (e) {
    $('config-error').textContent = e.message;
  }
  const current = cfg ? cfg.targetPackage : '';
  const known = apps.some((a) => a.packageName === current);
  select.replaceChildren(
    h('option', { value: '', text: t('form.chooseApp') }),
    ...apps.map((a) => h('option', { value: a.packageName, text: `${a.label} (${a.packageName})` })),
    h('option', { value: '__other__', text: t('form.otherApp') }),
  );
  select.value = current && !known ? '__other__' : current;
  $('f-targetPackageOther').value = current && !known ? current : '';
  syncOtherPackage();

  $('f-displayName').value = cfg ? cfg.displayName : '';
  $('f-upstreamHost').value = cfg ? cfg.upstreamHost : '';
  $('f-upstreamPort').value = cfg ? cfg.upstreamPort : 443;
  $('f-sni').value = cfg && cfg.sni ? cfg.sni : '';
  const mode = cfg ? cfg.mode : 'LOOPBACK';
  form.querySelector(`input[name="mode"][value="${mode}"]`).checked = true;
  $('f-loopbackPort').value = cfg && cfg.loopbackPort ? cfg.loopbackPort : randomLoopbackPort();
  // Token enabled by default on creation: it is the only effective isolation
  // of the loopback mode (webviews get through thanks to the proxy's session
  // cookie).
  $('f-pathTokenEnabled').checked = cfg ? !!cfg.pathToken : true;
  $('f-extraCanonicalHosts').value = cfg && cfg.extraCanonicalHosts ? cfg.extraCanonicalHosts : '';
  $('f-syntheticIp').value = cfg && cfg.syntheticIp ? cfg.syntheticIp : nextFreeSyntheticIp();
  $('f-syntheticPort').value = cfg && cfg.syntheticPort ? cfg.syntheticPort : 5001;
  syncModeFields();
  $('f-displayName').focus();
}

function selectedMode() {
  return $('config-form').querySelector('input[name="mode"]:checked').value;
}

function syncModeFields() {
  const vpn = selectedMode() === 'VPN';
  show('vpn-fields', vpn);
  show('loopback-fields', !vpn);
}

function syncOtherPackage() {
  show('f-targetPackageOther', $('f-targetPackage').value === '__other__');
}

async function submitConfig(ev) {
  ev.preventDefault();
  const err = $('config-error');
  err.textContent = '';
  const pkgChoice = $('f-targetPackage').value;
  const targetPackage = pkgChoice === '__other__' ? $('f-targetPackageOther').value.trim() : pkgChoice;
  const body = {
    displayName: $('f-displayName').value.trim(),
    targetPackage,
    upstreamHost: $('f-upstreamHost').value.trim(),
    upstreamPort: Number($('f-upstreamPort').value || 443),
    sni: $('f-sni').value.trim() || null,
    mode: selectedMode(),
    loopbackPort: Number($('f-loopbackPort').value) || null,
    pathTokenEnabled: $('f-pathTokenEnabled').checked,
    regenerateToken: $('f-regenerateToken').checked,
    extraCanonicalHosts: $('f-extraCanonicalHosts').value.trim() || null,
    syntheticIp: $('f-syntheticIp').value.trim() || null,
    syntheticPort: Number($('f-syntheticPort').value) || null,
  };
  if (!body.displayName || !body.targetPackage || !body.upstreamHost) {
    err.textContent = t('form.required');
    return;
  }
  const submit = $('config-submit');
  submit.disabled = true;
  try {
    if (state.editing) {
      await api('PUT', `/api/configs/${encodeURIComponent(state.editing.id)}`, body);
      notice(t('notice.updated', { name: body.displayName }));
    } else {
      const p12 = $('f-p12').files[0];
      const ca = $('f-ca').files[0];
      if (!p12 || !ca) {
        err.textContent = t('form.filesRequired');
        return;
      }
      body.p12Base64 = await fileToBase64(p12);
      body.caBase64 = await fileToBase64(ca);
      body.p12Passphrase = $('f-p12Passphrase').value;
      await api('POST', '/api/configs', body);
      notice(t('notice.created', { name: body.displayName }));
    }
    $('config-dialog').close();
    await refresh();
  } catch (e) {
    err.textContent = e.message;
  } finally {
    submit.disabled = false;
    $('f-p12Passphrase').value = '';
  }
}

// ----- Key, bundle, export, events -------------------------------------------

function openKeyDialog(c) {
  state.keyTarget = c;
  $('key-form').reset();
  $('key-error').textContent = '';
  $('key-dialog-title').textContent = t('key.titleFor', { name: c.displayName });
  $('key-dialog').showModal();
}

async function submitKey(ev) {
  ev.preventDefault();
  const file = $('k-p12').files[0];
  if (!file) { $('key-error').textContent = t('key.chooseFile'); return; }
  try {
    await api('POST', `/api/configs/${encodeURIComponent(state.keyTarget.id)}/key`, {
      p12Base64: await fileToBase64(file),
      p12Passphrase: $('k-pass').value,
    });
    $('key-dialog').close();
    notice(t('key.imported'));
    await refresh();
  } catch (e) {
    $('key-error').textContent = e.message;
  } finally {
    $('k-pass').value = '';
  }
}

let bundleBase64 = null;

function openBundleDialog() {
  bundleBase64 = null;
  $('bundle-form').reset();
  $('bundle-preview').textContent = '';
  $('bundle-error').textContent = '';
  show('bundle-pass-row', false);
  $('bundle-submit').disabled = true;
  $('bundle-dialog').showModal();
}

async function previewBundle() {
  const file = $('b-zip').files[0];
  $('bundle-error').textContent = '';
  $('bundle-preview').textContent = '';
  $('bundle-submit').disabled = true;
  if (!file) return;
  try {
    bundleBase64 = await fileToBase64(file);
    const p = await api('POST', '/api/bundle/preview', { zipBase64: bundleBase64 });
    $('bundle-preview').textContent = t('bundle.preview', {
      total: p.totalConfigs, withKey: p.withKey, withoutKey: p.withoutKey,
    });
    show('bundle-pass-row', p.needsPassphrase);
    $('bundle-submit').disabled = false;
  } catch (e) {
    $('bundle-error').textContent = e.message;
  }
}

async function submitBundle(ev) {
  ev.preventDefault();
  if (!bundleBase64) return;
  try {
    const pass = $('b-pass').value;
    const r = await api('POST', '/api/bundle/import', {
      zipBase64: bundleBase64,
      passphrase: pass || null,
    });
    $('bundle-dialog').close();
    notice(t('bundle.imported', {
      withKey: r.importedWithKey, withoutKey: r.importedWithoutKey, skipped: r.skipped,
    }));
    await refresh();
  } catch (e) {
    $('bundle-error').textContent = e.message;
  } finally {
    $('b-pass').value = '';
  }
}

function openExportDialog() {
  $('export-list').replaceChildren(...state.configs.map((c) =>
    h('label', { class: 'inline' },
      h('input', { type: 'checkbox', value: c.id, checked: true }),
      c.displayName)));
  $('export-dialog').showModal();
}

async function submitExport(ev) {
  ev.preventDefault();
  const ids = [...$('export-list').querySelectorAll('input:checked')].map((i) => i.value);
  if (ids.length === 0) return;
  try {
    const res = await api('POST', '/api/bundle/export', { ids });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: 'mtls_bridge-backup.zip' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    $('export-dialog').close();
  } catch (e) {
    notice(e.message);
  }
}

async function openEvents(c) {
  state.eventsTarget = c;
  $('events-title').textContent = t('events.titleFor', { name: c.displayName });
  $('events-dialog').showModal();
  await loadEvents();
}

async function loadEvents() {
  const body = $('events-body');
  body.replaceChildren(h('tr', {}, h('td', { colspan: 3, class: 'muted', text: t('form.loading') })));
  try {
    const r = await api('GET', `/api/configs/${encodeURIComponent(state.eventsTarget.id)}/events`);
    body.replaceChildren(...(r.events.length ? r.events.map((e) => h('tr', {},
      h('td', { text: fmtDate(e.timestampMs) }),
      h('td', { class: 'mono', text: e.type }),
      h('td', { class: 'details', text: e.details }))) :
      [h('tr', {}, h('td', { colspan: 3, class: 'muted', text: t('events.none') }))]));
  } catch (e) {
    body.replaceChildren(h('tr', {}, h('td', { colspan: 3, class: 'error', text: e.message })));
  }
}

// ----- Wiring ----------------------------------------------------------------

function wire() {
  $('pair-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    pair($('pin-input').value);
  });
  $('logout-btn').addEventListener('click', async () => {
    try { await api('POST', '/api/logout'); } catch (_) { /* already expired */ }
    forgetSession();
  });
  $('new-config-btn').addEventListener('click', () => openConfigDialog(null));
  $('import-bundle-btn').addEventListener('click', openBundleDialog);
  $('export-btn').addEventListener('click', openExportDialog);
  $('vpn-toggle').addEventListener('click', toggleVpn);

  $('config-form').addEventListener('submit', submitConfig);
  $('config-form').querySelectorAll('input[name="mode"]').forEach((r) => r.addEventListener('change', syncModeFields));
  $('f-targetPackage').addEventListener('change', syncOtherPackage);
  $('key-form').addEventListener('submit', submitKey);
  $('bundle-form').addEventListener('submit', submitBundle);
  $('b-zip').addEventListener('change', previewBundle);
  $('export-form').addEventListener('submit', submitExport);
  $('events-refresh').addEventListener('click', loadEvents);
  document.querySelectorAll('[data-close]').forEach((b) =>
    b.addEventListener('click', () => b.closest('dialog').close()));
}

async function boot() {
  applyStaticI18n();
  wire();
  // The QR code shown by the device carries the PIN in the fragment
  // (#pin=123456), which is never sent to the server. It is consumed here
  // and then removed from the address bar.
  const m = location.hash.match(/pin=(\d{6})/);
  if (m) history.replaceState(null, '', location.pathname);
  if (state.token && await enterMain()) return;
  showPair();
  if (m) await pair(m[1]);
}

boot();
