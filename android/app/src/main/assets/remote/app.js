// Console de configuration à distance de mTLS Bridge.
// Servie par l'appareil lui-même (pas de dépendance externe, CSP stricte) :
// tout le DOM est construit via textContent, jamais innerHTML.
'use strict';

const TOKEN_KEY = 'mtls_bridge_token';
const $ = (id) => document.getElementById(id);

const state = {
  token: sessionStorage.getItem(TOKEN_KEY),
  configs: [],
  apps: null,
  vpnRunning: false,
  vpnConsentNeeded: false,
  editing: null, // config en cours d'édition, null = création
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
    throw new Error("Appareil injoignable : l'écran « Configuration à distance » est-il toujours ouvert ?");
  }
  if (res.status === 401 && path !== '/api/pair') {
    forgetSession();
    throw new AuthError('Session expirée : saisis le nouveau PIN.');
  }
  const type = res.headers.get('content-type') || '';
  if (!type.includes('application/json')) {
    if (!res.ok) throw new Error('Erreur ' + res.status);
    return res;
  }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Erreur ' + res.status);
  return data;
}

// ----- Helpers DOM -----------------------------------------------------------

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
    r.onerror = () => reject(new Error('Lecture du fichier impossible'));
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
  } catch (_) { /* repli ci-dessous */ }
  if (!ok) {
    const buf = $('copy-buffer');
    buf.value = text;
    buf.select();
    ok = document.execCommand('copy');
  }
  if (button) {
    const old = button.textContent;
    button.textContent = ok ? 'Copié ✓' : 'Copie impossible';
    setTimeout(() => { button.textContent = old; }, 1500);
  }
}

function fmtDate(ms) {
  return new Date(ms).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'medium' });
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
    $('pair-error').textContent = 'Le PIN fait 6 chiffres.';
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
  // Jeton refusé pendant le premier refresh : on est déjà revenu à l'appairage.
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

// ----- Rendu -----------------------------------------------------------------

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

const SECURITY = {
  STRONGBOX: ['StrongBox', 'ok'],
  TRUSTED_ENVIRONMENT: ['TEE', 'ok'],
  SOFTWARE: ['Clé logicielle', 'warn'],
  UNKNOWN: ['Sécurité inconnue', ''],
};

function render() {
  const list = $('config-list');
  list.replaceChildren(...state.configs.map(renderCard));
  show('empty-state', state.configs.length === 0);

  const vpnCount = state.configs.filter((c) => c.mode === 'VPN').length;
  show('vpn-panel', vpnCount > 0);
  if (vpnCount > 0) {
    $('vpn-title').textContent = state.vpnRunning ? 'Tunnel VPN actif' : 'Tunnel VPN arrêté';
    $('vpn-sub').textContent = state.vpnConsentNeeded
      ? `${vpnCount} config(s) VPN · l'autorisation VPN doit d'abord être donnée sur l'appareil`
      : `${vpnCount} config(s) en mode VPN`;
    const btn = $('vpn-toggle');
    btn.textContent = state.vpnRunning ? 'Arrêter' : 'Démarrer';
    btn.className = state.vpnRunning ? 'danger' : 'primary';
    btn.disabled = !state.vpnRunning && state.vpnConsentNeeded;
  }
}

function renderCard(c) {
  const [secLabel, secClass] = SECURITY[c.securityLevel] || SECURITY.UNKNOWN;
  const badges = h('div', { class: 'badges' },
    h('span', { class: 'badge', text: c.mode === 'VPN' ? 'VPN' : 'Loopback' }),
    h('span', { class: 'badge ' + secClass, text: secLabel }),
    c.needsKeystoreRefresh ? h('span', { class: 'badge bad', text: 'Clé manquante' }) : null,
    c.pathToken ? h('span', { class: 'badge', text: 'Token' }) : null,
  );

  const toggle = c.mode === 'LOOPBACK'
    ? h('label', { class: 'switch' },
        h('input', {
          type: 'checkbox',
          checked: c.enabled,
          disabled: c.needsKeystoreRefresh,
          'aria-label': 'Activer le proxy',
          onchange: (ev) => setEnabled(c, ev.target.checked, ev.target),
        }),
        c.enabled ? 'Actif' : 'Inactif')
    : null;

  const kv = h('dl', { class: 'kv' },
    h('dt', { text: 'App' }),
    h('dd', { text: c.targetLabel ? `${c.targetLabel} (${c.targetPackage})` : c.targetPackage || '—' }),
    h('dt', { text: 'Upstream' }),
    h('dd', { text: `${c.upstreamHost}:${c.upstreamPort}${c.sni ? ` · SNI ${c.sni}` : ''}` }),
    c.certNotAfterMs ? h('dt', { text: 'Certificat' }) : null,
    c.certNotAfterMs ? h('dd', {}, certExpiry(c.certNotAfterMs)) : null,
  );

  const urlRow = h('div', { class: 'url-row' },
    h('span', { class: 'muted', text: 'URL pour l\'app :' }),
    c.clientUrl ? h('code', { text: c.clientUrl }) : h('span', { class: 'muted', text: 'port éphémère (voir les événements)' }),
    c.clientUrl ? h('button', {
      type: 'button', class: 'small', text: 'Copier',
      onclick: (ev) => copy(c.clientUrl, ev.currentTarget),
    }) : null,
  );

  const actions = h('div', { class: 'card-actions' },
    c.needsKeystoreRefresh
      ? h('button', { type: 'button', class: 'small primary', text: 'Fournir le .p12', onclick: () => openKeyDialog(c) })
      : null,
    h('button', { type: 'button', class: 'small', text: 'Modifier', onclick: () => openConfigDialog(c) }),
    h('button', { type: 'button', class: 'small', text: 'Événements', onclick: () => openEvents(c) }),
    h('button', { type: 'button', class: 'small danger', text: 'Supprimer', onclick: () => removeConfig(c) }),
  );

  return h('article', { class: 'card' },
    h('div', { class: 'card-head' },
      h('div', {}, h('div', { class: 'card-title', text: c.displayName }), badges),
      toggle),
    kv, urlRow, actions);
}

function certExpiry(ms) {
  const days = Math.floor((ms - Date.now()) / 86400000);
  const date = new Date(ms).toLocaleDateString('fr-FR');
  if (days < 0) return h('span', { class: 'badge bad', text: `expiré le ${date}` });
  if (days < 30) return h('span', { class: 'badge warn', text: `expire le ${date} (${days} j)` });
  return document.createTextNode(`valide jusqu'au ${date}`);
}

// ----- Actions sur les configs ----------------------------------------------

async function setEnabled(c, enabled, input) {
  input.disabled = true;
  try {
    await api('POST', `/api/configs/${encodeURIComponent(c.id)}/enabled`, { enabled });
    notice(`« ${c.displayName} » ${enabled ? 'activée' : 'désactivée'}.`);
  } catch (e) {
    input.checked = !enabled;
    notice(e.message);
  } finally {
    await refresh();
  }
}

async function removeConfig(c) {
  const ok = confirm(
    `Supprimer « ${c.displayName} » ?\n\nLa clé privée importée dans le Keystore de l'appareil ` +
    'sera détruite : il faudra le .p12 d\'origine pour recréer la config.');
  if (!ok) return;
  try {
    await api('DELETE', `/api/configs/${encodeURIComponent(c.id)}`);
    notice(`« ${c.displayName} » supprimée.`);
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
  // Le service met un instant à démarrer / s'arrêter.
  setTimeout(refresh, 1200);
}

// ----- Formulaire de config --------------------------------------------------

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
  $('config-dialog-title').textContent = cfg ? `Modifier « ${cfg.displayName} »` : 'Nouvelle config';
  show('file-fields', !cfg);
  show('regen-token-row', !!(cfg && cfg.pathToken));

  const select = $('f-targetPackage');
  select.replaceChildren(h('option', { value: '', text: 'Chargement…' }));
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
    h('option', { value: '', text: '— Choisir l\'app cible —' }),
    ...apps.map((a) => h('option', { value: a.packageName, text: `${a.label} (${a.packageName})` })),
    h('option', { value: '__other__', text: 'Autre (saisir le nom du package)…' }),
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
  // Token activé par défaut à la création : seule isolation effective du
  // loopback (les webviews passent grâce au cookie de session du proxy).
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
    err.textContent = 'Nom, app cliente et hôte upstream sont obligatoires.';
    return;
  }
  const submit = $('config-submit');
  submit.disabled = true;
  try {
    if (state.editing) {
      await api('PUT', `/api/configs/${encodeURIComponent(state.editing.id)}`, body);
      notice(`« ${body.displayName} » mise à jour.`);
    } else {
      const p12 = $('f-p12').files[0];
      const ca = $('f-ca').files[0];
      if (!p12 || !ca) {
        err.textContent = 'Le .p12 et la CA épinglée sont obligatoires.';
        return;
      }
      body.p12Base64 = await fileToBase64(p12);
      body.caBase64 = await fileToBase64(ca);
      body.p12Passphrase = $('f-p12Passphrase').value;
      await api('POST', '/api/configs', body);
      notice(`« ${body.displayName} » créée. Le proxy démarre sur l'appareil.`);
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

// ----- Clé, bundle, export, événements --------------------------------------

function openKeyDialog(c) {
  state.keyTarget = c;
  $('key-form').reset();
  $('key-error').textContent = '';
  $('key-dialog-title').textContent = `Fournir le .p12 de « ${c.displayName} »`;
  $('key-dialog').showModal();
}

async function submitKey(ev) {
  ev.preventDefault();
  const file = $('k-p12').files[0];
  if (!file) { $('key-error').textContent = 'Choisis le fichier .p12.'; return; }
  try {
    await api('POST', `/api/configs/${encodeURIComponent(state.keyTarget.id)}/key`, {
      p12Base64: await fileToBase64(file),
      p12Passphrase: $('k-pass').value,
    });
    $('key-dialog').close();
    notice('Clé importée dans le Keystore de l\'appareil.');
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
    $('bundle-preview').textContent =
      `${p.totalConfigs} config(s) : ${p.withKey} avec clé, ${p.withoutKey} sans clé.`;
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
    notice(`${r.importedWithKey} prête(s) à l'emploi, ${r.importedWithoutKey} sans clé, ${r.skipped} ignorée(s).`);
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
  $('events-title').textContent = `Événements – ${c.displayName}`;
  $('events-dialog').showModal();
  await loadEvents();
}

async function loadEvents() {
  const body = $('events-body');
  body.replaceChildren(h('tr', {}, h('td', { colspan: 3, class: 'muted', text: 'Chargement…' })));
  try {
    const r = await api('GET', `/api/configs/${encodeURIComponent(state.eventsTarget.id)}/events`);
    body.replaceChildren(...(r.events.length ? r.events.map((e) => h('tr', {},
      h('td', { text: fmtDate(e.timestampMs) }),
      h('td', { class: 'mono', text: e.type }),
      h('td', { class: 'details', text: e.details }))) :
      [h('tr', {}, h('td', { colspan: 3, class: 'muted', text: 'Aucun événement.' }))]));
  } catch (e) {
    body.replaceChildren(h('tr', {}, h('td', { colspan: 3, class: 'error', text: e.message })));
  }
}

// ----- Câblage ---------------------------------------------------------------

function wire() {
  $('pair-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    pair($('pin-input').value);
  });
  $('logout-btn').addEventListener('click', async () => {
    try { await api('POST', '/api/logout'); } catch (_) { /* déjà expirée */ }
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
  wire();
  // Le QR code affiché par l'appareil porte le PIN dans le fragment
  // (#pin=123456), qui n'est jamais envoyé au serveur. On le consomme puis
  // on l'efface de la barre d'adresse.
  const m = location.hash.match(/pin=(\d{6})/);
  if (m) history.replaceState(null, '', location.pathname);
  if (state.token && await enterMain()) return;
  showPair();
  if (m) await pair(m[1]);
}

boot();
