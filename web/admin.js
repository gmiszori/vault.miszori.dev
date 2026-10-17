import { CHUNK_SIZE, MAX_BYTES, MAX_FILES, encodeKey, importKey, encryptChunk, serializeManifest, formatBytes } from './crypto.js';

import { validateLabelKey, validateName, deriveNameKey, encryptName, decryptName } from './names.js';

const $ = id => document.getElementById(id);
let labelConfig;
let nameKey = null;
let nameEpoch = 0;
let auditPackages = [];
let renameTarget = null;

function closeNameDialog() {
  renameTarget = null;
  $('rename-name').value = '';
  message('rename-status', '');
  if ($('name-dialog').open) $('name-dialog').close();
}

function lockNames() {
  ++nameEpoch;
  nameKey = null;
  $('names-passphrase').value = '';
  $('names-confirm').value = '';
  $('package-name').value = '';
  $('package-name').disabled = true;
  $('names-form').hidden = false;
  $('unlock-names').disabled = false;
  $('lock-names').hidden = true;
  closeNameDialog();
  for (const row of $('audit-body').children) {
    const label = row.children[0]?.children[0];
    if (label) label.textContent = 'Locked name';
  }
  message('names-status', 'Names locked.');
  void renderList();
}

function reusesAdminPassword(passphrase) {
  const credentials = Uint8Array.from(atob(authorization.slice(6)), char => char.charCodeAt(0));
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(credentials);
    return passphrase === decoded.slice(decoded.indexOf(':') + 1);
  } finally { credentials.fill(0); }
}

async function unlockNames(event) {
  event.preventDefault();
  if (!authorization || nameKey || $('unlock-names').disabled) return;
  const epoch = ++nameEpoch;
  const session = loginAttempt;
  $('unlock-names').disabled = true;
  message('names-status', 'Unlocking names…');
  try {
    const reused = reusesAdminPassword($('names-passphrase').value);
    const keyPromise = reused ? null : deriveNameKey($('names-passphrase').value, labelConfig);
    const matches = $('names-passphrase').value === $('names-confirm').value;
    $('names-passphrase').value = '';
    $('names-confirm').value = '';
    if (reused) throw new Error('Use a strong, different name passphrase, not the admin access password known to the server.');
    const candidate = await keyPromise;
    if (epoch !== nameEpoch || session !== loginAttempt || !authorization) return;
    const data = await (await api('/packages')).json();
    if (epoch !== nameEpoch || session !== loginAttempt || !authorization) return;
    if (!Array.isArray(data.packages)) throw new Error('Could not verify existing names.');
    const existing = data.packages.find(item => item.encryptedName);
    if (existing) {
      try { await decryptName(candidate, existing.id, existing.encryptedName); }
      catch { throw new Error('Passphrase could not unlock the existing names. No names were changed.'); }
    } else if (!matches) throw new Error('First use: enter the same new passphrase twice.');
    if (epoch !== nameEpoch || session !== loginAttempt || !authorization) return;
    nameKey = candidate;
    auditPackages = data.packages;
    $('names-form').hidden = true;
    $('lock-names').hidden = false;
    $('package-name').disabled = uploading;
    message('names-status', 'Names unlocked in this tab only.');
    await renderList();
  } catch (error) {
    if (epoch === nameEpoch && session === loginAttempt) message('names-status', error.message || 'Names could not be unlocked.', true);
  } finally {
    if (epoch === nameEpoch) $('unlock-names').disabled = false;
  }
}

async function savePackageName(id, value, signal) {
  const epoch = nameEpoch;
  const session = loginAttempt;
  if (!nameKey) throw new Error('Unlock names before naming a package.');
  const name = validateName(value);
  const encryptedName = name ? await encryptName(nameKey, id, name) : null;
  if (epoch !== nameEpoch || session !== loginAttempt || !nameKey) throw new Error('Names were locked. Name was not saved.');
  signal?.throwIfAborted();
  await api(`/packages/${encodeURIComponent(id)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ encryptedName }), signal });
}
let authorization = '';
let publicOrigin = '';
let selected = [];
let uploading = false;
let uploadController;
let currentPackage = null;
let listing = false;
let pendingDelete = null;
let loginAttempt = 0;

function message(id, text, error = false) {
  $(id).textContent = text;
  $(id).classList.toggle('error', error);
}

async function api(path, options = {}) {
  const response = await fetch(`/admin/api${path}`, {
    ...options,
    headers: { ...options.headers, Authorization: authorization },
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    signal: options.signal || AbortSignal.timeout(30000)
  });
  if (!response.ok) {
    await response.body?.cancel();
    const errors = {
      401: 'Sign-in failed or credentials are no longer valid. Sign out and sign in again.',
      403: 'Access denied. Connect to the private VPN and check your credentials.',
      404: 'This package no longer exists.',
      409: 'Package state changed, or this record already exists. Uploads cannot be retried.',
      413: 'The server rejected the package size.',
      429: 'Too many requests. Please wait before trying again.'
    };
    throw new Error(errors[response.status] || `The server could not complete the request (HTTP ${response.status}).`);
  }
  return response;
}

function forgetLink() {
  $('share-link').value = '';
  $('result-panel').hidden = true;
  message('copy-status', '');
}

async function login(event) {
  event.preventDefault();
  if (!window.isSecureContext || !crypto.subtle) return;
  const attempt = ++loginAttempt;
  const username = $('username').value;
  const password = $('password').value;
  if (username.includes(':')) {
    message('login-status', 'A Basic Auth username cannot contain a colon.', true);
    return;
  }
  $('login-button').disabled = true;
  message('login-status', 'Signing in…');
  const raw = new TextEncoder().encode(`${username}:${password}`);
  authorization = `Basic ${btoa(String.fromCharCode(...raw))}`;
  raw.fill(0);
  $('password').value = '';
  try {
    const config = await (await api('/config')).json();
    const origin = new URL(config.publicOrigin);
    const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
    const loopback = origin.protocol === 'http:' && loopbackHosts.has(origin.hostname) && loopbackHosts.has(location.hostname) && window.isSecureContext;
    if ((origin.protocol !== 'https:' && !loopback) || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('The server must provide a valid HTTPS public origin (HTTP is allowed only on localhost for development).');
    if (attempt !== loginAttempt) return;
    labelConfig = validateLabelKey(config.labelKey);
    publicOrigin = origin.origin;
    $('username').value = '';
    $('login-panel').hidden = true;
    $('workspace').hidden = false;
    $('logout').hidden = false;
    message('login-status', '');
    $('compose-title').setAttribute('tabindex', '-1');
    $('compose-title').focus();
    await refreshList();
  } catch (error) {
    if (attempt !== loginAttempt) return;
    authorization = '';
    message('login-status', error.message || 'Could not connect. Check the VPN and try again.', true);
  } finally {
    $('login-button').disabled = !crypto.subtle;
  }
}

function selectionView() {
  $('selection').hidden = !selected.length;
  $('file-list').replaceChildren();
  if (selected.length) {
    const bytes = selected.reduce((sum, file) => sum + file.size, 0);
    $('selection-summary').textContent = `${selected.length.toLocaleString()} ${selected.length === 1 ? 'file' : 'files'} · ${formatBytes(bytes)}`;
    for (const file of selected.slice(0, 6)) {
      const li = document.createElement('li');
      const name = document.createElement('span');
      name.textContent = file.webkitRelativePath || file.name;
      const size = document.createElement('span');
      size.textContent = formatBytes(file.size);
      li.append(name, size);
      $('file-list').append(li);
    }
    if (selected.length > 6) {
      const li = document.createElement('li');
      li.textContent = `And ${(selected.length - 6).toLocaleString()} more files`;
      li.className = 'muted';
      $('file-list').append(li);
    }
  }
  $('upload-button').disabled = uploading || !selected.length || !crypto.subtle;
}

function describeFiles(files) {
  return files.map(file => ({ path: file.webkitRelativePath || file.name, size: file.size, lastModified: file.lastModified }));
}

function addFiles(incoming) {
  if (uploading || !incoming.length) return;
  try {
    if (selected.length + incoming.length > MAX_FILES) throw new Error('Choose no more than 20,000 files per transfer.');
    const candidates = [...selected, ...incoming];
    // Validate the exact same manifest that will be encrypted, before any API call.
    serializeManifest(describeFiles(candidates));
    selected = candidates;
    selectionView();
    message('upload-status', 'Files selected. Nothing has been uploaded yet.');
  } catch (error) {
    message('upload-status', error.message, true);
  }
}

function setBusy(value) {
  uploading = value;
  for (const id of ['file-input', 'folder-input', 'clear-files', 'ttl', 'custom-ttl', 'logout']) $(id).disabled = value;
  $('package-name').disabled = value || !nameKey;
  $('drop-zone').classList.toggle('disabled', value);
  $('upload-progress').hidden = !value;
  $('abort-upload').disabled = false;
  selectionView();
}

function uploadProgress(completed, total, stage) {
  const percent = Math.floor(completed / total * 100);
  $('upload-meter').value = percent;
  $('upload-percent').textContent = `${percent}%`;
  $('upload-stage').textContent = stage;
}

async function upload() {
  if (uploading || !selected.length) return;
  let validated;
  let ttlSeconds;
  try {
    if (nameKey) validateName($('package-name').value);
    validated = serializeManifest(describeFiles(selected));
    ttlSeconds = $('ttl').value === 'custom' ? Number($('custom-ttl').value) * 60 : Number($('ttl').value);
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 2592000 || ($('ttl').value === 'custom' && !Number.isInteger(Number($('custom-ttl').value)))) throw new Error('Choose an expiry between 1 minute and 30 days, in whole minutes.');
    if (validated.bytes > MAX_BYTES) throw new Error('The package exceeds 20 GiB.');
  } catch (error) {
    message('upload-status', error.message, true);
    return;
  }
  forgetLink();
  setBusy(true);
  uploadController = new AbortController();
  const signal = uploadController.signal;
  const uploadNameEpoch = nameEpoch;
  const naming = !!nameKey && !!validateName($('package-name').value);
  currentPackage = null;
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  let completed = false;
  let uploadToken = '';
  uploadProgress(0, validated.chunks, 'Creating your encrypted package…');
  message('upload-status', 'Keep this tab open until your private link is ready.');
  try {
    const key = await importKey(rawKey);
    signal.throwIfAborted();
    // Let creation return its ID even if cancellation is requested, so cleanup can delete it.
    const created = await (await api('/packages', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ttlSeconds }) })).json();
    if (typeof created.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(created.id)) throw new Error('The server returned an invalid package identifier. Check Transfer activity for an incomplete package.');
    currentPackage = created.id;
    if (typeof created.uploadToken !== 'string' || !created.uploadToken || !Number.isFinite(Date.parse(created.expiresAt))) throw new Error('The server returned an invalid upload session.');
    uploadToken = created.uploadToken;
    signal.throwIfAborted();
    if (naming) {
      if (uploadNameEpoch !== nameEpoch || !nameKey) throw new Error('Names were locked before the package name was saved.');
      await savePackageName(currentPackage, $('package-name').value, signal);
      $('package-name').value = '';
      signal.throwIfAborted();
    }
    let index = 0;
    let sentBytes = 0;
    const send = async plaintext => {
      signal.throwIfAborted();
      const ciphertext = await encryptChunk(key, currentPackage, index, plaintext);
      signal.throwIfAborted();
      await api(`/packages/${encodeURIComponent(currentPackage)}/chunks/${index}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/octet-stream', 'X-Upload-Token': uploadToken }, body: ciphertext, signal
      });
      index++;
      uploadProgress(index, validated.chunks, `Encrypted ${formatBytes(sentBytes)} of ${formatBytes(validated.bytes)} · ${index.toLocaleString()} / ${validated.chunks.toLocaleString()} records`);
    };
    await send(validated.plaintext);
    for (const file of selected) {
      for (let offset = 0; offset < file.size; offset += CHUNK_SIZE) {
        signal.throwIfAborted();
        const bytes = new Uint8Array(await file.slice(offset, offset + CHUNK_SIZE).arrayBuffer());
        if (bytes.length !== Math.min(CHUNK_SIZE, file.size - offset)) throw new Error('A selected file changed or could not be read. Choose the files again.');
        sentBytes += bytes.length;
        await send(bytes);
      }
    }
    signal.throwIfAborted();
    if (index !== validated.chunks) throw new Error('The uploaded record count is inconsistent.');
    $('upload-stage').textContent = 'Sealing package…';
    await api(`/packages/${encodeURIComponent(currentPackage)}/finalize`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Upload-Token': uploadToken }, body: JSON.stringify({ chunks: index }), signal
    });
    signal.throwIfAborted();
    $('share-link').value = `${publicOrigin}/package/${currentPackage}#${encodeKey(rawKey)}`;
    $('link-expiry').textContent = `Expires ${new Date(created.expiresAt).toLocaleString()}, or immediately after it is claimed.`;
    $('result-panel').hidden = false;
    message('upload-status', 'Encrypted, uploaded, and ready. Copy the share link below.');
    selected = [];
    completed = true;
    $('copy-link').focus();
  } catch (error) {
    let cleanup = '';
    if (currentPackage) {
      $('upload-stage').textContent = 'Deleting incomplete package…';
      try {
        await api(`/packages/${encodeURIComponent(currentPackage)}`, { method: 'DELETE', signal: AbortSignal.timeout(15000) });
        cleanup = ' The server package was deleted.';
      } catch {
        cleanup = ` Cleanup could not be confirmed. Delete package ${currentPackage} in Transfer activity; otherwise it remains until expiry.`;
      }
    } else {
      cleanup = ' If creation reached the server, an incomplete package may appear in Transfer activity. Delete it there or let it expire.';
    }
    message('upload-status', `${signal.aborted ? 'Upload cancelled.' : error.message || 'Upload failed. Uploads are never retried.'}${cleanup}`, true);
  } finally {
    rawKey.fill(0);
    uploadToken = '';
    currentPackage = null;
    uploadController = null;
    setBusy(false);
    if (!completed) forgetLink();
    await refreshList();
  }
}

function date(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : '—';
}

function cell(row, primary, secondary) {
  const td = document.createElement('td');
  const first = document.createElement('span');
  first.textContent = primary;
  td.append(first);
  if (secondary) {
    const sub = document.createElement('span');
    sub.className = 'table-secondary';
    sub.textContent = secondary;
    td.append(sub);
  }
  row.append(td);
  return td;
}

async function refreshList() {
  if (!authorization || listing) return;
  listing = true;
  $('refresh-list').disabled = true;
  message('audit-status', 'Loading transfer activity…');
  const sessionAuth = authorization;
  const session = loginAttempt;
  try {
    const data = await (await api('/packages')).json();
    if (sessionAuth !== authorization || session !== loginAttempt) return;
    if (!Array.isArray(data.packages)) throw new Error('The server returned an invalid package list.');
    auditPackages = data.packages;
    await renderList();
  } catch (error) {
    if (sessionAuth === authorization && session === loginAttempt) message('audit-status', `${error.message || 'Activity could not be loaded.'} Displayed data may be out of date.`, true);
  } finally {
    listing = false;
    $('refresh-list').disabled = false;
  }
}

function packageActions(item, knownStatus, epoch) {
  const id = String(item.id);
  const action = document.createElement('td');
  if (knownStatus !== 'deleted' && /^[A-Za-z0-9_-]{1,128}$/.test(item.id)) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'text-button danger';
    button.textContent = 'Delete';
    button.setAttribute('aria-label', `Delete package ${item.id}`);
    button.addEventListener('click', () => {
      pendingDelete = { id: item.id, button };
      $('delete-description').textContent = `Package ${item.id}`;
      $('delete-dialog').returnValue = '';
      $('delete-dialog').showModal();
    });
    action.append(button);
  }
  if (nameKey && /^[A-Za-z0-9_-]{1,128}$/.test(id)) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'text-button';
    button.textContent = 'Name';
    button.setAttribute('aria-label', `Name package ${id}`);
    button.addEventListener('click', () => {
      if (!nameKey || epoch !== nameEpoch) return;
      renameTarget = id;
      $('rename-name').value = '';
      message('rename-status', 'Enter a new name, or leave empty to remove it.');
      $('name-dialog').showModal();
      $('rename-name').focus();
    });
    action.append(button);
  }
  return action;
}

async function renderList() {
  const epoch = nameEpoch;
  const session = loginAttempt;
  const packages = auditPackages;
  const fragment = document.createDocumentFragment();
  let unreadable = 0;
  const statuses = new Set(['uploading', 'ready', 'consuming', 'consumed', 'expired', 'deleted', 'failed']);
  for (const item of [...packages].sort((a, b) => (Date.parse(b.createdAt) || 0) - (Date.parse(a.createdAt) || 0))) {
    const row = document.createElement('tr');
    const id = String(item.id);
    let label = id.length > 12 ? `${id.slice(0, 12)}…` : id;
    if (item.encryptedName) {
      label = 'Locked name';
      if (nameKey) {
        try { label = await decryptName(nameKey, id, item.encryptedName); }
        catch { ++unreadable; }
      }
    }
    if (epoch !== nameEpoch || session !== loginAttempt) return;
    const packageCell = cell(row, label);
    packageCell.className = 'package-id';
    packageCell.title = id;
    const state = document.createElement('span');
    const knownStatus = statuses.has(item.status) ? item.status : 'unknown';
    state.className = `status-badge status-${knownStatus}`;
    state.textContent = knownStatus;
    const td = document.createElement('td');
    td.append(state);
    row.append(td);
    cell(row, date(item.createdAt), `Expires ${date(item.expiresAt)}`);
    cell(row, Number.isSafeInteger(item.bytes) && item.bytes >= 0 ? formatBytes(item.bytes) : '—', `${Number.isSafeInteger(item.chunks) ? item.chunks.toLocaleString() : '—'} records`);
    const opened = cell(row, date(item.openedAt), item.openedIp || 'Not opened');
    const profile = document.createElement('span');
    profile.className = 'table-secondary';
    const browser = item.openedBrowser;
    profile.textContent = browser ? [browser.browser, browser.os, browser.deviceType].map(value => typeof value === 'string' && value ? value : '—').join(' / ') : '—';
    if (typeof browser?.userAgent === 'string') profile.title = browser.userAgent;
    opened.append(profile);
    const action = packageActions(item, knownStatus, epoch);
    row.append(action);
    fragment.append(row);
  }
  if (epoch !== nameEpoch || session !== loginAttempt) return;
  $('audit-body').replaceChildren(fragment);
  $('audit-table').hidden = !packages.length;
  $('audit-empty').hidden = !!packages.length;
  message('audit-status', `${packages.length.toLocaleString()} ${packages.length === 1 ? 'transfer' : 'transfers'} · Updated ${new Date().toLocaleTimeString()}`);
  if (unreadable) message('names-status', `${unreadable} historic name(s) could not be decrypted and remain locked. They were not changed.`, true);
}

$('delete-dialog').addEventListener('close', async () => {
  const target = pendingDelete;
  pendingDelete = null;
  if ($('delete-dialog').returnValue !== 'confirm' || !target) return;
  target.button.disabled = true;
  message('audit-status', 'Deleting package…');
  try {
    await api(`/packages/${encodeURIComponent(target.id)}`, { method: 'DELETE' });
    if ($('share-link').value.startsWith(`${publicOrigin}/package/${target.id}#`)) forgetLink();
    await refreshList();
  } catch (error) {
    message('audit-status', `${error.message} Deletion could not be confirmed. Refresh before retrying.`, true);
    target.button.disabled = false;
  }
});

$('names-form').addEventListener('submit', unlockNames);
$('lock-names').addEventListener('click', lockNames);
$('cancel-name').addEventListener('click', closeNameDialog);
$('name-dialog').addEventListener('close', () => { renameTarget = null; $('rename-name').value = ''; });
$('rename-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!renameTarget || !nameKey) return;
  const epoch = nameEpoch;
  $('save-name').disabled = true;
  try {
    await savePackageName(renameTarget, $('rename-name').value);
    if (epoch !== nameEpoch) return;
    closeNameDialog();
    await refreshList();
  } catch (error) {
    if (epoch === nameEpoch) message('rename-status', error.message || 'Name could not be saved.', true);
  } finally { $('save-name').disabled = false; }
});

$('login-form').addEventListener('submit', login);
$('logout').addEventListener('click', () => {
  if (uploading) return;
  ++loginAttempt;
  auditPackages = [];
  lockNames();
  labelConfig = undefined;
  authorization = '';
  publicOrigin = '';
  selected = [];
  forgetLink();
  selectionView();
  $('audit-body').replaceChildren();
  $('login-panel').hidden = false;
  $('workspace').hidden = true;
  $('logout').hidden = true;
  $('username').focus();
  message('login-status', 'Signed out. Credentials and the share link were forgotten.');
  message('upload-status', '');
});
for (const id of ['file-input', 'folder-input']) $(id).addEventListener('change', event => {
  addFiles(Array.from(event.target.files));
  event.target.value = '';
});
$('clear-files').addEventListener('click', () => { selected = []; selectionView(); message('upload-status', ''); });
$('ttl').addEventListener('change', () => { $('custom-ttl-field').hidden = $('ttl').value !== 'custom'; });
$('upload-button').addEventListener('click', upload);
$('abort-upload').addEventListener('click', () => {
  uploadController?.abort();
  $('abort-upload').disabled = true;
  $('upload-stage').textContent = 'Cancelling and cleaning up…';
});
$('refresh-list').addEventListener('click', refreshList);
$('hide-link').addEventListener('click', forgetLink);
$('copy-link').addEventListener('click', async () => {
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText($('share-link').value);
    message('copy-status', 'Private link copied. Share it only with your recipient.');
  } catch {
    $('share-link').focus();
    $('share-link').select();
    message('copy-status', 'Copy is unavailable. The link is selected; use your browser’s Copy command.');
  }
});
for (const type of ['dragenter', 'dragover']) $('drop-zone').addEventListener(type, event => {
  event.preventDefault();
  if (!uploading) $('drop-zone').classList.add('drag-over');
});
$('drop-zone').addEventListener('dragleave', event => {
  if (!$('drop-zone').contains(event.relatedTarget)) $('drop-zone').classList.remove('drag-over');
});
$('drop-zone').addEventListener('drop', event => {
  event.preventDefault();
  $('drop-zone').classList.remove('drag-over');
  if (Array.from(event.dataTransfer.items).some(item => item.webkitGetAsEntry?.()?.isDirectory)) {
    message('upload-status', 'For folders, use “Choose folder” so every relative path is preserved.', true);
    return;
  }
  addFiles(Array.from(event.dataTransfer.files));
});
// Prevent a missed drop from navigating away and losing an in-memory key.
window.addEventListener('dragover', event => event.preventDefault());
window.addEventListener('drop', event => event.preventDefault());
window.addEventListener('beforeunload', event => {
  if (uploading || !$('result-panel').hidden) { event.preventDefault(); event.returnValue = ''; }
});
window.addEventListener('pagehide', () => {
  ++loginAttempt;
  auditPackages = [];
  lockNames();
  labelConfig = undefined;
  uploadController?.abort();
  authorization = '';
  publicOrigin = '';
  selected = [];
  forgetLink();
  $('audit-body').replaceChildren();
  $('workspace').hidden = true;
  $('logout').hidden = true;
  $('login-panel').hidden = false;
});
if (!window.isSecureContext || !crypto.subtle) {
  $('crypto-warning').hidden = false;
  $('login-button').disabled = true;
}
