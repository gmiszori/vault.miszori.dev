import { CHUNK_SIZE, MEMORY_LIMIT, decodeKey, importKey, decryptChunk, parseManifest, parseTextManifest, FramedReader, formatBytes, deriveClaimToken } from './crypto.js';
import { ZipWriter, archiveSize } from './zip.js';
import { prepareServiceWorkerDownload } from './download.js';

let fragment = location.hash.slice(1);
if (location.hash) history.replaceState(null, '', location.pathname + location.search);
const $ = id => document.getElementById(id);
const route = /^\/package\/([A-Za-z0-9_-]{1,128})\/?$/.exec(location.pathname);
const supportsStreaming = typeof window.showSaveFilePicker === 'function' && window.isSecureContext;
const supportsLocalStreaming = window.isSecureContext && Boolean(globalThis.navigator?.serviceWorker) && typeof MessageChannel === 'function' && typeof ReadableStream === 'function';
let blobFallbackOffered = !supportsLocalStreaming;
let keyBytes;
let available = false;
let oneTime = true;
let packageFormat = 'files';
let busy = false;
let expiresAt = 0;
let controller;
let blobURL;
let initialization = 0;

function status(message, error = false) {
  $('download-status').textContent = message;
  $('download-status').classList.toggle('error', error);
}

function updateButton() {
  $('download-consent').disabled = busy || !available;
  $('download-button').disabled = !available || busy || (oneTime && !$('download-consent').checked);
}

function packageState(label) {
  const element = $('package-state');
  element.textContent = label;
  element.classList.toggle('status-ready', label === 'Ready');
  element.classList.toggle('status-unavailable', label === 'Unavailable');
  element.classList.toggle('status-downloading', label === 'Downloading');
}

function progress(bytes, total) {
  const percent = total ? Math.floor(bytes / total * 100) : 100;
  $('download-meter').value = percent;
  $('download-percent').textContent = `${percent}%`;
  $('download-stage').textContent = `Decrypting ${formatBytes(bytes)} of ${formatBytes(total)}`;
}

function memorySink(filename) {
  let parts = [];
  let bytes = 0;
  return {
    async write(part) {
      if (bytes + part.byteLength > MEMORY_LIMIT) throw new Error('The archive exceeds this browser’s strict 128 MiB memory limit.');
      parts.push(part);
      bytes += part.byteLength;
    },
    async close() {
      const blob = new Blob(parts, { type: 'application/zip' });
      parts = [];
      blobURL = URL.createObjectURL(blob);
      const link = $('save-archive');
      link.href = blobURL;
      link.download = filename;
      link.hidden = false;
      link.click();
    },
    async abort() { parts = []; }
  };
}

async function download() {
  if (!available || busy || (oneTime && !$('download-consent').checked)) return;
  if (Date.now() >= expiresAt) {
    available = false;
    packageState('Unavailable');
    updateButton();
    status('This package has expired. Ask the sender for a new link.', true);
    return;
  }
  if (packageFormat === 'text') { await viewText(); return; }
  busy = true;
  updateButton();
  status('Choose a destination. The transfer has not started yet.');
  const id = route[1];
  const filename = `vault-${id.slice(0, 12)}.zip`;
  let consumed = false;
  let unavailableResponse = false;
  let sink;
  let frames;
  let boundedFallback = false;
  let localStream = false;
  controller = new AbortController();
  $('download-meter').classList.toggle('is-complete', false);
  $('download-meter').value = 0;
  $('download-percent').textContent = '0%';
  $('save-archive').hidden = true;
  if (blobURL) { URL.revokeObjectURL(blobURL); blobURL = null; }
  try {
    // Invoke the picker during the click gesture, before any asynchronous work.
    const destination = supportsStreaming ? await window.showSaveFilePicker({
      suggestedName: filename,
      types: [{ description: 'ZIP archive (all package files)', accept: { 'application/zip': ['.zip'] } }]
    }) : null;
    if (destination) sink = await destination.createWritable();
    else {
      if (!blobFallbackOffered) {
        sink = await prepareServiceWorkerDownload({ signal: controller.signal, onFailure: error => controller.abort(error) });
        if (!sink) {
          blobFallbackOffered = true;
          $('fallback-warning').hidden = false;
          $('download-consent').checked = false;
          status(oneTime ? 'Streaming downloads are unavailable. The fallback is limited to 128 MiB, and encrypted package sizes cannot be checked before claiming. Nothing has been claimed. For larger or unknown packages, use a browser with working streaming downloads. To accept this limit, check consent again and press Download.' : 'Streaming downloads are unavailable. The fallback is limited to 128 MiB. Press Download again to try the fallback, or use a browser with streaming support.');
          return;
        }
      }
      localStream = Boolean(sink);
      if (!sink) {
        sink = memorySink(filename);
        boundedFallback = true;
      }
    }
    $('fallback-warning').hidden = !boundedFallback;
    controller.signal.throwIfAborted();
    const key = await importKey(keyBytes);
    const claimToken = await deriveClaimToken(keyBytes, id);
    controller.signal.throwIfAborted();
    $('download-progress').hidden = false;
    $('cancel-download').hidden = false;
    $('download-stage').textContent = 'Claiming encrypted package…';
    status('');
    consumed = true;
    available = false;
    packageState('Downloading');
    const response = await fetch(`/api/packages/${encodeURIComponent(id)}/consume`, {
      method: 'POST', headers: { 'X-Claim-Token': claimToken }, signal: controller.signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer'
    });
    if (response.status === 429) {
      consumed = false;
      available = Boolean(keyBytes);
      controller.abort();
      try { await response.body?.cancel(); } catch { /* The rejection body may already be closed. */ }
      try { await sink?.abort(); } catch { /* The destination may already be closed. */ }
      packageState(available ? 'Ready' : 'Unavailable');
      $('download-progress').hidden = true;
      $('download-meter').value = 0;
      $('download-percent').textContent = '0%';
      $('download-stage').textContent = 'Not started';
      status('The server is busy. Your package has not been claimed. Wait a moment, then press Download to try again.', true);
      return;
    }
    if (!response.ok) {
      await response.body?.cancel();
      unavailableResponse = response.status === 404 || response.status === 409 || response.status === 410;
      throw new Error(unavailableResponse
        ? 'This package does not exist, or it has already been claimed, deleted, or expired.'
        : 'The server could not start the transfer. Ask the sender to check its status.');
    }
    frames = new FramedReader(response.body);
    const { manifest, bytes, chunks } = parseManifest(await decryptChunk(key, id, 0, await frames.record()));
    const size = archiveSize(manifest.files);
    if (boundedFallback && size > MEMORY_LIMIT) {
      throw new Error(oneTime ? 'This archive is larger than the 128 MiB browser limit. No file data was saved. The one-time transfer has already been claimed; ask the sender for a new link and use a browser with supported streaming downloads, such as desktop Chrome or Edge.' : 'This archive exceeds the 128 MiB browser limit. Use a browser with streaming downloads. The package remains available until expiry.');
    }
    if (localStream) await sink.initialize(filename, size);
    const archive = new ZipWriter(sink);
    let index = 1;
    let received = 0;
    for (const file of manifest.files) {
      await archive.startFile(file);
      for (let offset = 0; offset < file.size; offset += CHUNK_SIZE) {
        controller.signal.throwIfAborted();
        const plaintext = await decryptChunk(key, id, index++, await frames.record());
        if (plaintext.length !== Math.min(CHUNK_SIZE, file.size - offset)) throw new Error('Decrypted file size does not match the manifest.');
        await archive.write(plaintext);
        received += plaintext.length;
        progress(received, bytes);
      }
      await archive.endFile();
    }
    if (index !== chunks) throw new Error('The package record count is invalid.');
    await frames.end();
    controller.signal.throwIfAborted();
    await archive.close();
    progress(bytes, bytes);
    $('download-meter').classList.toggle('is-complete', true);
    $('download-stage').textContent = 'Decrypted & saved';
    packageState('Downloaded');
    $('package-title').textContent = 'Package downloaded';
    $('package-description').textContent = 'Your files are in the ZIP archive. The server copy has been destroyed.';
    $('availability').textContent = 'Claimed — no longer on the server';
    status(boundedFallback ? 'Archive ready. If your browser did not save it automatically, use “Save decrypted ZIP archive” below.' : localStream ? 'Archive sent to your browser’s download manager. Check that it finished saving before closing this tab.' : 'Archive saved. Open the .zip file to access your files.');
    $('download-button').hidden = true;
    $('consent-label').hidden = true;
    $('download-warning').hidden = true;
    if (oneTime) {
      keyBytes.fill(0);
      keyBytes = null;
    } else {
      available = Date.now() < expiresAt;
      packageState(available ? 'Ready' : 'Unavailable');
      $('package-title').textContent = 'Package ready to download';
      $('package-description').textContent = 'Your files are in the ZIP archive.';
      $('availability').textContent = `Until ${new Date(expiresAt).toLocaleString()}`;
      $('download-button').hidden = !available;
    }
  } catch (error) {
    const aborted = error.name === 'AbortError';
    status(consumed
      ? `${aborted ? 'Transfer cancelled.' : error.message} This transfer cannot be resumed. Ask the sender for a new package.`
      : aborted ? 'Save cancelled. Your package has not been claimed.' : `Could not prepare a save destination. ${error.message} Your package has not been claimed.`, !aborted || consumed);
    if (!oneTime) {
      available = !unavailableResponse && Boolean(keyBytes) && Date.now() < expiresAt;
      packageState(available ? 'Ready' : 'Unavailable');
      status(`${aborted ? 'Transfer cancelled.' : error.message}${available ? ' You can try again before expiry.' : ''}`, !aborted);
      if (!available) { keyBytes?.fill(0); keyBytes = null; }
    } else if (consumed) {
      packageState('Unavailable');
      $('package-title').textContent = 'Package unavailable';
      $('package-description').textContent = 'This transfer has stopped and cannot be resumed. Ask the sender for a new package.';
      $('availability').textContent = 'Claimed or unavailable';
      $('download-stage').textContent = 'Transfer stopped — not recoverable';
      keyBytes?.fill(0);
      keyBytes = null;
    }
    controller?.abort();
    await frames?.cancel();
    try { await sink?.abort(); } catch { /* The destination may already be closed. */ }
  } finally {
    busy = false;
    $('cancel-download').hidden = true;
    updateButton();
  }
}

function clearText() {
  $('revealed-text').value = '';
  $('text-result').hidden = true;
  $('copy-text-status').textContent = '';
}

async function viewText() {
  busy = true;
  updateButton();
  clearText();
  const attempt = initialization;
  let started = false;
  let unavailableResponse = false;
  let frames;
  let plaintext;
  controller = new AbortController();
  const signal = controller.signal;
  $('cancel-download').hidden = false;
  status('Decrypting secret…');
  try {
    const key = await importKey(keyBytes);
    const token = await deriveClaimToken(keyBytes, route[1]);
    signal.throwIfAborted();
    started = true;
    available = false;
    packageState('Opening');
    const response = await fetch(`/api/packages/${encodeURIComponent(route[1])}/consume`, {
      method: 'POST', headers: { 'X-Claim-Token': token }, signal,
      credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer'
    });
    if (response.status === 429) {
      started = false;
      await response.body?.cancel();
      throw new Error('The server is busy. Nothing has been opened. Try again.');
    }
    if (!response.ok) {
      unavailableResponse = [404, 409, 410].includes(response.status);
      await response.body?.cancel();
      throw new Error(unavailableResponse ? 'This package is unavailable.' : 'Could not open the secret.');
    }
    frames = new FramedReader(response.body);
    const manifestBytes = await decryptChunk(key, route[1], 0, await frames.record());
    const manifest = parseTextManifest(manifestBytes);
    manifestBytes.fill(0);
    plaintext = await decryptChunk(key, route[1], 1, await frames.record());
    if (plaintext.byteLength !== manifest.size) throw new Error('Secret size does not match its encrypted manifest.');
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
    await frames.end();
    signal.throwIfAborted();
    if (attempt !== initialization) return;
    $('revealed-text').value = text;
    $('text-result').hidden = false;
    $('package-title').textContent = 'Secret';
    $('package-description').textContent = oneTime ? 'The server copy has been destroyed.' : '';
    $('consent-label').hidden = true;
    $('download-warning').hidden = true;
    if (oneTime) {
      keyBytes?.fill(0);
      keyBytes = null;
      $('download-button').hidden = true;
      $('availability').textContent = 'Opened — no longer on the server';
      packageState('Viewed');
    } else {
      available = Date.now() < expiresAt;
      packageState(available ? 'Ready' : 'Unavailable');
    }
    status('Secret decrypted.');
  } catch (error) {
    if (attempt !== initialization) return;
    clearText();
    available = (!oneTime || !started) && !unavailableResponse && Boolean(keyBytes) && Date.now() < expiresAt;
    packageState(available ? 'Ready' : 'Unavailable');
    status(`${error.name === 'AbortError' ? 'Opening cancelled.' : error.message}${oneTime && started ? ' This one-time package cannot be opened again.' : available ? ' You can try again before expiry.' : ''}`, true);
    if (!available) { keyBytes?.fill(0); keyBytes = null; }
    controller.abort();
    await frames?.cancel();
  } finally {
    plaintext?.fill(0);
    if (attempt === initialization) {
      busy = false;
      $('cancel-download').hidden = true;
      updateButton();
    }
  }
}

async function initialize() {
  const attempt = ++initialization;
  clearText();
  available = false;
  keyBytes?.fill(0);
  keyBytes = null;
  updateButton();
  $('checking-card').hidden = false;
  $('package-card').hidden = true;
  $('package-facts').hidden = false;
  blobFallbackOffered = !supportsLocalStreaming;
  $('fallback-warning').hidden = supportsStreaming || supportsLocalStreaming;
  packageState('Checking');
  $('package-title').textContent = 'Package ready to download';
  $('package-description').textContent = '';
  $('availability').textContent = 'Checking…';
  $('download-button').hidden = false;
  $('consent-label').hidden = false;
  $('download-consent').checked = false;
  $('download-warning').hidden = false;
  $('download-progress').hidden = true;
  $('download-meter').classList.toggle('is-complete', false);
  $('download-meter').value = 0;
  $('download-percent').textContent = '0%';
  $('save-archive').hidden = true;
  if (blobURL) { URL.revokeObjectURL(blobURL); blobURL = null; }
  status('');
  try {
    if (!route) throw new Error('');
    if (!window.isSecureContext || !crypto.subtle) throw new Error('Browser encryption requires a secure HTTPS connection and Web Crypto support.');
    try { keyBytes = decodeKey(fragment); } catch { throw new Error(''); }
    fragment = '';
    const response = await fetch(`/api/packages/${encodeURIComponent(route[1])}`, { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (attempt !== initialization) return;
    if (!response.ok) throw new Error(response.status === 404 || response.status === 410 ? '' : 'Unable to check this package. Reopen the original complete link to try again; nothing has been consumed.');
    const info = await response.json();
    if (attempt !== initialization) return;
    expiresAt = Date.parse(info.expiresAt);
    if (info.status !== 'ready' || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new Error('');
    if (info.oneTime !== undefined && typeof info.oneTime !== 'boolean') throw new Error('Invalid package mode.');
    oneTime = info.oneTime !== false;
    if (info.format !== undefined && !['files', 'text'].includes(info.format)) throw new Error('Invalid package format.');
    packageFormat = info.format || 'files';
    const text = packageFormat === 'text';
    $('package-format').textContent = text ? 'Plain TXT' : 'ZIP archive';
    $('package-title').textContent = text ? 'Secret ready to view' : 'Package ready to download';
    $('warning-title').textContent = text ? 'One-time view' : 'One-time download';
    $('warning-description').textContent = text ? 'Viewing this secret destroys the server copy, even if opening fails or is cancelled. It cannot be opened again; copy the secret before leaving.' : 'Starting the transfer claims and destroys the server copy, even if the download fails or is cancelled. It cannot be resumed; ask the sender for a new package.';
    $('consent-text').textContent = text ? 'I understand that this is a one-time reveal secret.' : 'I understand that this is a one-time download package.';
    if (text) $('fallback-warning').hidden = true;
    $('download-warning').hidden = !oneTime;
    $('consent-label').hidden = !oneTime;
    $('download-button').textContent = text ? 'Reveal secret' : oneTime ? 'Download package' : 'Download';
    $('cancel-download').textContent = text ? (oneTime ? 'Cancel view (irreversible)' : 'Cancel view') : oneTime ? 'Cancel transfer (irreversible)' : 'Cancel transfer';
    $('fallback-description').textContent = oneTime ? 'This browser can save ZIP archives up to 128 MiB, including archive overhead. The encrypted size is unknown until you start and claim the one-time download. A larger package will be lost. For large or unknown sizes, use desktop Chrome or Edge with “Save As” support.' : 'This browser can save ZIP archives up to 128 MiB. For larger packages use a browser with streaming downloads, such as desktop Chrome or Edge. The package remains available until expiry.';
    available = true;
    packageState('Ready');
    $('availability').textContent = `Until ${new Date(expiresAt).toLocaleString()}`;
    $('package-description').textContent = '';
    status('');
  } catch (error) {
    if (attempt !== initialization) return;
    fragment = '';
    keyBytes?.fill(0);
    keyBytes = null;
    packageState('Unavailable');
    $('package-title').textContent = 'Package unavailable';
    $('package-description').textContent = 'This package either does not exist or has already been downloaded.';
    $('availability').textContent = 'Unavailable';
    $('consent-label').hidden = true;
    $('download-button').hidden = true;
    $('download-warning').hidden = true;
    $('fallback-warning').hidden = true;
    $('package-facts').hidden = true;
    status(error.message, true);
  }
  $('checking-card').hidden = true;
  $('package-card').hidden = false;
  updateButton();
}

$('copy-text').addEventListener('click', async () => {
  if ($('text-result').hidden) return;
  const attempt = initialization;
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText($('revealed-text').value);
    if (attempt === initialization && !$('text-result').hidden) $('copy-text-status').textContent = 'Copied.';
  } catch {
    if (attempt !== initialization || $('text-result').hidden) return;
    $('revealed-text').focus();
    $('revealed-text').select();
    $('copy-text-status').textContent = 'Secret selected. Use your browser’s Copy command.';
  }
});

$('download-consent').addEventListener('change', updateButton);
$('download-button').addEventListener('click', download);
$('cancel-download').addEventListener('click', () => controller?.abort());
window.addEventListener('hashchange', () => {
  // Skip-link navigation is not a new package key.
  if (!location.hash || location.hash === '#main') return;
  fragment = location.hash.slice(1);
  history.replaceState(null, '', location.pathname + location.search);
  if (busy) { fragment = ''; return; }
  initialize();
});
window.addEventListener('pagehide', () => {
  clearText();
  ++initialization;
  controller?.abort();
  keyBytes?.fill(0);
  keyBytes = null;
  available = false;
  updateButton();
  if (blobURL) URL.revokeObjectURL(blobURL);
});
window.addEventListener('pageshow', event => {
  if (event.persisted && route) {
    $('save-archive').hidden = true;
    status('For privacy, the key was forgotten when you left this page. Reopen the original complete link from your sender. Merely opening the link does not claim the package.', true);
  }
});
window.addEventListener('beforeunload', event => {
  if (busy) { event.preventDefault(); event.returnValue = ''; }
});
initialize();
