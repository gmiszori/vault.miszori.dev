const WAIT = 120000;
const randomToken = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');

function timed(promise, milliseconds = WAIT) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('The local download did not respond.')), milliseconds);
  })]).finally(() => clearTimeout(timer));
}

async function controlledWorker() {
  const serviceWorker = navigator.serviceWorker;
  const scriptURL = new URL('/download-worker.js', location.origin).href;
  await timed(serviceWorker.register(scriptURL, { scope: '/', updateViaCache: 'none' }), 15000);
  const matches = () => serviceWorker.controller?.scriptURL === scriptURL;
  if (!matches()) {
    let changed;
    try {
      await timed(new Promise(resolve => {
        changed = () => { if (matches()) resolve(); };
        serviceWorker.addEventListener('controllerchange', changed);
        changed();
      }), 15000);
    } finally { serviceWorker.removeEventListener('controllerchange', changed); }
  }
  return serviceWorker.controller;
}

function channel(worker, signal, onFailure, probe = false) {
  const token = randomToken();
  const nonce = randomToken();
  const pair = new MessageChannel();
  const port = pair.port1;
  const pending = new Map();
  let failure;
  let credit = false;
  let finished = false;
  let frame;
  const send = (type, extra = {}) => port.postMessage({ nonce, type, ...extra });
  const wait = type => {
    if (failure) return Promise.reject(failure);
    const promise = new Promise((resolve, reject) => pending.set(type, { resolve, reject }));
    return timed(promise).catch(error => { fail(error); throw error; });
  };
  function cleanup() {
    signal?.removeEventListener('abort', aborted);
    window.removeEventListener('pagehide', aborted);
    port.close();
    frame?.remove();
  }
  function fail(error) {
    if (failure || finished) return;
    failure = error;
    try { send('abort'); } catch { /* The worker may already be gone. */ }
    for (const waiter of pending.values()) waiter.reject(error);
    pending.clear();
    cleanup();
    onFailure?.(error);
  }
  function aborted() { fail(new DOMException('The download was cancelled.', 'AbortError')); }
  port.onmessage = ({ data }) => {
    if (data?.nonce !== nonce || failure || finished) return;
    if (data.type === 'error') { fail(new Error(data.message || 'The local download failed.')); return; }
    if (data.type === 'pull') credit = true;
    const waiter = pending.get(data.type);
    if (waiter) { pending.delete(data.type); waiter.resolve(); }
  };
  port.onmessageerror = () => fail(new Error('The local download channel failed.'));
  port.start();
  signal?.addEventListener('abort', aborted, { once: true });
  window.addEventListener('pagehide', aborted, { once: true });
  const ready = wait('ready');
  try { worker.postMessage({ type: 'prepare-download', token, nonce, probe }, [pair.port2]); }
  catch (error) { pair.port2.close(); fail(error); }
  if (signal?.aborted) aborted();
  return {
    ready,
    url: `/local-download/${token}`,
    token,
    async initialize(fileName, size) {
      const initialized = wait('initialized');
      send('initialize', { fileName, size });
      await initialized;
      const started = wait('started');
      frame = document.createElement('iframe');
      frame.hidden = true;
      frame.referrerPolicy = 'no-referrer';
      frame.src = this.url;
      document.body.append(frame);
      await started;
    },
    async write(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > 8 * 1024 * 1024 || !bytes.byteLength) throw new Error('Invalid local download chunk.');
      if (failure) throw failure;
      if (!credit) await wait('pull');
      credit = false;
      const ack = wait('ack');
      // Structured cloning retains the caller's ZIP buffers; only one chunk is
      // in flight and its acknowledgement is awaited before the next write.
      send('chunk', { bytes });
      await ack;
    },
    async close() {
      const closed = wait('closed');
      send('close');
      await closed;
      finished = true;
      cleanup();
    },
    async abort() { fail(new DOMException('The download was cancelled.', 'AbortError')); },
    release() { finished = true; cleanup(); }
  };
}

// Prepare and actually probe interception before a one-time package is claimed.
// Unsupported/private-mode browsers retain the bounded Blob fallback.
export async function prepareServiceWorkerDownload({ signal, onFailure } = {}) {
  if (!window.isSecureContext || !globalThis.navigator?.serviceWorker || typeof MessageChannel !== 'function' || typeof ReadableStream !== 'function') return null;
  let probe;
  let sink;
  try {
    const worker = await controlledWorker();
    signal?.throwIfAborted();
    probe = channel(worker, signal, undefined, true);
    await probe.ready;
    const response = await timed(fetch(probe.url, { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal }), 15000);
    if (response.status !== 204 || response.headers.get('X-Local-Download') !== probe.token) {
      await response.body?.cancel();
      throw new Error('Local download interception is unavailable.');
    }
    probe.release();
    let prepared = false;
    sink = channel(worker, signal, error => { if (prepared) onFailure?.(error); });
    await sink.ready;
    prepared = true;
    return sink;
  } catch (error) {
    await probe?.abort();
    await sink?.abort();
    if (signal?.aborted) throw signal.reason;
    return null;
  }
}
