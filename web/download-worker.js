/* Local-only download transport. No cache, network forwarding, or encryption keys. */
const sessions = new Map();
const TOKEN = /^[a-f0-9]{64}$/;
const MAX_CHUNK = 8 * 1024 * 1024;
const TIMEOUT = 120000;

self.addEventListener('install', () => { /* Updates wait for existing controlled pages to close. */ });
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

function dispose(session, error) {
  if (sessions.get(session.token) !== session) return;
  sessions.delete(session.token);
  clearTimeout(session.timer);
  if (error) {
    try { session.streamController?.error(new Error(error)); } catch { /* Already closed. */ }
    session.port.postMessage({ nonce: session.nonce, type: 'error', message: error });
  }
  session.port.close();
  session.resolvePull?.();
}
function touch(session) {
  clearTimeout(session.timer);
  session.timer = setTimeout(() => dispose(session, 'The local download timed out.'), TIMEOUT);
}
function send(session, type, extra = {}) {
  session.port.postMessage({ nonce: session.nonce, type, ...extra });
}

self.addEventListener('message', event => {
  const data = event.data;
  const port = event.ports?.[0];
  if (!port || data?.type !== 'prepare-download' || !TOKEN.test(data.token) || !TOKEN.test(data.nonce)) return;
  event.waitUntil((async () => {
    const owner = await self.clients.get(event.source?.id);
    if (!owner || owner.type !== 'window' || new URL(owner.url).origin !== self.location.origin || owner.id !== event.source.id) { port.close(); return; }
    if (sessions.has(data.token) || sessions.size >= 8) { port.close(); return; }
    const session = { token: data.token, nonce: data.nonce, owner: owner.id, port, probe: data.probe === true, used: false, initialized: false, waiting: false, written: 0 };
    sessions.set(session.token, session);
    touch(session);
    port.onmessage = ({ data: message }) => {
      if (sessions.get(session.token) !== session || message?.nonce !== session.nonce) return;
      touch(session);
      try {
        if (message.type === 'abort') { dispose(session, 'The local download was cancelled.'); return; }
        if (message.type === 'initialize' && !session.probe && !session.initialized && !session.used) {
          if (typeof message.fileName !== 'string' || !/^[A-Za-z0-9._-]{1,160}\.zip$/.test(message.fileName) || !Number.isSafeInteger(message.size) || message.size < 0) throw new Error('Invalid download metadata.');
          session.fileName = message.fileName;
          session.size = message.size;
          session.initialized = true;
          send(session, 'initialized');
        } else if (message.type === 'chunk' && session.waiting && message.bytes instanceof Uint8Array && message.bytes.byteLength > 0 && message.bytes.byteLength <= MAX_CHUNK) {
          if (session.written + message.bytes.byteLength > session.size) throw new Error('Download size mismatch.');
          session.waiting = false;
          session.written += message.bytes.byteLength;
          session.streamController.enqueue(message.bytes);
          send(session, 'ack');
          session.resolvePull?.();
          session.resolvePull = null;
        } else if (message.type === 'close' && session.used && session.written === session.size) {
          session.streamController.close();
          send(session, 'closed');
          dispose(session);
        } else throw new Error('Invalid local download protocol.');
      } catch (error) { dispose(session, error.message); }
    };
    port.start();
    send(session, 'ready');
  })());
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  const match = /^\/local-download\/([a-f0-9]{64})$/.exec(url.pathname);
  if (url.origin !== self.location.origin || !match || url.search || event.request.method !== 'GET') return;
  event.respondWith((async () => {
    const session = sessions.get(match[1]);
    if (!session || session.used) return new Response(null, { status: 404 });
    // A download navigation may have a new iframe client ID. Its unguessable,
    // single-use capability authorizes it; only the creator owns the data port.
    if (event.clientId !== session.owner && event.request.mode !== 'navigate') return new Response(null, { status: 403 });
    const owner = await self.clients.get(session.owner);
    if (!owner || owner.type !== 'window') { dispose(session, 'The download page was closed.'); return new Response(null, { status: 410 }); }
    // Recheck after awaiting: concurrent GETs must not consume a capability twice.
    if (sessions.get(session.token) !== session || session.used) return new Response(null, { status: 404 });
    if (!session.probe && !session.initialized) return new Response(null, { status: 409 });
    session.used = true;
    touch(session);
    if (session.probe) {
      dispose(session);
      return new Response(null, { status: 204, headers: { 'X-Local-Download': match[1], 'Cache-Control': 'no-store' } });
    }
    const stream = new ReadableStream({
      start(controller) { session.streamController = controller; },
      pull() {
        if (sessions.get(session.token) !== session) return;
        touch(session);
        session.waiting = true;
        send(session, 'pull');
        return new Promise(resolve => { session.resolvePull = resolve; });
      },
      cancel() { dispose(session, 'The browser cancelled the local download.'); }
    }, { highWaterMark: 1, size: () => 1 });
    send(session, 'started');
    return new Response(stream, { headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${session.fileName}"`,
      'Content-Length': String(session.size),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    } });
  })());
});
