// Streams downloads from the page straight into the browser's download manager,
// so a multi-GiB encrypt or decrypt never has to fit in memory or in storage
// quota. The page side, and the message protocol, live in src/downloadSink.ts.
//
// 1. The page posts { type: 'register', id, filename } with a MessagePort.
// 2. We wrap the port in a ReadableStream and reply { type: 'ready' }.
// 3. The page points a hidden iframe at <scope>__download__/<id>/<filename>,
//    and we answer that navigation with the stream as an attachment.
// 4. Each time the stream wants more, we post { type: 'pull' }; the page sends
//    one { type: 'chunk' } per pull, so backpressure from the download manager
//    reaches all the way back to the SDK.

const HIGH_WATER_MARK_BYTES = 4 * 2 ** 20;

/** @type {Map<string, { stream: ReadableStream<Uint8Array>, filename: string }>} */
const pending = new Map();

function downloadBase() {
  return new URL('__download__/', self.registration.scope).href;
}

/** @implements {UnderlyingDefaultSource<Uint8Array>} */
class PortSource {
  /**
   * @param {MessagePort} port
   * @param {() => void} forget drops the entry if the download never started
   */
  constructor(port, forget) {
    this.port = port;
    this.forget = forget;
  }

  /** @param {ReadableStreamDefaultController<Uint8Array>} controller */
  start(controller) {
    this.port.onmessage = ({ data }) => {
      switch (data?.type) {
        case 'chunk':
          controller.enqueue(new Uint8Array(data.chunk));
          break;
        case 'close':
          controller.close();
          this.port.close();
          break;
        case 'abort':
          // Erroring the body makes the browser mark the download failed,
          // rather than leaving a truncated file that looks complete.
          controller.error(new Error(data.reason));
          this.port.close();
          this.forget();
          break;
      }
    };
  }

  pull() {
    this.port.postMessage({ type: 'pull' });
  }

  /** @param {unknown} reason */
  cancel(reason) {
    // The user cancelled in the download UI. Firefox reports this; Chromium
    // does not (https://crbug.com/638494), so there the page finds out only
    // when it aborts on its own.
    this.port.postMessage({ type: 'cancel', reason: String(reason) });
    this.port.close();
  }
}

/** @param {string} filename */
function contentDisposition(filename) {
  const safe = filename.replace(/[\u0000-\u001f\u007f/\\]/g, '_');
  const ascii = safe.replace(/[^\x20-\x7e]|["%]/g, '_');
  const encoded = encodeURIComponent(safe).replace(
    /['()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
  );
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  if (event.origin !== self.location.origin) {
    console.warn(`download worker: ignoring message from ${event.origin}`);
    return;
  }
  const { data } = event;
  // 'ping' needs no handling: receiving a message is what keeps us alive.
  if (data?.type !== 'register') {
    return;
  }
  const [port] = event.ports;
  if (!port || typeof data.id !== 'string' || typeof data.filename !== 'string') {
    console.warn('download worker: malformed register message');
    return;
  }
  const { id, filename } = data;
  const stream = new ReadableStream(
    new PortSource(port, () => pending.delete(id)),
    new ByteLengthQueuingStrategy({ highWaterMark: HIGH_WATER_MARK_BYTES })
  );
  pending.set(id, { stream, filename });
  port.postMessage({ type: 'ready' });
});

self.addEventListener('fetch', (event) => {
  const { url } = event.request;
  const base = downloadBase();
  if (!url.startsWith(base)) {
    return;
  }
  const [id] = url.slice(base.length).split('/');
  const entry = pending.get(id);
  if (!entry) {
    event.respondWith(new Response('No such download, or it already started', { status: 404 }));
    return;
  }
  // Single use: a second request for the same id gets a 404.
  pending.delete(id);
  event.respondWith(
    new Response(entry.stream, {
      headers: {
        'Cache-Control': 'no-store',
        'Content-Disposition': contentDisposition(entry.filename),
        'Content-Type': 'application/octet-stream',
        'X-Content-Type-Options': 'nosniff',
      },
    })
  );
});
