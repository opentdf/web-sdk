// Streams downloads from the page straight into the browser's download manager,
// so a multi-GiB encrypt or decrypt never has to fit in memory or in storage
// quota. The page side lives in ../downloadSink.ts, and the message types in
// ./protocol.ts.
//
// 1. The page posts { type: 'register', id, filename } with a MessagePort.
// 2. We wrap the port in a ReadableStream and reply { type: 'ready' }.
// 3. The page points a hidden iframe at <scope>__download__/<id>/<filename>.
//    We answer that navigation with the stream as an attachment and post
//    { type: 'started' }.
// 4. Each time the stream wants more, we post { type: 'pull' }; the page sends
//    one { type: 'chunk' } per pull. The stream fills its HIGH_WATER_MARK_BYTES
//    queue as soon as it is registered; after that, pulls follow the download
//    manager's reads, so backpressure reaches all the way back to the SDK.
// 5. After the page posts { type: 'close' } and the browser has read the last
//    byte, we post { type: 'done' }.
//
// Either side can end a download early: the page posts
// { type: 'abort', reason }, and we post { type: 'cancel', reason } when the
// browser cancels the response. While streaming, the page also posts
// { type: 'ping' } every 10 s, so the browser doesn't stop us mid-download.
//
// vite.config.ts strips the types from this file and serves it as /sw.js, a
// classic script. So it can't import or export anything, not even a type; use
// import() types for anything shared with the page.

declare const self: ServiceWorkerGlobalScope;

type ControlMessage = import('./protocol.js').ControlMessage;
type FromWorker = import('./protocol.js').FromWorker;
type ToWorker = import('./protocol.js').ToWorker;

const HIGH_WATER_MARK_BYTES = 4 * 2 ** 20;

const pending = new Map<
  string,
  { stream: ReadableStream<Uint8Array>; source: PortSource; filename: string }
>();

function downloadBase() {
  return new URL('__download__/', self.registration.scope).href;
}

class PortSource implements UnderlyingDefaultSource<Uint8Array> {
  readonly #port: MessagePort;
  // Drops the entry if the download never started.
  readonly #forget: () => void;

  constructor(port: MessagePort, forget: () => void) {
    this.#port = port;
    this.#forget = forget;
  }

  start(controller: ReadableStreamDefaultController<Uint8Array>) {
    this.#port.onmessage = ({ data }: MessageEvent<ToWorker | null>) => {
      switch (data?.type) {
        case 'chunk':
          controller.enqueue(new Uint8Array(data.chunk));
          break;
        case 'close':
          // Keep the port open: the page waits for 'done'.
          controller.close();
          break;
        case 'abort':
          // Erroring the body makes the browser mark the download failed,
          // rather than leaving a truncated file that looks complete. This can
          // also arrive after 'close', if the download never started or stalled.
          controller.error(new Error(String(data.reason ?? 'aborted')));
          this.end();
          break;
        default:
          console.warn('download worker: unknown message', data);
      }
    };
    // A chunk that can't be deserialized is lost, and the page has already
    // spent its credit on it; fail rather than save a file with a hole in it.
    this.#port.onmessageerror = () => {
      const error = new Error('a message from the page could not be read');
      controller.error(error);
      this.cancel(error.message);
    };
  }

  pull() {
    this.send({ type: 'pull' });
  }

  // The browser passes a DOMException, if anything.
  cancel(reason?: Error | string) {
    // The user cancelled in the download UI. Firefox is expected to report
    // this (not yet verified); Chromium does not (https://crbug.com/638494),
    // so there the page notices only when its stall watchdog fires.
    this.send({ type: 'cancel', reason: String(reason ?? 'no reason given') });
    this.end();
  }

  send(message: FromWorker) {
    this.#port.postMessage(message);
  }

  end() {
    this.#port.close();
    this.#forget();
  }
}

/**
 * Passes the body through, posting { type: 'done' } once the browser has read
 * all of it, so the page does not report success while bytes are still queued.
 */
function reportWhenRead(stream: ReadableStream<Uint8Array>, source: PortSource) {
  const reader = stream.getReader();
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          source.send({ type: 'done' });
          source.end();
        } else {
          controller.enqueue(value);
        }
      },
      cancel: (reason) => reader.cancel(reason),
    },
    { highWaterMark: 0 }
  );
}

function contentDisposition(filename: string) {
  // eslint-disable-next-line no-control-regex -- control characters are what this replaces
  const safe = filename.replace(/[\u0000-\u001f\u007f/\\]/g, '_');
  const ascii = safe.replace(/[^\x20-\x7e]|["%]/g, '_');
  const encoded = encodeURIComponent(safe).replace(
    /['()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
  );
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  if (event.origin !== self.location.origin) {
    console.warn(`download worker: ignoring message from ${event.origin}`);
    return;
  }
  // Same origin, but not necessarily the same version of the page: check the
  // fields at runtime rather than trusting the type.
  const data = event.data as ControlMessage | null;
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
  const source = new PortSource(port, () => pending.delete(id));
  const stream = new ReadableStream(
    source,
    new ByteLengthQueuingStrategy({ highWaterMark: HIGH_WATER_MARK_BYTES })
  );
  pending.set(id, { stream, source, filename });
  source.send({ type: 'ready' });
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
  entry.source.send({ type: 'started' });
  event.respondWith(
    new Response(reportWhenRead(entry.stream, entry.source), {
      headers: {
        'Cache-Control': 'no-store',
        'Content-Disposition': contentDisposition(entry.filename),
        'Content-Type': 'application/octet-stream',
        'X-Content-Type-Options': 'nosniff',
      },
    })
  );
});
