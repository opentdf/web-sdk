/**
 * Saves a stream as a browser download without holding it in memory.
 *
 * The page hands the stream to our own service worker (public/sw.js) over a
 * MessagePort, then navigates a hidden iframe to a URL the worker answers with
 * a streamed attachment. The browser's download manager pulls from that
 * response, and each pull grants the page one more chunk, so backpressure
 * reaches back through the SDK to its source. This replaces StreamSaver, which
 * did the same through a service worker on a third-party origin.
 */

export type SinkStrategy = 'service-worker' | 'blob';

// Browsers stop a service worker that has had no events for about 30 seconds.
// Chunks arrive on a MessagePort, which may not count, so ping while streaming.
const KEEPALIVE_MS = 10_000;
// How long to wait for a worker before falling back to an in-memory Blob.
const WORKER_TIMEOUT_MS = 5_000;
// The iframe only exists to start the download; by the time the stream has
// closed the browser owns it, but leave the frame a moment to be safe.
const IFRAME_LINGER_MS = 30_000;

type WorkerMessage = { type: 'ready' } | { type: 'pull' } | { type: 'cancel'; reason?: string };

export function registerDownloadWorker(): void {
  if (!('serviceWorker' in navigator)) {
    console.warn('No service workers here (insecure context?); downloads will buffer in memory');
    return;
  }
  navigator.serviceWorker.register('./sw.js').catch((e: unknown) => {
    console.warn('Download service worker registration failed', e);
  });
}

export function canSaveAs(): boolean {
  return 'showSaveFilePicker' in window;
}

export async function toFile(
  stream: ReadableStream<Uint8Array>,
  filename = 'download.tdf',
  options?: StreamPipeOptions
): Promise<SinkStrategy> {
  const registration = await withTimeout(navigator.serviceWorker?.ready);
  if (registration?.active) {
    const sink = new PortSink();
    registration.active.postMessage({ type: 'register', id: sink.id, filename }, [sink.remotePort]);
    // An outdated or broken worker may never answer; the stream is untouched
    // until it does, so falling back is still possible.
    if (await withTimeout(sink.ready)) {
      await streamThroughWorker(registration, sink, stream, filename, options);
      return 'service-worker';
    }
  }
  console.warn('Download service worker unavailable; buffering the whole output in memory');
  await saveAsBlob(stream, filename, options);
  return 'blob';
}

async function streamThroughWorker(
  registration: ServiceWorkerRegistration,
  sink: PortSink,
  stream: ReadableStream<Uint8Array>,
  filename: string,
  options?: StreamPipeOptions
) {
  const iframe = document.createElement('iframe');
  iframe.hidden = true;
  iframe.src = new URL(
    `__download__/${sink.id}/${encodeURIComponent(filename)}`,
    registration.scope
  ).href;
  document.body.appendChild(iframe);
  const keepalive = setInterval(
    () => registration.active?.postMessage({ type: 'ping' }),
    KEEPALIVE_MS
  );
  try {
    await stream.pipeTo(new WritableStream(sink, { highWaterMark: 1 }), options);
  } finally {
    clearInterval(keepalive);
    setTimeout(() => iframe.remove(), IFRAME_LINGER_MS);
  }
}

/** Sends one chunk per credit; the worker grants a credit each time its stream pulls. */
class PortSink implements UnderlyingSink<Uint8Array> {
  readonly id = crypto.randomUUID();
  readonly remotePort: MessagePort;
  readonly ready: Promise<true>;
  #port: MessagePort;
  #credits = 0;
  #grant?: () => void;
  // Set when the download is cancelled or the stream aborted; wakes a write
  // that is waiting for a credit.
  #stopped?: Error;
  #controller?: WritableStreamDefaultController;

  constructor() {
    const { port1, port2 } = new MessageChannel();
    this.#port = port1;
    this.remotePort = port2;
    let markReady: (ok: true) => void;
    this.ready = new Promise((resolve) => (markReady = resolve));
    port1.onmessage = ({ data }: MessageEvent<WorkerMessage>) => {
      switch (data.type) {
        case 'ready':
          markReady(true);
          break;
        case 'pull':
          this.#credits++;
          this.#grant?.();
          break;
        case 'cancel':
          this.#stop(new Error(`Download cancelled: ${data.reason ?? 'no reason given'}`));
          this.#controller?.error(this.#stopped);
          break;
      }
    };
  }

  start(controller: WritableStreamDefaultController) {
    this.#controller = controller;
    // abort() is only called once the in-flight write settles, and that write
    // may be waiting for a credit the worker will never send (for example,
    // because the browser hasn't started reading the download yet).
    controller.signal.addEventListener('abort', () => this.#stop(controller.signal.reason));
  }

  #stop(reason: unknown) {
    this.#stopped ??= reason instanceof Error ? reason : new Error(String(reason));
    this.#grant?.();
  }

  async write(chunk: Uint8Array) {
    while (!this.#credits && !this.#stopped) {
      await new Promise<void>((resolve) => (this.#grant = resolve));
    }
    if (this.#stopped) {
      throw this.#stopped;
    }
    this.#credits--;
    // Transfer a copy rather than the chunk's own buffer: the chunk may be a
    // view into a larger buffer the SDK still holds.
    const { buffer } = chunk.slice();
    this.#port.postMessage({ type: 'chunk', chunk: buffer }, [buffer]);
  }

  // The worker closes its end once it has read these; closing ours here could
  // drop the message.
  close() {
    this.#port.postMessage({ type: 'close' });
  }

  abort(reason: unknown) {
    this.#port.postMessage({ type: 'abort', reason: String(reason) });
  }
}

async function saveAsBlob(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  options?: StreamPipeOptions
) {
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  await stream.pipeTo(
    new WritableStream({ write: (chunk) => void chunks.push(chunk.slice()) }),
    options
  );
  const url = URL.createObjectURL(new Blob(chunks, { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), IFRAME_LINGER_MS);
}

function withTimeout<T>(promise: Promise<T> | undefined): Promise<T | undefined> {
  if (!promise) {
    return Promise.resolve(undefined);
  }
  return Promise.race([
    promise,
    new Promise<undefined>((resolve) => setTimeout(resolve, WORKER_TIMEOUT_MS)),
  ]);
}
