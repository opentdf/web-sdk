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

export type ToFileOptions = StreamPipeOptions & {
  /**
   * Called with the reason before falling back to buffering the whole output
   * in memory, so the caller can warn that large files may not fit.
   */
  onFallback?: (reason: string) => void;
};

// Browsers stop a service worker that has had no events for about 30 seconds.
// Chunks arrive on a MessagePort, which may not count, so ping while streaming.
const KEEPALIVE_MS = 10_000;
// How long to wait for a worker before falling back to an in-memory Blob.
const WORKER_TIMEOUT_MS = 5_000;
// How long the iframe's request may take to reach the worker. If it never does
// (a frame-src Content-Security-Policy, an extension, DevTools "Bypass for
// network"), there is no download, and we must fail rather than report success.
const START_TIMEOUT_MS = 10_000;
// Once the download has started, how long the browser may go without reading
// before we give up. Chromium does not tell the worker when the user cancels
// in its download UI, and a terminated worker sends nothing, so silence is all
// there is to go on. Generous, because a download paused in Chromium's download
// UI looks the same, as does a slow disk or a save dialog (DSPX-5258).
const STALL_TIMEOUT_MS = 10 * 60_000;
// The iframe and the Blob URL only have to start the download, after which the
// browser owns it; wait a moment before removing them to be safe.
const CLEANUP_DELAY_MS = 30_000;

type FromWorker =
  | { type: 'ready' }
  | { type: 'started' }
  | { type: 'pull' }
  | { type: 'done' }
  | { type: 'cancel'; reason: string };

type ToWorker =
  { type: 'chunk'; chunk: ArrayBuffer } | { type: 'close' } | { type: 'abort'; reason: string };

let registered: Promise<ServiceWorkerRegistration> | undefined;

export function registerDownloadWorker(): void {
  if (!('serviceWorker' in navigator)) {
    console.warn('No service workers here (insecure context?); downloads will buffer in memory');
    return;
  }
  registered = navigator.serviceWorker
    .register('./sw.js')
    .then(() => navigator.serviceWorker.ready);
  registered.catch((e: unknown) => {
    console.warn('Download service worker registration failed', e);
  });
}

export function canSaveAs(): boolean {
  return 'showSaveFilePicker' in window;
}

export async function toFile(
  stream: ReadableStream<Uint8Array>,
  filename = 'download.tdf',
  { onFallback, ...options }: ToFileOptions = {}
): Promise<SinkStrategy> {
  const found = await findWorker();
  let reason: string;
  if (typeof found === 'string') {
    reason = found;
  } else {
    const sink = new PortSink();
    found.worker.postMessage({ type: 'register', id: sink.id, filename }, [sink.remotePort]);
    // An outdated or broken worker may never answer; the stream is untouched
    // until it does, so falling back is still possible.
    if (await withTimeout(sink.ready)) {
      await streamThroughWorker(found.worker, found.scope, sink, stream, filename, options);
      return 'service-worker';
    }
    // Frees whatever the worker sets up if it answers after all.
    sink.abort('the page stopped waiting for the worker');
    reason = 'the service worker did not answer (an outdated sw.js?)';
  }
  console.warn(`Streaming download unavailable (${reason}); buffering the whole output in memory`);
  onFallback?.(reason);
  await saveAsBlob(stream, filename, options);
  return 'blob';
}

/** The active worker, or why there isn't one. */
async function findWorker(): Promise<{ worker: ServiceWorker; scope: string } | string> {
  if (!('serviceWorker' in navigator)) {
    return 'no service workers here (insecure context?)';
  }
  let registration: ServiceWorkerRegistration | undefined;
  try {
    // Pages that never called registerDownloadWorker may still have a worker.
    registration = await withTimeout(registered ?? navigator.serviceWorker.ready);
  } catch (e) {
    return `service worker registration failed: ${e instanceof Error ? e.message : String(e)}`;
  }
  if (!registration?.active) {
    return `no service worker became active within ${WORKER_TIMEOUT_MS / 1000} s`;
  }
  return { worker: registration.active, scope: registration.scope };
}

async function streamThroughWorker(
  worker: ServiceWorker,
  scope: string,
  sink: PortSink,
  stream: ReadableStream<Uint8Array>,
  filename: string,
  options: StreamPipeOptions
) {
  const iframe = document.createElement('iframe');
  iframe.hidden = true;
  iframe.src = new URL(`__download__/${sink.id}/${encodeURIComponent(filename)}`, scope).href;
  document.body.appendChild(iframe);
  sink.expectStart();
  // Ping the worker holding the stream, not registration.active, which an
  // update can replace mid-download.
  const keepalive = setInterval(() => worker.postMessage({ type: 'ping' }), KEEPALIVE_MS);
  try {
    await stream.pipeTo(new WritableStream(sink, { highWaterMark: 1 }), options);
  } finally {
    clearInterval(keepalive);
    sink.dispose();
    setTimeout(() => iframe.remove(), CLEANUP_DELAY_MS);
  }
}

/**
 * Sends one chunk per credit; the worker grants a credit each time its stream
 * pulls. Closing succeeds only once the browser has read every byte, and the
 * pipe fails if the download never reaches the worker or stops being read.
 */
class PortSink implements UnderlyingSink<Uint8Array> {
  readonly id = crypto.randomUUID();
  readonly remotePort: MessagePort;
  readonly ready: Promise<true>;
  #port: MessagePort;
  #credits = 0;
  #started = false;
  #done = false;
  #startTimer?: ReturnType<typeof setTimeout>;
  // Wakes a write or close waiting for the next message from the worker.
  #wake?: () => void;
  // Set when the download is cancelled, stalls or the stream aborts; wakes a
  // waiting write or close so it can throw.
  #stopped?: Error;
  #controller?: WritableStreamDefaultController;

  constructor() {
    const { port1, port2 } = new MessageChannel();
    this.#port = port1;
    this.remotePort = port2;
    let markReady: (ok: true) => void;
    this.ready = new Promise((resolve) => (markReady = resolve));
    port1.onmessage = ({ data }: MessageEvent<FromWorker>) => {
      switch (data.type) {
        case 'ready':
          markReady(true);
          break;
        case 'started':
          this.#started = true;
          clearTimeout(this.#startTimer);
          break;
        case 'pull':
          this.#credits++;
          break;
        case 'done':
          this.#done = true;
          break;
        case 'cancel':
          // The worker has already closed its end.
          this.#fail(new Error(`Download cancelled: ${data.reason}`), false);
          break;
      }
      this.#wake?.();
    };
  }

  start(controller: WritableStreamDefaultController) {
    this.#controller = controller;
    // abort() is only called once the in-flight write settles, and that write
    // may be waiting for a credit the worker will never send (for example,
    // because its queue is full and the browser hasn't started reading).
    controller.signal.addEventListener('abort', () => this.#stop(controller.signal.reason));
  }

  /** Call once the iframe points at the download URL. */
  expectStart() {
    this.#startTimer = setTimeout(
      () =>
        this.#fail(
          new Error(
            'The download never reached the service worker; a Content-Security-Policy ' +
              'frame-src, a browser extension or DevTools "Bypass for network" may be blocking it'
          )
        ),
      START_TIMEOUT_MS
    );
  }

  dispose() {
    clearTimeout(this.#startTimer);
  }

  async write(chunk: Uint8Array) {
    await this.#until(() => this.#credits > 0);
    this.#credits--;
    // Transfer a copy rather than the chunk's own buffer: the chunk may be a
    // view into a larger buffer the SDK still holds.
    const { buffer } = chunk.slice();
    this.#send({ type: 'chunk', chunk: buffer }, [buffer]);
  }

  async close() {
    this.#send({ type: 'close' });
    // The bytes are sent, but up to a queue's worth may not be saved yet.
    await this.#until(() => this.#done);
  }

  abort(reason: unknown) {
    this.#send({ type: 'abort', reason: String(reason) });
  }

  #send(message: ToWorker, transfer: Transferable[] = []) {
    this.#port.postMessage(message, transfer);
  }

  // Waits until `ready()` holds, rechecking after each message from the worker.
  async #until(ready: () => boolean) {
    while (!ready() && !this.#stopped) {
      // Until the download starts, the start timer is the deadline.
      const stall = this.#started
        ? setTimeout(
            () =>
              this.#fail(
                new Error(
                  `Download stalled: the browser read nothing for ${STALL_TIMEOUT_MS / 60_000} minutes. ` +
                    'Was it cancelled in the downloads list?'
                )
              ),
            STALL_TIMEOUT_MS
          )
        : undefined;
      await new Promise<void>((resolve) => (this.#wake = resolve));
      clearTimeout(stall);
    }
    if (this.#stopped) {
      throw this.#stopped;
    }
  }

  #stop(reason: unknown) {
    this.#stopped ??= reason instanceof Error ? reason : new Error(String(reason));
    this.#wake?.();
  }

  // For failures the writable stream doesn't know about yet.
  #fail(error: Error, tellWorker = true) {
    if (this.#stopped) {
      return;
    }
    this.#stop(error);
    this.#controller?.error(error);
    if (tellWorker) {
      this.abort(error.message);
    }
  }
}

async function saveAsBlob(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  options: StreamPipeOptions
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
  setTimeout(() => URL.revokeObjectURL(url), CLEANUP_DELAY_MS);
}

function withTimeout<T>(promise: Promise<T>): Promise<T | undefined> {
  let timer: number | undefined;
  return Promise.race([
    promise,
    new Promise<undefined>((resolve) => (timer = window.setTimeout(resolve, WORKER_TIMEOUT_MS))),
  ]).finally(() => clearTimeout(timer));
}
