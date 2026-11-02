// The messages exchanged by ../downloadSink.ts and the download service worker
// in ./sw.ts. Types only: sw.ts is a classic script that reaches these through
// import() types, so nothing declared here can exist at runtime.

/** Page to worker, through ServiceWorker.postMessage. */
export type ControlMessage =
  // Transfers the MessagePort that carries the rest of the download.
  | { type: 'register'; id: string; filename: string }
  // Keeps the worker alive while a download is streaming.
  | { type: 'ping' };

/** Page to worker, on the registered port. The page sends one chunk per pull. */
export type ToWorker =
  { type: 'chunk'; chunk: ArrayBuffer } | { type: 'close' } | { type: 'abort'; reason: string };

/** Worker to page, on the registered port. */
export type FromWorker =
  | { type: 'ready' }
  | { type: 'started' }
  | { type: 'pull' }
  | { type: 'done' }
  | { type: 'cancel'; reason: string };
