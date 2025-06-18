/**
 * Downloads a ReadableStream as a file using a service worker stream (streamsaver-like) or a Blob fallback.
 * Efficient for large files and supports aborting via AbortSignal in options.
 */
export async function downloadReadableStream(
  stream: ReadableStream<Uint8Array>,
  filename = 'download.tdf',
  options?: { signal?: AbortSignal }
): Promise<void> {
  if (typeof navigator !== 'undefined' && typeof navigator?.serviceWorker !== 'undefined') {
    const swUrl = '/sw.js';
    try {
      await navigator.serviceWorker.register(swUrl, { scope: '/' });
      await navigator.serviceWorker.ready;
    } catch (e) {
      console.log('Downloading service worker registration failed:', e);
      return fallbackDownload(stream, filename, options);
    }

    const channel = new MessageChannel();
    const downloadId = Math.random().toString(36).slice(2);
    navigator.serviceWorker.controller?.postMessage(
      {
        downloadId,
        filename,
        port: channel.port2,
      },
      [channel.port2]
    );

    // Pipe the stream to the service worker via the channel
    if (typeof stream.pipeTo === 'function') {
      const writer = channel.port1;
      const reader = stream.getReader();
      function readAndSend() {
        reader.read().then(({ done, value }) => {
          if (done) {
            writer.postMessage({ done: true });
            writer.close();
            return;
          }
          writer.postMessage({ chunk: value });
          readAndSend();
        });
      }
      readAndSend();
    }

    // Hidden iframe triggers the browser download event
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = `/stream-saver-download?downloadId=${downloadId}`;
    document.body.appendChild(iframe);
    setTimeout(() => {
      document.body.removeChild(iframe);
    }, 2000); // Clean up after 2 seconds
  } else {
    fallbackDownload(stream, filename, options);
  }
}

// Fallback: collect stream into a Blob and trigger download via anchor
async function fallbackDownload(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  options?: { signal?: AbortSignal }
) {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let done = false;
  let aborted = false;
  const signal = options?.signal;
  let abortHandler: (() => void) | undefined;

  if (signal) {
    if (signal.aborted) {
      throw new DOMException('Aborted', 'AbortError');
    }
    abortHandler = () => {
      aborted = true;
      reader.cancel();
    };
    signal.addEventListener('abort', abortHandler);
  }
  try {
    while (!done) {
      if (aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
      const { value, done: streamDone } = await reader.read();
      if (value) {
        chunks.push(value);
      }
      done = streamDone;
    }
  } finally {
    if (signal && abortHandler) {
      signal.removeEventListener('abort', abortHandler);
    }
  }
  if (aborted) {
    throw new DOMException('Aborted', 'AbortError');
  }
  const blob = new Blob(chunks);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
}
