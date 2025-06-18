/**
 * Downloads a ReadableStream as a file by streaming it directly to a file handle
 * using the File System Access API. Supports aborting via AbortSignal in options.
 *
 * @param stream - The ReadableStream of Uint8Array data to download as a file.
 * @param filename - The name for the downloaded file (default: 'download.tdf').
 * @param options - Optional StreamPipeOptions, supports AbortSignal for cancellation.
 * @returns Promise that resolves when the download is triggered or rejects if aborted.
 */
export async function downloadReadableStream(
  stream: ReadableStream<Uint8Array>,
  filename = 'download.tdf',
  options?: { signal?: AbortSignal }
): Promise<void> {
  // Use the File System Access API to prompt the user for a save location
  const fileHandle = await window.showSaveFilePicker({
    suggestedName: filename,
    types: [
      {
        description: 'TDF File',
        accept: { 'application/octet-stream': ['.tdf'] },
      },
    ],
  });
  const writable = await fileHandle.createWritable();
  let aborted = false;
  const signal = options?.signal;
  let abortHandler: (() => void) | undefined;

  if (signal) {
    if (signal.aborted) {
      await writable.abort();
      throw new DOMException('Aborted', 'AbortError');
    }
    abortHandler = () => {
      aborted = true;
      writable.abort();
    };
    signal.addEventListener('abort', abortHandler);
  }

  try {
    await stream.pipeTo(writable, { signal });
  } catch (err) {
    if (aborted) {
      throw new DOMException('Aborted', 'AbortError');
    }
    throw err;
  } finally {
    if (signal && abortHandler) {
      signal.removeEventListener('abort', abortHandler);
    }
  }
}
