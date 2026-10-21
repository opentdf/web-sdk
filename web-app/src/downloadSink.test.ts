import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DownloadError, toFile } from './downloadSink.js';

// Drives the page side of the download protocol against a scripted worker, with
// fake timers so the start and stall timeouts run instantly. Port messages
// still travel on the real event loop, which the fake timers leave alone.

const MINUTE = 60_000;

type Message = { type: string; [key: string]: unknown };

/** Plays public/sw.js: records what the page sends and answers on cue. */
class FakeWorker {
  port?: MessagePort;
  received: Message[] = [];

  postMessage(message: Message, transfer: Transferable[] = []) {
    if (message.type !== 'register') {
      return;
    }
    this.port = transfer[0] as MessagePort;
    this.port.onmessage = ({ data }: MessageEvent<Message>) => void this.received.push(data);
  }

  send(...messages: Message[]) {
    for (const message of messages) {
      this.port?.postMessage(message);
    }
  }

  types() {
    return this.received.map(({ type }) => type);
  }
}

function source(chunks: number) {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent++ < chunks) {
        controller.enqueue(new Uint8Array(1024));
      } else {
        controller.close();
      }
    },
  });
}

function track<T>(promise: Promise<T>) {
  const state: { settled: boolean; value?: T; error?: unknown } = { settled: false };
  promise.then(
    (value) => Object.assign(state, { settled: true, value }),
    (error: unknown) => Object.assign(state, { settled: true, error })
  );
  return state;
}

// Lets queued port messages, and the stream work they trigger, run.
async function flush() {
  for (let i = 0; i < 20; i++) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

let worker: FakeWorker;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
  worker = new FakeWorker();
  vi.stubGlobal('window', globalThis);
  vi.stubGlobal('navigator', {
    serviceWorker: { ready: Promise.resolve({ active: worker, scope: 'http://app.test/' }) },
  });
  vi.stubGlobal('document', {
    body: { appendChild() {} },
    createElement: () => ({ click() {}, remove() {} }),
  });
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  worker.port?.close();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('toFile through the service worker', () => {
  it("resolves only once the worker reports 'done'", async () => {
    const result = track(toFile(source(2)));
    await flush();
    worker.send({ type: 'ready' }, { type: 'started' }, { type: 'pull' }, { type: 'pull' });
    await flush();
    expect(worker.types()).toEqual(['chunk', 'chunk', 'close']);
    expect(result.settled).toBe(false);
    worker.send({ type: 'done' });
    await flush();
    expect(result).toEqual({ settled: true, value: 'service-worker' });
  });

  it('sends one chunk per pull', async () => {
    track(toFile(source(3)));
    await flush();
    worker.send({ type: 'ready' }, { type: 'started' });
    await flush();
    expect(worker.types()).toEqual([]);
    worker.send({ type: 'pull' });
    await flush();
    expect(worker.types()).toEqual(['chunk']);
  });

  it('fails if the download never reaches the worker', async () => {
    const result = track(toFile(source(1)));
    await flush();
    // Credit arrives before any download exists: the worker fills its queue.
    worker.send({ type: 'ready' }, { type: 'pull' }, { type: 'pull' });
    await flush();
    expect(worker.types()).toEqual(['chunk', 'close']);
    await vi.advanceTimersByTimeAsync(10_000);
    await flush();
    expect(result.error).toBeInstanceOf(DownloadError);
    expect(String(result.error)).toMatch(/didn't start within 10 s/);
    expect(worker.types()).toEqual(['chunk', 'close', 'abort']);
  });

  it('fails a started download once the browser stops reading', async () => {
    const result = track(toFile(source(2)));
    await flush();
    worker.send({ type: 'ready' }, { type: 'started' }, { type: 'pull' });
    await flush();
    await vi.advanceTimersByTimeAsync(10 * MINUTE - 1);
    await flush();
    expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(result.error).toBeInstanceOf(DownloadError);
    expect(String(result.error)).toMatch(/Download stalled/);
    expect(worker.types()).toEqual(['chunk', 'abort']);
  });

  it('keeps a slow download going while the browser keeps reading', async () => {
    const result = track(toFile(source(3)));
    await flush();
    worker.send({ type: 'ready' }, { type: 'started' });
    for (let i = 0; i < 3; i++) {
      await vi.advanceTimersByTimeAsync(9 * MINUTE);
      worker.send({ type: 'pull' });
      await flush();
    }
    // close() waits for 'done' under the same rule.
    await vi.advanceTimersByTimeAsync(9 * MINUTE);
    worker.send({ type: 'done' });
    await flush();
    expect(result).toEqual({ settled: true, value: 'service-worker' });
  });

  it("rejects on the worker's cancel without sending abort back", async () => {
    const result = track(toFile(source(2)));
    await flush();
    worker.send({ type: 'ready' }, { type: 'started' });
    worker.send({ type: 'cancel', reason: 'user cancelled' });
    await flush();
    expect(result.error).toBeInstanceOf(DownloadError);
    expect(String(result.error)).toMatch(/Download cancelled: user cancelled/);
    expect(worker.types()).not.toContain('abort');
  });

  it('an abort ends the wait for done', async () => {
    const abort = new AbortController();
    const result = track(toFile(source(1), 'f.bin', { signal: abort.signal }));
    await flush();
    worker.send({ type: 'ready' }, { type: 'started' }, { type: 'pull' });
    await flush();
    expect(worker.types()).toEqual(['chunk', 'close']);
    abort.abort(new Error('user abort'));
    await flush();
    // The caller's own abort, not a failed download.
    expect(result.error).not.toBeInstanceOf(DownloadError);
    expect(String(result.error)).toMatch(/user abort/);
    expect(worker.types()).toEqual(['chunk', 'close', 'abort']);
  });
});

describe('toFile fallback', () => {
  it("buffers in memory, and frees the worker's stream, when ready never comes", async () => {
    const onFallback = vi.fn();
    const result = track(toFile(source(1), 'f.bin', { onFallback }));
    await flush();
    await vi.advanceTimersByTimeAsync(5_000);
    await flush();
    expect(result).toEqual({ settled: true, value: 'blob' });
    expect(onFallback).toHaveBeenCalledWith(expect.stringMatching(/did not answer/));
    expect(worker.types()).toEqual(['abort']);
  });

  it('falls back at once when registration failed', async () => {
    vi.stubGlobal('navigator', {
      serviceWorker: { register: () => Promise.reject(new Error('sw.js 404')) },
    });
    // registerDownloadWorker keeps module state, so use a fresh copy.
    vi.resetModules();
    const sink = await import('./downloadSink.js');
    sink.registerDownloadWorker();
    const onFallback = vi.fn();
    const result = track(sink.toFile(source(1), 'f.bin', { onFallback }));
    await flush();
    expect(result).toEqual({ settled: true, value: 'blob' });
    expect(onFallback).toHaveBeenCalledWith(
      expect.stringMatching(/registration failed: sw.js 404/)
    );
  });
});
