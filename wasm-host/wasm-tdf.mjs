// wasm-tdf.mjs — High-level API for the WASM TDF encrypt module.
//
// Usage:
//   const tdf = new WasmTDF();
//   await tdf.init('tdfcore.wasm');
//   const tdfBytes = await tdf.encrypt({ kasPubPEM, kasURL, plaintext });
//   tdf.terminate();

import { TOTAL_SAB_SIZE } from './protocol.mjs';
import { CryptoHandler } from './crypto-handler.mjs';

export const ALG_HS256 = 0;
export const ALG_GMAC = 1;

export class WasmTDF {
  constructor() {
    this._sab = null;
    this._worker = null;
    this._cryptoHandler = null;
    this._nextId = 1;
    this._pending = new Map();
  }

  async init(wasmUrl = 'tdfcore.wasm') {
    this._sab = new SharedArrayBuffer(TOTAL_SAB_SIZE);
    this._cryptoHandler = new CryptoHandler(this._sab);
    this._cryptoHandler.start();

    this._worker = new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' });

    return new Promise((resolve, reject) => {
      const onMessage = (e) => {
        const msg = e.data;
        if (msg.type === 'ready') {
          this._worker.removeEventListener('message', onMessage);
          this._worker.addEventListener('message', (ev) => this._onWorkerMessage(ev));
          resolve();
        } else if (msg.type === 'error' && msg.id === null) {
          this._worker.removeEventListener('message', onMessage);
          reject(new Error(msg.message));
        }
      };
      this._worker.addEventListener('message', onMessage);
      this._worker.postMessage({ type: 'init', sab: this._sab, wasmUrl });
    });
  }

  encrypt({ kasPubPEM, kasURL, attrs, plaintext, integrityAlg, segIntegrityAlg }) {
    const id = this._nextId++;
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({
        type: 'encrypt',
        id,
        kasPubPEM,
        kasURL,
        attrs: attrs || [],
        plaintext: plaintext instanceof Uint8Array ? plaintext : new TextEncoder().encode(plaintext),
        integrityAlg: integrityAlg ?? ALG_HS256,
        segIntegrityAlg: segIntegrityAlg ?? ALG_HS256,
      });
    });
  }

  terminate() {
    if (this._cryptoHandler) this._cryptoHandler.stop();
    if (this._worker) this._worker.terminate();
    this._worker = null;
    for (const [, { reject }] of this._pending) {
      reject(new Error('WasmTDF terminated'));
    }
    this._pending.clear();
  }

  _onWorkerMessage(e) {
    const msg = e.data;
    const p = this._pending.get(msg.id);
    if (!p) return;
    this._pending.delete(msg.id);
    if (msg.type === 'result') {
      p.resolve(msg.data);
    } else if (msg.type === 'error') {
      p.reject(new Error(msg.message));
    }
  }
}
