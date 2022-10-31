import { EventEmitter } from 'events';

declare global {
  interface Window {
    TDF: typeof EventEmitter;
    InstallTrigger: unknown;
  }

  interface Crypto {
    webcrypto: {
      subtle: SubtleCrypto;
    };
  }
}

export {};
