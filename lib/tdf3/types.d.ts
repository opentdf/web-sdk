import { EventEmitter } from 'events';

declare global {
  interface Window {
    TDF: typeof EventEmitter;
    msCrypto?: Crypto;
    safari: {
      pushNotification: {
        toString: () => string;
      };
    };
    InstallTrigger: unknown;
  }

  interface Crypto {
    webkitSubtle?: SubtleCrypto;
    webcrypto: {
      subtle: SubtleCrypto;
    };
  }
}

export {};
