declare global {
  interface Window {
    TDF: unknown;
    InstallTrigger: unknown;
  }

  interface Crypto {
    webcrypto: {
      subtle: SubtleCrypto;
    };
  }
}

export {};
