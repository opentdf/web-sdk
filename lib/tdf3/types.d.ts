declare global {
  interface Window {
    TDF: unknown;
    InstallTrigger: unknown;
    activeWorkers: Set<Worker>;
  }

  interface Crypto {
    webcrypto: {
      subtle: SubtleCrypto;
    };
  }
}

export {};
