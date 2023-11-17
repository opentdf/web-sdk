import { TdfDecryptError } from '../errors.js';

const maxWorkers = navigator?.hardwareConcurrency || 4;

interface DecryptData {
  key: CryptoKey;
  encryptedPayload: ArrayBuffer;
  algo: AesCbcParams | AesGcmParams;
}

const workerScript = async (event: { data: DecryptData }) => {
  const { key, encryptedPayload, algo } = event.data;

  try {
    const decryptedData = await crypto.subtle.decrypt(
      algo,
      key,
      encryptedPayload
    );
    self.postMessage({ success: true, data: decryptedData });
  } catch (error) {
    self.postMessage({ success: false, error: error.message });
  }
};

const workerBlob = new Blob([`(${workerScript.toString()})()`], { type: 'application/javascript' });
const workerUrl = URL.createObjectURL(workerBlob);
const workersArray: Worker[] = new Array(maxWorkers).fill(new Worker(workerUrl));

interface WorkersQueue {
  freeWorkers: Worker[];
  resolvers: ((worker: Worker) => void)[];
  push: (worker: Worker) => void;
  pop: () => Promise<Worker>,
}

const workersQueue: WorkersQueue = {
  freeWorkers: [...workersArray],
  resolvers: [],

  push(worker: Worker) {
    const resolve = this.resolvers.shift();
    if (typeof resolve === 'function') {
      resolve(worker);
    } else {
      this.freeWorkers.push(worker);
    }
  },

  pop(): Promise<Worker> {
    return new Promise((resolve) => {
      const worker = this.freeWorkers.shift();
      if (worker instanceof Worker) {
        resolve(worker);
      } else {
        this.resolvers.push(resolve);
      }
    });
  }
}

export async function decrypt(data: DecryptData): Promise<ArrayBuffer> {
  const worker: Worker = await workersQueue.pop();
  return await new Promise((resolve, reject) => {
    worker.onmessage = (event) => {
      const { success, data, error } = event.data;
      workersQueue.push(worker);
      if (success) {
        resolve((data as ArrayBuffer));
      } else {
        reject(new TdfDecryptError(error));
      }
    };

    worker.postMessage(data);
  });
};