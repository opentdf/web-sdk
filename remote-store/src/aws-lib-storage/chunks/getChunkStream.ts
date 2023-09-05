import { RawDataPart } from '../Upload.js';

interface Buffers {
  chunks: Uint8Array[];
  length: number;
}

export async function* getChunkStream<T>(
  data: T,
  partSize: number,
  getNextData: (data: T) => AsyncGenerator<Uint8Array>
): AsyncGenerator<RawDataPart, void, undefined> {
  let partNumber = 1;
  const currentBuffer: Buffers = { chunks: [], length: 0 };

  for await (const datum of getNextData(data)) {
    currentBuffer.chunks.push(datum);
    currentBuffer.length += datum.length;

    while (currentBuffer.length >= partSize) {
      /**
       * Concat all the buffers together once if there is more than one to concat. Attempt
       * to minimize concats as Buffer.Concat is an extremely expensive operation.
       */
      const dataChunk =
        currentBuffer.chunks.length > 1
          ? concatUint8(currentBuffer.chunks)
          : currentBuffer.chunks[0];

      yield {
        partNumber,
        data: dataChunk.slice(0, partSize),
      };

      // Reset the buffer.
      currentBuffer.chunks = [dataChunk.slice(partSize)];
      currentBuffer.length = currentBuffer.chunks[0].length;
      partNumber += 1;
    }
  }
  yield {
    partNumber,
    data: concatUint8(currentBuffer.chunks),
    lastPart: true,
  };
}

function concatUint8(uint8Arrays: Uint8Array[]): Uint8Array {
  const newLength = uint8Arrays.reduce(
    (accumulator, currentValue) => accumulator + currentValue.length,
    0
  );
  const combinedUint8Array = new Uint8Array(newLength);

  let offset = 0;
  for (const uint8Array of uint8Arrays) {
    combinedUint8Array.set(uint8Array, offset);
    offset += uint8Array.length;
  }

  return combinedUint8Array;
}
