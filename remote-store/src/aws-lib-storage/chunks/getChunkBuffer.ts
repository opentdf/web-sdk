import { RawDataPart } from '../Upload.js';

export async function* getChunkBuffer(
  data: Uint8Array,
  partSize: number
): AsyncGenerator<RawDataPart, void, undefined> {
  let partNumber = 1;
  let startByte = 0;
  let endByte = partSize;

  while (endByte < data.byteLength) {
    yield {
      partNumber,
      data: data.slice(startByte, endByte),
    };
    partNumber += 1;
    startByte = endByte;
    endByte = startByte + partSize;
  }

  yield {
    partNumber,
    data: data.slice(startByte),
    lastPart: true,
  };
}
