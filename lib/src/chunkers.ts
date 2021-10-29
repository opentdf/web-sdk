export type chunker = (byteStart?: number, byteEnd?: number) => Promise<Uint8Array>;

export const fromBrowserFile = (fileRef: Blob): chunker => {
  return async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    const chunkBlob = fileRef.slice(byteStart, byteEnd);
    const arrayBuffer = await chunkBlob.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  };
};
