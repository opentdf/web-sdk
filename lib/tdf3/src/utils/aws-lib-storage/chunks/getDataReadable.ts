export async function* getDataReadable(data: any): AsyncGenerator<Uint8Array> {
  for await (const chunk of data) {
    yield chunk;
  }
}
