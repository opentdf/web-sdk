export async function* getDataReadable(data: any): AsyncGenerator<Buffer> {
  for await (const chunk of data) {
    yield Buffer.from(chunk);
  }
}
