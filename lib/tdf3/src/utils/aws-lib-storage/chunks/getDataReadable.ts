// @ts-ignore
export async function* getDataReadable(data): AsyncGenerator<Buffer> {
  for await (const chunk of data) {
    yield Buffer.from(chunk);
  }
}
