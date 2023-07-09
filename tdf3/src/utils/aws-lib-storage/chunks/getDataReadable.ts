export async function* getDataReadable(data: any): AsyncGenerator<Buffer> {
  if (data && typeof data[Symbol.asyncIterator] === 'function')
    for await (const chunk of data) {
      yield Buffer.from(chunk);
    }
}
