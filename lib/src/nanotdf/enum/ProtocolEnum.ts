export enum ProtocolEnum {
  Http = 0,
  Https = 1,
  SharedResourceDirectory = 0xf,
}

export function fromURLProtocol(protocol: string): number {
  switch (protocol) {
    case 'http':
    case 'http:':
      return ProtocolEnum.Http;
    case 'https':
    case 'https:':
      return ProtocolEnum.Https;
  }
  throw new Error(`ResourceLocator protocol [${protocol}] is unsupported`);
}
