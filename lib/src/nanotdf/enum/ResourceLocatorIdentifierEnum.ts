export enum ResourceLocatorIdentifierEnum {
  None = 0,
  TwoBytes,
  EightBytes,
  ThirtyTwoBytes,
}

export function length(rli: ResourceLocatorIdentifierEnum): number {
  switch (rli) {
    case ResourceLocatorIdentifierEnum.None:
      return 0;
    case ResourceLocatorIdentifierEnum.TwoBytes:
      return 2;
    case ResourceLocatorIdentifierEnum.EightBytes:
      return 8;
    case ResourceLocatorIdentifierEnum.ThirtyTwoBytes:
      return 32;
  }
  // throw new Error('Unsupported identifier type: ' + rli);
}

export function idType(identifierLength: number): ResourceLocatorIdentifierEnum {
  if (identifierLength === 0) {
    return ResourceLocatorIdentifierEnum.None;
  } else if (identifierLength <= 2) {
    return ResourceLocatorIdentifierEnum.TwoBytes;
  } else if (identifierLength <= 8) {
    return ResourceLocatorIdentifierEnum.EightBytes;
  } else if (identifierLength <= 32) {
    return ResourceLocatorIdentifierEnum.ThirtyTwoBytes;
  }
  throw new Error('Unsupported identifier length: ' + identifierLength);
}
