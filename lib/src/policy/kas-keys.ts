import { Value } from './attributes.js';

export function effectiveKasKeys(value: Value): Value['kasKeys'] {
  if (value.kasKeys.length) {
    return value.kasKeys;
  }
  if (value.attribute?.kasKeys?.length) {
    return value.attribute.kasKeys;
  }
  return value.attribute?.namespace?.kasKeys ?? [];
}
