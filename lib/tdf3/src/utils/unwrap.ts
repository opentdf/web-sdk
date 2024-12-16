import { decodeArrayBuffer } from '../../../src/encodings/base64.js';
import { InvalidFileError } from '../../../src/errors.js';

export function unwrapHtml(htmlPayload: Uint8Array): Uint8Array {
  const html = new TextDecoder().decode(htmlPayload);
  const payloadRe = /<input id=['"]?data-input['"]?[^>]*?value=['"]?([a-zA-Z0-9+/=]+)['"]?/;
  const reResult = payloadRe.exec(html);
  if (!reResult) {
    throw new InvalidFileError('Payload is missing');
  }
  const base64Payload = reResult[1];
  try {
    return new Uint8Array(decodeArrayBuffer(base64Payload));
  } catch (e) {
    throw new InvalidFileError('There was a problem extracting the TDF3 payload', e);
  }
}
