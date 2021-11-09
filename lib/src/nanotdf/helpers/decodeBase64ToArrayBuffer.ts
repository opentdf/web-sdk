/**
 * Decode base64 to Array Buffer
 *
 * Decode a base64 string to an ArrayBuffer
 *
 * @param str string Base64 encoded string
 * @returns ArrayBuffer the array buffer for the decoded string
 */
export default function decodeBase64ToArrayBuffer(str: string): ArrayBuffer {
  if (typeof window !== 'undefined') {
    return new Uint8Array(
      window
        .atob(str)
        .split('')
        .map((c) => c.charCodeAt(0))
    );
  } else {
    // Buffer is a wrapper around
    return Buffer.from(str, 'base64');
  }
}
