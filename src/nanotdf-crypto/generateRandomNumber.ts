/**
 * Generate a random number of given length
 */
export default function generateRandomNumber(length: number): Uint8Array {
  const byteArray = new Uint8Array(length);
  crypto.getRandomValues(byteArray);
  return byteArray;
}
