/**
 * Buffer to hex
 *
 * Convert a buffer / Typed Array (i.e. Uint8Array) to a array of hex values
 *
 * @param buffer
 */
export default function bufferToHex(buffer: any, uppercase = false): Array<string> | undefined {
  if (!buffer) return undefined;
  return Array.from(buffer).map((i: any): string => {
    // Convert to number (should already be a number)
    let num = Number(i);
    // Handle signed numbers
    if (num < 0) num = num >>> 0;
    // Convert to hex and pad with a zero if needed
    const hex = num.toString(16).padStart(2, '0');
    return uppercase ? hex.toUpperCase() : hex.toLowerCase();
  });
}
