/**
 * Buffer to hex
 *
 * Convert a buffer / Typed Array (i.e. Uint8Array) to a array of hex values
 *
 * @param buffer
 */
export function bufferToHex(buffer?: Uint8Array, uppercase = false): Array<string> | undefined {
  if (!buffer) return undefined;
  return Array.from(buffer).map((i: number): string => {
    // Convert to number (should already be a number)
    let num = Number(i);
    // Handle signed numbers
    if (num < 0) num = num >>> 0;
    // Convert to hex and pad with a zero if needed
    const hex = num.toString(16).padStart(2, '0');
    return uppercase ? hex.toUpperCase() : hex.toLowerCase();
  });
}

/**
 * Hex array tagged template
 *
 * Convert a hex string to a hex array
 *
 * @link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals#Tagged_templates
 * @param strings string Tagged template string
 * @returns Array<string> Array of hex strings
 */
export function hexArrayTag(strings: TemplateStringsArray): Array<string> {
  if (strings.raw[0] === '') return [];
  return (
    strings.raw[0]
      .toLowerCase()
      // Remove space beginning and end
      .trim()
      // Replace whitespace with single space
      .replace(/(\s{2,}|\n)/g, ' ')
      // Split on space
      .split(' ')
  );
}
