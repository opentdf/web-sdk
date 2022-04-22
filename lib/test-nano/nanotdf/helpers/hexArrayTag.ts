/**
 * Hex array tagged template
 *
 * Convert a hex string to a hex array
 *
 * @link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals#Tagged_templates
 * @param strings string Tagged template string
 * @returns Array<string> Array of hex strings
 */
export default function hexArrayTag(strings: { raw: any }): Array<string> {
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
