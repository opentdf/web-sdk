/** Javascript escape attribute strings. How is this not part of the lib?.
 * https://stackoverflow.com/a/30970751
 */
export function escHtml(plainString = '') {
  return plainString.replace(/["'&<]/g, (c) => `&#${c.charCodeAt(0)};`);
}

export function escJavaScript(plainString = '') {
  return plainString.replace(/["'\\<]/g, (c) => `\\${c === '<' ? '074' : c}`);
}
