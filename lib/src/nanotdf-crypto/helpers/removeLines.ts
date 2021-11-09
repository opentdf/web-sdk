export default function removeLines(str: string): string {
  return str.replace(/\r?\n|\r/g, '');
}
