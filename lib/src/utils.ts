export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isSafari = (): boolean => isBrowser() && ('safari' in global || 'WebKitPoint' in global);
export const isFirefox = (): boolean => isBrowser() && 'InstallTrigger' in window;

export const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};
