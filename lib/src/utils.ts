export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isFirefox = (): boolean => typeof window.InstallTrigger !== 'undefined';

export const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};
