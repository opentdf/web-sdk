export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isSafari = (): boolean =>
  /constructor/i.test(String(globalThis.HTMLElement)) ||
  // @ts-ignore
  globalThis?.safari?.pushNotification?.toString() === '[object SafariRemoteNotification]';

// @ts-ignore
export const isFirefox = (): boolean => typeof InstallTrigger !== 'undefined';
