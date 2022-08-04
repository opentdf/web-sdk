export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isSafari = (): boolean =>
  /constructor/i.test(String(globalThis.HTMLElement)) ||
  window?.safari?.pushNotification?.toString() === '[object SafariRemoteNotification]';

export const isFirefox = (): boolean => typeof window.InstallTrigger !== 'undefined';
