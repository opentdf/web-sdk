export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isSafari(): Boolean => (
  /constructor/i.test(globalThis.HTMLElement) ||
  globalThis?.safari?.pushNotification?.toString() === '[object SafariRemoteNotification]'
);

export const isFirefox(): Boolean => typeof InstallTrigger !== 'undefined';

