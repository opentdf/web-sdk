import { UnsafeUrlError } from './errors.js';

/**
 * Check to see if the given URL is 'secure'. This assumes:
 *
 * - `https` URLs are always secure
 * - `http` URLS are allowed for localhost
 * - And also for '`svc.cluster.local` and `.internal` URLs
 *
 * Note that this does not resolve the URL, so it is possible this could
 * resolve to some other internal URL, and may return `false` on non-fully
 * qualified internal URLs.
 *
 * @param url remote service to validate
 * @returns the url is local or `https`
 */
export function validateSecureUrl(url: string): boolean {
  const httpsRegex = /^https:/;
  if (/^http:\/\/(localhost|127\.0\.0\.1)(:[0-9]{1,5})?($|\/)/.test(url)) {
    console.warn(`Development URL detected: [${url}]`);
  } else if (
    /^http:\/\/([a-zA-Z.-]*[.])?svc\.cluster\.local($|\/)/.test(url) ||
    /^http:\/\/([a-zA-Z.-]*[.])?internal(:[0-9]{1,5})?($|\/)/.test(url)
  ) {
    console.info(`Internal URL detected: [${url}]`);
  } else if (!httpsRegex.test(url)) {
    console.error(`Insecure KAS URL loaded. Are you running in a secure environment? [${url}]`);
    return false;
  }
  return true;
}

export function padSlashToUrl(u: string): string {
  if (u.endsWith('/')) {
    return u;
  }
  return `${u}/`;
}

const someStartsWith = (prefixes: string[], requestUrl: string): boolean =>
  prefixes.some((prixfixe) => requestUrl.startsWith(padSlashToUrl(prixfixe)));

/**
 * Checks that `testUrl` is prefixed with one of the given origin + path fragment URIs in urlPrefixes.
 *
 * Note this doesn't do anything special to queries or fragments and will fail to work properly if those are present on the prefixes
 * @param urlPrefixes a list of origin parts of urls, possibly including some path fragment as well
 * @param testUrl a url to see if it is prefixed by one or more of the `urlPrefixes` values
 * @throws Error when testUrl is not present
 */
export const safeUrlCheck = (urlPrefixes: string[], testUrl: string): void | never => {
  if (!someStartsWith(urlPrefixes, testUrl)) {
    throw new UnsafeUrlError(`Invalid request URL: [${testUrl}] ∉ [${urlPrefixes}];`, testUrl);
  }
};

export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isFirefox = (): boolean => isBrowser() && 'InstallTrigger' in window;

export const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};
