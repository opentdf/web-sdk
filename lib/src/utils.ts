import { type AxiosResponseHeaders, type RawAxiosResponseHeaders } from 'axios';

export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isFirefox = (): boolean => 'InstallTrigger' in window;

export const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};

/**
 * Rough estimate of number of seconds to add to the current system clock time
 * to get the clock time on the given server, or origin if not specified
 * @param server a server to compute skew with
 * @returns the number of seconds to add to the current local system clock time
 * to get an rough guess of the time on the given server
 */
export const estimateSkew = async (serverEndpoint = window.origin): Promise<number> => {
  const localUnixTimeBefore = Date.now();
  const response = await fetch(serverEndpoint);
  return estimateSkewFromHeaders(response.headers, localUnixTimeBefore);
};

export type AnyHeaders = AxiosResponseHeaders | RawAxiosResponseHeaders | Headers;

/**
 * Rough estimate of number of seconds to add to the curren time to get
 * the clock time on the server that responded with the headers object.
 * @param headers A set of headers, which must include the `date` header
 * @param dateNowBefore time before initiating the request, usually by calling
 * `Date.now()`. Note this is in milliseconds since the epoch, while the
 * estimate is given in seconds.
 * @returns the number of seconds to add to the current local system clock time
 * to get an rough guess of the time on the server that was used
 */
export const estimateSkewFromHeaders = (headers: AnyHeaders, dateNowBefore?: number): number => {
  const localUnixTimeBefore = (dateNowBefore || Date.now()) / 1000;
  let serverDateString;
  if (headers.get) {
    serverDateString = (headers as Headers).get('Date');
  } else {
    serverDateString = (headers as AxiosResponseHeaders | RawAxiosResponseHeaders).date;
  }
  if (serverDateString === null) {
    throw Error('Cannot get access to Date header!');
  }
  const serverUnixTime = Date.parse(serverDateString) / 1000;
  const localUnixTimeAfter = Date.now() / 1000;
  const deltaBefore = serverUnixTime - localUnixTimeBefore;
  const deltaAfter = serverUnixTime - localUnixTimeAfter;

  return Math.round((deltaBefore + deltaAfter) / 2);
};
