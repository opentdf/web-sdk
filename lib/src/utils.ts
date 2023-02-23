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

export const calculateSKU = async (serverEndpoint = window.location.host): Promise<number> => {
  const localUnixTimeBefore = Date.now() / 1000;
  const response = await fetch(serverEndpoint, {
    method: 'GET',
    headers: { 'Access-Control-Expose-Headers': 'Date' },
  });

  const serverDateString = response.headers.get('Date');
  if (serverDateString === null) {
    throw Error('Cannot get access to Date header!');
  }
  const serverUnixTime = Date.parse(serverDateString) / 1000;
  const localUnixTimeAfter = Date.now() / 1000;
  const deltaBefore = serverUnixTime - localUnixTimeBefore;
  const deltaAfter = serverUnixTime - localUnixTimeAfter;

  return (deltaBefore + deltaAfter) / 2;
};
