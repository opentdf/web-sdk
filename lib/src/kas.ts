import { AuthProvider } from "./auth/auth";

export class RewrapRequest {
  signedRequestToken = '';
}

export class RewrapResponse {
  entityWrappedKey = '';
  sessionPublicKey = '';
}

/**
 * Get a rewrapped access key to the document, if possible
 * @param url Key access server rewrap endpoint
 * @param requestBody a signed request with an encrypted document key
 * @param authProvider Authorization middleware
 * @param clientVersion
 */
export async function fetchWrappedKey(
  url: string,
  requestBody: RewrapRequest,
  authProvider: AuthProvider,
  clientVersion: string
): Promise<RewrapResponse> {
  const req = await authProvider.withCreds({
    url,
    method: 'post',
    headers: {
      'Content-Type': 'application/json',
      'virtru-ntdf-version': clientVersion,
    },
    body: JSON.stringify(requestBody),
  });
  const response = await fetch(req.url, {
    method: req.method,
    mode: 'cors', // no-cors, *cors, same-origin
    cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
    credentials: 'same-origin', // include, *same-origin, omit
    headers: req.headers,
    redirect: 'follow', // manual, *follow, error
    referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    body: req.body as BodyInit,
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}
