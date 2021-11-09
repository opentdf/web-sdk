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
 * @param authHeader Bearer token string
 * @param clientVersion
 */
export async function fetchWrappedKey(
  url: string,
  requestBody: RewrapRequest,
  authHeader: string,
  clientVersion: string
): Promise<RewrapResponse> {
  const response = await fetch(url, {
    method: 'POST',
    mode: 'cors', // no-cors, *cors, same-origin
    cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
    credentials: 'same-origin', // include, *same-origin, omit
    headers: {
      'Content-Type': 'application/json',
      Authorization: authHeader,
      'virtru-ntdf-version': clientVersion,
    },
    redirect: 'follow', // manual, *follow, error
    referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}
