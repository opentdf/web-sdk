import { AuthProvider } from '../auth/auth.js';
import { rstrip } from '../utils.js';
import { GetAttributeValuesByFqnsResponse, Value } from './attributes.js';

export async function attributeFQNsAsValues(
  kasUrl: string,
  authProvider: AuthProvider,
  ...fqns: string[]
): Promise<Value[]> {
  const avs = new URLSearchParams();
  for (const fqn of fqns) {
    avs.append('fqns', fqn);
  }
  avs.append('withValue.withKeyAccessGrants', 'true');
  avs.append('withValue.withAttribute.withKeyAccessGrants', 'true');
  const uNoSlash = rstrip(kasUrl, '/');
  const uNoKas = uNoSlash.endsWith('/kas') ? uNoSlash.slice(0, -4) : uNoSlash;
  const url = `${uNoKas}/attributes/*/fqn?${avs}`;
  const req = await authProvider.withCreds({
    url,
    headers: {},
    method: 'GET',
  });
  let response: Response;
  try {
    response = await fetch(req.url, {
      mode: 'cors',
      credentials: 'same-origin',
      headers: req.headers,
      redirect: 'follow',
      referrerPolicy: 'no-referrer',
    });

    if (!response.ok) {
      throw new Error(`${req.method} ${req.url} => ${response.status} ${response.statusText}`);
    }
  } catch (e) {
    console.error(`network error [${req.method} ${req.url}]`, e);
    throw e;
  }

  let resp: GetAttributeValuesByFqnsResponse;
  try {
    resp = (await response.json()) as GetAttributeValuesByFqnsResponse;
  } catch (e) {
    console.error(`response parse error [${req.method} ${req.url}]`, e);
    throw e;
  }

  const values: Value[] = [];
  for (const [fqn, av] of Object.entries(resp.fqnAttributeValues)) {
    if (!av.value) {
      console.log(`Missing value definition for [${fqn}]; is this a valid attribute?`);
      continue;
    }
    if (av.attribute && !av.value.attribute) {
      av.value.attribute = av.attribute;
    }
    values.push(av.value);
  }
  return values;
}
