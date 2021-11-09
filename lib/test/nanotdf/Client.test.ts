import { expect } from '@esm-bundle/chai';

import Client, { clientAuthProvider } from '../../src/nanotdf/Client.js';

describe('nanotdf client', () => {
  it('Can create a client with a mock EAS', async () => {
    const kasUrl = 'https://etheria.local/kas';
    const authProvider = await clientAuthProvider({
      organizationName: 'string',
      clientId: 'string',
      oidcOrigin: 'string',
      exchange: 'client',
      clientSecret: 'password',
    });
    const client = new Client(authProvider, kasUrl);
    expect(client.getAuthProvider()).to.be.ok;
  });
});
