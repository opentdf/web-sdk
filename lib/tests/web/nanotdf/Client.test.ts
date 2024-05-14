import { expect } from '@esm-bundle/chai';
import { clientAuthProvider } from '../../../src/auth/providers.js';
import Client from '../../../src/nanotdf/Client.js';

describe('nanotdf client', () => {
  it('Can create a client with a mock EAS', async () => {
    const kasEndpoint = 'https://etheria.local/kas';
    const authProvider = await clientAuthProvider({
      clientId: 'string',
      oidcOrigin: 'string',
      exchange: 'client',
      clientSecret: 'password',
    });
    const client = new Client({ authProvider, kasEndpoint });
    expect(client.authProvider).to.be.ok;
  });
});
