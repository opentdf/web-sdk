import { expect } from '@esm-bundle/chai';
import { clientAuthProvider } from '../../../src/auth/providers.js';
import Client, { ClientConfig } from '../../../src/nanotdf/Client.js';

describe('nanotdf client', () => {
  it('Can create a client with a mock EAS', async () => {
    const kasEndpoint = 'https://etheria.local/kas';
    const platformUrl = 'https://etheria.local';
    const authProvider = await clientAuthProvider({
      clientId: 'string',
      oidcOrigin: 'string',
      exchange: 'client',
      clientSecret: 'password',
    });
    const client = new Client({ authProvider, kasEndpoint, platformUrl });
    expect(client.authProvider).to.be.ok;
  });

  describe('fulfillableObligationFQNs', async () => {
    const authProvider = await clientAuthProvider({
      clientId: 'string',
      oidcOrigin: 'string',
      exchange: 'client',
      clientSecret: 'password',
    });
    const defaultConfig: ClientConfig = {
      authProvider,
      kasEndpoint: 'https://opentdf.io/kas',
      platformUrl: 'https://opentdf.io',
    };

    it('should default to empty array when not provided', async () => {
      const client = new Client(defaultConfig);

      expect(client.fulfillableObligationFQNs).to.be.an('array');
      expect(client.fulfillableObligationFQNs).to.have.lengthOf(0);
    });

    it('should store fulfillableObligationFQNs when provided', async () => {
      const fqns = [
        'https://example.com/obl/drm/value/mask',
        'https://example.com/obl/watermark/value/apply',
      ];
      const config = {
        ...defaultConfig,
        fulfillableObligationFQNs: fqns,
      };

      const client = new Client(config);
      expect(client.fulfillableObligationFQNs).to.deep.equal(fqns);
    });

    it('should store empty array when explicitly provided as empty', async () => {
      const fqns: string[] = [];
      const config = {
        ...defaultConfig,
        fulfillableObligationFQNs: fqns,
      };

      const client = new Client(config);
      expect(client.fulfillableObligationFQNs).to.be.an('array');
      expect(client.fulfillableObligationFQNs).to.have.lengthOf(0);
    });
  });
});
