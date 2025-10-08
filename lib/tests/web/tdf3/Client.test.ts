import { expect } from '@esm-bundle/chai';
import { clientAuthProvider } from '../../../src/auth/providers.js';
import { Client as TDF3Client, type ClientConfig } from '../../../tdf3/src/client/index.js';

describe('tdf3 client', () => {
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
      const client = new TDF3Client(defaultConfig);

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

      const client = new TDF3Client(config);
      expect(client.fulfillableObligationFQNs).to.deep.equal(fqns);
    });

    it('should store empty array when explicitly provided as empty', async () => {
      const fqns: string[] = [];
      const config = {
        ...defaultConfig,
        fulfillableObligationFQNs: fqns,
      };

      const client = new TDF3Client(config);
      expect(client.fulfillableObligationFQNs).to.be.an('array');
      expect(client.fulfillableObligationFQNs).to.have.lengthOf(0);
    });
  });
});
