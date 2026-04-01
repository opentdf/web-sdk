import { expect } from '@esm-bundle/chai';
import { OpenTDF } from '../../src/opentdf.js';
import type { AuthProvider } from '../../src/auth/auth.js';
import type { Interceptor } from '@connectrpc/connect';
import { authTokenInterceptor } from '../../src/auth/interceptors.js';

const stubAuthProvider: AuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (req) => req,
};

describe('OpenTDF constructor', () => {
  describe('disableDPoP flag', () => {
    it('sets dpopEnabled to false when disableDPoP is true', () => {
      const client = new OpenTDF({
        authProvider: stubAuthProvider,
        disableDPoP: true,
      });
      expect(client.dpopEnabled).to.equal(false);
    });

    it('sets dpopEnabled to true when disableDPoP is false', () => {
      const client = new OpenTDF({
        authProvider: stubAuthProvider,
        disableDPoP: false,
      });
      expect(client.dpopEnabled).to.equal(true);
    });

    it('sets dpopEnabled to true when disableDPoP is omitted', () => {
      const client = new OpenTDF({
        authProvider: stubAuthProvider,
      });
      expect(client.dpopEnabled).to.equal(true);
    });

    it('does not pass dpopKeys to tdf3Client when disableDPoP is true', () => {
      const client = new OpenTDF({
        authProvider: stubAuthProvider,
        disableDPoP: true,
      });
      expect(client.tdf3Client.dpopEnabled).to.equal(false);
    });

    it('passes dpopKeys to tdf3Client when disableDPoP is false', () => {
      const client = new OpenTDF({
        authProvider: stubAuthProvider,
        disableDPoP: false,
      });
      expect(client.tdf3Client.dpopEnabled).to.equal(true);
    });
  });

  describe('ready promise', () => {
    it('eagerly binds DPoP keys to the auth provider', async () => {
      let publicKeyUpdated = false;
      const trackingAuthProvider: AuthProvider = {
        updateClientPublicKey: async () => {
          publicKeyUpdated = true;
        },
        withCreds: async (req) => req,
      };
      const client = new OpenTDF({
        authProvider: trackingAuthProvider,
      });
      await client.ready;
      expect(publicKeyUpdated).to.equal(true);
    });

    it('resolves immediately when DPoP is disabled', async () => {
      let publicKeyUpdated = false;
      const trackingAuthProvider: AuthProvider = {
        updateClientPublicKey: async () => {
          publicKeyUpdated = true;
        },
        withCreds: async (req) => req,
      };
      const client = new OpenTDF({
        authProvider: trackingAuthProvider,
        disableDPoP: true,
      });
      await client.ready;
      expect(publicKeyUpdated).to.equal(false);
    });

    it('propagates rejection when updateClientPublicKey fails', async () => {
      const failingAuthProvider: AuthProvider = {
        updateClientPublicKey: async () => {
          throw new Error('IdP unreachable');
        },
        withCreds: async (req) => req,
      };
      const client = new OpenTDF({
        authProvider: failingAuthProvider,
      });
      try {
        await client.ready;
        expect.fail('expected ready to reject');
      } catch (e) {
        expect(e).to.have.property('message', 'IdP unreachable');
      }
    });
  });

  describe('interceptors (new path)', () => {
    const stubInterceptor: Interceptor = (next) => (req) => next(req);

    it('accepts interceptors instead of authProvider', () => {
      const client = new OpenTDF({
        interceptors: [stubInterceptor],
        platformUrl: 'https://example.com',
      });
      expect(client.interceptors).to.deep.equal([stubInterceptor]);
      expect(client.authProvider).to.equal(undefined);
    });

    it('ready resolves immediately with interceptors', async () => {
      const client = new OpenTDF({
        interceptors: [stubInterceptor],
      });
      // Should not hang or throw
      await client.ready;
    });

    it('does not call updateClientPublicKey with interceptors', async () => {
      const client = new OpenTDF({
        interceptors: [authTokenInterceptor(async () => 'token')],
      });
      await client.ready;
      // No updateClientPublicKey to call — if we got here, no error was thrown
      expect(client.dpopEnabled).to.equal(true);
    });

    it('throws if neither authProvider nor interceptors provided', () => {
      try {
        new OpenTDF({});
        expect.fail('should have thrown');
      } catch (e) {
        expect((e as Error).message).to.include('Either authProvider or interceptors');
      }
    });

    it('resolves auth config in tdf3Client', () => {
      const client = new OpenTDF({
        interceptors: [stubInterceptor],
        platformUrl: 'https://example.com',
      });
      expect(client.tdf3Client.auth).to.deep.equal({ interceptors: [stubInterceptor] });
    });

    it('generates dpopKeys even with interceptors', async () => {
      const client = new OpenTDF({
        interceptors: [stubInterceptor],
      });
      const keys = await client.dpopKeys;
      expect(keys).to.have.property('publicKey');
      expect(keys).to.have.property('privateKey');
    });
  });
});
