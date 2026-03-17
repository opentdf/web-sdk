import { expect } from '@esm-bundle/chai';
import { OpenTDF } from '../../src/opentdf.js';
import type { AuthProvider } from '../../src/auth/auth.js';

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
  });
});
