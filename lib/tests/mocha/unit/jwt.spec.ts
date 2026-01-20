import { expect } from 'chai';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import {
  signJwt,
  verifyJwt,
  base64urlEncode,
  type JwtHeader,
  type JwtPayload,
} from '../../../tdf3/src/crypto/jwt.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';

describe('JWT Utilities', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;
  const cryptoService: CryptoService = DefaultCryptoService;

  before(async () => {
    // Generate a test key pair
    const keyPair = await cryptoService.generateSigningKeyPair();
    const pemPair = await cryptoService.cryptoToPemPair(keyPair);
    privateKeyPem = pemPair.privateKey;
    publicKeyPem = pemPair.publicKey;
  });

  describe('signJwt() and verifyJwt() round-trip', () => {
    it('should sign and verify a simple JWT with RS256', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = {
        sub: 'user123',
        name: 'Test User',
      };

      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      expect(token).to.be.a('string');
      expect(token.split('.')).to.have.lengthOf(3);

      const result = await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
      });

      expect(result.header.alg).to.equal('RS256');
      expect(result.payload.sub).to.equal('user123');
      expect(result.payload.name).to.equal('Test User');
    });

    it('should sign and verify a JWT with typ header', async () => {
      const header: JwtHeader = { alg: 'RS256', typ: 'JWT' };
      const payload: JwtPayload = { data: 'test' };

      const token = await signJwt(cryptoService, payload, privateKeyPem, header);
      const result = await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        typ: 'JWT',
      });

      expect(result.header.typ).to.equal('JWT');
      expect(result.payload.data).to.equal('test');
    });

    it('should sign and verify a JWT with standard claims', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const now = Math.floor(Date.now() / 1000);
      const payload: JwtPayload = {
        iss: 'https://issuer.example.com',
        sub: 'user123',
        aud: 'https://app.example.com',
        exp: now + 3600,
        nbf: now - 60,
        iat: now,
      };

      const token = await signJwt(cryptoService, payload, privateKeyPem, header);
      const result = await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        issuer: 'https://issuer.example.com',
        audience: 'https://app.example.com',
        subject: 'user123',
      });

      expect(result.payload.iss).to.equal('https://issuer.example.com');
    });
  });

  describe('verifyJwt() security validations', () => {
    it('should reject JWT with alg "none"', async () => {
      // Manually craft a JWT with alg: "none"
      const header = base64urlEncode(JSON.stringify({ alg: 'none' }));
      const payload = base64urlEncode(JSON.stringify({ sub: 'user' }));
      const token = `${header}.${payload}.`;

      try {
        await verifyJwt(cryptoService, token, publicKeyPem);
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('Invalid JWT: alg "none" not allowed');
      }
    });

    it('should reject JWT with algorithm not in allowlist', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = { sub: 'user123' };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      try {
        await verifyJwt(cryptoService, token, publicKeyPem, { algorithms: [] });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('algorithm "RS256" not in allowlist');
      }
    });

    it('should reject JWT with tampered payload', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = { sub: 'user123', role: 'user' };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      // Tamper with payload
      const parts = token.split('.');
      const tamperedPayload = base64urlEncode(JSON.stringify({ sub: 'user123', role: 'admin' }));
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      try {
        await verifyJwt(cryptoService, tamperedToken, publicKeyPem, { algorithms: ['RS256'] });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('signature verification failed');
      }
    });

    it('should reject malformed JWT', async () => {
      try {
        await verifyJwt(cryptoService, 'invalid.token', publicKeyPem, { algorithms: ['RS256'] });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('expected 3 parts');
      }
    });
  });

  describe('verifyJwt() claim validations', () => {
    it('should validate audience claim', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = { sub: 'user123', aud: 'https://api.example.com' };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      // Should succeed with correct audience
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        audience: 'https://api.example.com',
      });

      // Should fail with wrong audience
      try {
        await verifyJwt(cryptoService, token, publicKeyPem, {
          algorithms: ['RS256'],
          audience: 'https://wrong.example.com',
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('unexpected "aud" claim');
      }
    });

    it('should validate issuer claim', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = { sub: 'user123', iss: 'https://issuer.example.com' };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      // Should succeed
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        issuer: 'https://issuer.example.com',
      });

      // Should fail with wrong issuer
      try {
        await verifyJwt(cryptoService, token, publicKeyPem, {
          algorithms: ['RS256'],
          issuer: 'https://wrong-issuer.example.com',
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('unexpected "iss" claim');
      }
    });

    it('should validate expiration time', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const now = Math.floor(Date.now() / 1000);

      // Expired token
      const expiredPayload: JwtPayload = { sub: 'user123', exp: now - 60 };
      const expiredToken = await signJwt(cryptoService, expiredPayload, privateKeyPem, header);

      try {
        await verifyJwt(cryptoService, expiredToken, publicKeyPem, { algorithms: ['RS256'] });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('token has expired');
      }

      // Valid token
      const validPayload: JwtPayload = { sub: 'user123', exp: now + 3600 };
      const validToken = await signJwt(cryptoService, validPayload, privateKeyPem, header);
      await verifyJwt(cryptoService, validToken, publicKeyPem, { algorithms: ['RS256'] });
    });

    it('should validate not before time', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const now = Math.floor(Date.now() / 1000);

      // Not yet valid
      const futurePayload: JwtPayload = { sub: 'user123', nbf: now + 3600 };
      const futureToken = await signJwt(cryptoService, futurePayload, privateKeyPem, header);

      try {
        await verifyJwt(cryptoService, futureToken, publicKeyPem, { algorithms: ['RS256'] });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('not yet valid');
      }
    });

    it('should validate max token age', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const now = Math.floor(Date.now() / 1000);
      const oldPayload: JwtPayload = { sub: 'user123', iat: now - 7200 };
      const oldToken = await signJwt(cryptoService, oldPayload, privateKeyPem, header);

      // Should fail with maxTokenAge of 1 hour
      try {
        await verifyJwt(cryptoService, oldToken, publicKeyPem, {
          algorithms: ['RS256'],
          maxTokenAge: '1h',
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('token is too old');
      }

      // Should succeed with maxTokenAge of 3 hours
      await verifyJwt(cryptoService, oldToken, publicKeyPem, {
        algorithms: ['RS256'],
        maxTokenAge: '3h',
      });
    });

    it('should support clock tolerance', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const now = Math.floor(Date.now() / 1000);
      const payload: JwtPayload = { sub: 'user123', exp: now - 30 };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      // Should fail without clock tolerance
      try {
        await verifyJwt(cryptoService, token, publicKeyPem, { algorithms: ['RS256'] });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('token has expired');
      }

      // Should succeed with 60 second clock tolerance
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        clockTolerance: 60,
      });
    });

    it('should validate required claims', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = { sub: 'user123', email: 'user@example.com' };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      // Should succeed
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        requiredClaims: ['sub', 'email'],
      });

      // Should fail when required claim is missing
      try {
        await verifyJwt(cryptoService, token, publicKeyPem, {
          algorithms: ['RS256'],
          requiredClaims: ['sub', 'email', 'role'],
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('Missing required claim');
      }
    });
  });

  describe('Duration parsing', () => {
    it('should parse duration strings', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const now = Math.floor(Date.now() / 1000);
      const payload: JwtPayload = { sub: 'user123', iat: now - 3700 };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      // Test minutes
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        maxTokenAge: '62m',
      });

      // Test hours
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        maxTokenAge: '2h',
      });

      // Test numeric seconds
      await verifyJwt(cryptoService, token, publicKeyPem, {
        algorithms: ['RS256'],
        maxTokenAge: 7200,
      });
    });
  });

  describe('signJwt() with custom headers', () => {
    it('should sign JWT with custom header fields', async () => {
      const header: JwtHeader = {
        alg: 'RS256',
        kid: 'key-123',
        customField: 'value',
      };
      const payload: JwtPayload = { sub: 'user123' };

      const token = await signJwt(cryptoService, payload, privateKeyPem, header);
      expect(token).to.be.a('string');

      const result = await verifyJwt(cryptoService, token, publicKeyPem);
      expect(result.header.kid).to.equal('key-123');
      expect(result.header.customField).to.equal('value');
    });
  });

  describe('verifyJwt() without options', () => {
    it('should verify JWT without options', async () => {
      const header: JwtHeader = { alg: 'RS256' };
      const payload: JwtPayload = { sub: 'user123' };
      const token = await signJwt(cryptoService, payload, privateKeyPem, header);

      const result = await verifyJwt(cryptoService, token, publicKeyPem);
      expect(result.payload.sub).to.equal('user123');
    });
  });
});
