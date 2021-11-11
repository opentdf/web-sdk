import { expect } from '@esm-bundle/chai';
import { fake } from 'sinon';
import { AccessToken } from '../../src/keycloak/AccessToken.js';

// // const qsparse = (s: string) => Object.fromEntries(new URLSearchParams(s));
const qsparse = (s: string) =>
  [...new URLSearchParams(s).entries()].reduce((o, i) => ({ ...o, [i[0]]: i[1] }), {});

function mockFetch(r: unknown = { hello: 'world' }) {
  const json = fake.resolves(r);
  const request = fake.resolves({ json });
  return request;
}

// Due to Jest mocks not working with ESModules currently,
// these tests use poor man's mocking
describe('AccessToken', () => {
  describe('userinfo endpoint', () => {
    it('appends Auth header and calls userinfo', async () => {
      const cfg = {
        auth_server_url: 'http://auth.invalid',
        client_id: 'yoo',
        realm: 'yeet',
      };
      const mf = mockFetch();
      const accessToken = new AccessToken(cfg, mf);
      const res = await accessToken.info('fakeToken');
      expect(res).to.have.property('hello', 'world');
      expect(mf.lastCall.firstArg).to.match(
        /\/auth\/realms\/yeet\/protocol\/openid-connect\/userinfo$/
      );
      expect(mf).to.have.nested.property('lastArg.headers.Authorization', 'Bearer fakeToken');
    });
  });

  describe('exchanging refresh token for token with TDF claims', () => {
    describe('using client credentials', () => {
      it('passes client creds with refresh grant type to token endpoint', async () => {
        const mf = mockFetch({ access_token: 'fdfsdffsdf' });
        const accessToken = new AccessToken(
          {
            auth_mode: 'credentials',
            auth_server_url: 'http://auth.invalid',
            realm: 'yeet',
            client_id: 'myid',
            client_secret: 'mysecret',
          },
          mf
        );
        accessToken.setVirtruPubkey('fake-pub-key');
        const res = await accessToken.refresh('refresh');
        expect(res).to.equal('fdfsdffsdf');
        expect(mf.lastCall.firstArg).to.match(
          /\/auth\/realms\/yeet\/protocol\/openid-connect\/token$/
        );
        const body = qsparse(mf.lastCall.lastArg.body);
        expect(body).to.eql({
          grant_type: 'refresh_token',
          client_id: 'myid',
          client_secret: 'mysecret',
          refresh_token: 'refresh',
        });
        expect(mf.lastCall.lastArg.headers).to.have.property('X-VirtruPubKey', 'fake-pub-key');
      });
    });
    describe('using browser flow', () => {
      it('passes only refresh token with refresh grant type to token endpoint', async () => {
        const mf = mockFetch({ access_token: 'fake_token' });
        const accessToken = new AccessToken(
          {
            realm: 'yeet',
            auth_server_url: 'http://auth.invalid',
            auth_mode: 'browser',
            client_id: 'browserclient',
          },
          mf
        );
        const res = await accessToken.refresh('fakeRefreshToken');
        expect(res).to.eql('fake_token');
        expect(mf.lastCall.firstArg).to.match(
          /\/auth\/realms\/yeet\/protocol\/openid-connect\/token$/
        );
        const body = qsparse(mf.lastCall.lastArg.body);
        expect(body).to.eql({
          grant_type: 'refresh_token',
          client_id: 'browserclient',
          refresh_token: 'fakeRefreshToken',
        });
      });
    });
  });

  describe('exchanging external JWT for token with TDF claims', () => {
    describe('using client credentials', () => {
      it('passes client creds and JWT with exchange grant type to token endpoint', async () => {
        const mf = mockFetch({ access_token: 'fake_token' });
        const accessToken = new AccessToken(
          {
            realm: 'yeet',
            auth_server_url: 'http://auth.invalid',
            client_id: 'myid',
            client_secret: 'mysecret',
            auth_mode: 'credentials',
          },
          mf
        );
        const res = await accessToken.exchangeJwt('subject.token');
        expect(res).to.eql('fake_token');
        expect(mf.lastCall.firstArg).to.match(
          /\/auth\/realms\/yeet\/protocol\/openid-connect\/token$/
        );
        const body = qsparse(mf.lastCall.lastArg.body);
        expect(body).to.eql({
          audience: 'myid',
          client_id: 'myid',
          client_secret: 'mysecret',
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: 'subject.token',
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        });
      });
    });

    describe('using browser flow', () => {
      it('passes only external JWT with exchange grant type to token endpoint', async () => {
        const mf = mockFetch({ access_token: 'fake_token' });
        const accessToken = new AccessToken(
          {
            realm: 'yeet',
            auth_mode: 'browser',
            auth_server_url: 'http://auth.invalid',
            client_id: 'browserclient',
          },
          mf
        );

        const jwtToken = 'fdfsdffsdf';
        const res = await accessToken.exchangeJwt(jwtToken);
        expect(res).to.eql('fake_token');
        expect(mf.lastCall.firstArg).to.match(
          /\/auth\/realms\/yeet\/protocol\/openid-connect\/token$/
        );
        const body = qsparse(mf.lastCall.lastArg.body);
        expect(body).to.eql({
          audience: 'browserclient',
          client_id: 'browserclient',
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: jwtToken,
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        });
      });
    });
  });

  describe('forceRefresh', () => {
    it('should call refresh using internal refresh token if cached tokenset exists', async () => {
      const mf = mockFetch({ access_token: 'sure', refresh_token: 'aieeee' });
      const accessToken = new AccessToken(
        {
          realm: 'yeet',
          auth_mode: 'browser',
          auth_server_url: 'http://auth.invalid',
          client_id: 'browserclient',
        },
        mf
      );

      // Do a refresh to cache tokenset
      const res = await accessToken.refresh('fdfsdffsdf');
      expect(res).to.eql('sure');
      expect(accessToken.data?.refresh_token).to.eql('aieeee');
      expect(mf.lastCall.firstArg).to.match(
        /\/auth\/realms\/yeet\/protocol\/openid-connect\/token$/
      );
      const body = qsparse(mf.lastCall.lastArg.body);
      expect(body).to.eql({
        client_id: 'browserclient',
        grant_type: 'refresh_token',
        refresh_token: 'fdfsdffsdf',
      });

      // Force refresh of cached tokens
      const forceRes = await accessToken.forceRefresh();
      expect(mf.callCount).to.eql(2);
      expect(forceRes).to.eql('sure');
      expect(mf.lastCall.firstArg).to.match(
        /\/auth\/realms\/yeet\/protocol\/openid-connect\/token$/
      );
      const parseForceArgs = qsparse(mf.lastCall.lastArg.body);
      expect(parseForceArgs).to.have.property('grant_type', 'refresh_token');
      expect(parseForceArgs).to.have.property('refresh_token', 'aieeee');
    });

    it('should return error if force refresh happens and no cached tokenset exists', async () => {
      const mf = mockFetch({ access_token: 'sure', refresh_token: 'aieeee' });
      const accessToken = new AccessToken(
        {
          realm: 'yeet',
          auth_mode: 'browser',
          auth_server_url: 'http://auth.invalid',
          client_id: 'browserclient',
        },
        mf
      );
      // Force refresh of cached tokens
      try {
        await accessToken.forceRefresh();
        expect.fail();
      } catch (e) {
        expect(e.message).to.match(
          /forceRefresh refreshes a preexisting cached tokenset, and none exists/
        );
      }
    });
  });

  describe('get token', () => {
    describe('clientCredentials and no cached tokenset', () => {
      it('should call token endpoint using client credentials if no cached tokenset', async () => {
        const mf = mockFetch({ access_token: 'notreal' });
        const accessTokenClient = new AccessToken(
          {
            realm: 'yeet',
            auth_server_url: 'http://auth.invalid',
            client_id: 'myid',
            client_secret: 'mysecret',
            auth_mode: 'credentials',
          },
          mf
        );
        // Do a refresh to cache tokenset
        const atr = await accessTokenClient.get();
        expect(atr).to.eql('notreal');
        expect(mf.lastCall.firstArg).to.eql(
          'http://auth.invalid/auth/realms/yeet/protocol/openid-connect/token'
        );
        const parseArgs = qsparse(mf.lastCall.lastArg.body);
        expect(parseArgs).to.have.property('grant_type', 'client_credentials');
        expect(parseArgs).to.have.property('client_id', 'myid');
        expect(parseArgs).to.have.property('client_secret', 'mysecret');
      });

      it('should throw error if no cached tokenset and no client creds in config', async () => {
        const mf = mockFetch({ access_token: 'notreal' });
        try {
          const accessTokenClient = new AccessToken(
            {
              realm: 'yeet',
              auth_server_url: 'http://auth.invalid',
              auth_mode: 'credentials',
              client_id: '',
            },
            mf
          );

          await accessTokenClient.get();
        } catch (e) {
          expect(e.message).to.match(/client identifier/);
        }
      });
    });
  });

  describe('cached tokenset', () => {
    it('should call userinfo endpoint and return cached tokenset', async () => {
      const mf = mockFetch({ access_token: 'notreal' });
      const accessTokenClient = new AccessToken(
        {
          realm: 'yeet',
          auth_server_url: 'http://auth.invalid',
          client_id: 'myid',
          client_secret: 'mysecret',
          auth_mode: 'credentials',
        },
        mf
      );
      accessTokenClient.data = {
        refresh_token: 'r',
        access_token: 'a',
      };
      // Do a refresh to cache tokenset
      const res = await accessTokenClient.get();
      expect(res).to.eql('a');
      // TODO Why do we do an info call here?
      // expect(mf.callCount).to.eql(0);
    });
    it('should attempt to refresh token if userinfo call throws error', async () => {
      const json = fake.resolves({ access_token: 'a' });
      const mf = fake((url: string, { method, headers }: { method: string; headers: unknown }) => {
        if (method === 'POST') {
          return Promise.resolve({ json });
        }
        return Promise.reject(`yee [${url}] [${JSON.stringify(headers)}]`);
      });
      const accessTokenClient = new AccessToken(
        {
          realm: 'yeet',
          auth_server_url: 'http://auth.invalid',
          client_id: 'myid',
          client_secret: 'mysecret',
          auth_mode: 'credentials',
        },
        mf
      );
      accessTokenClient.data = {
        refresh_token: 'r',
        access_token: 'a',
      };
      // Do a refresh to cache tokenset
      const res = await accessTokenClient.get();
      expect(res).to.eql('a');
      expect(mf.callCount).to.eql(2);
    });
  });
});
