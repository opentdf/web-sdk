import Token from './Token.js';

export default class Jwt {
  constructor(config, request) {
    this.config = config;
    this.request = request;
  }

  decode(accessToken) {
    return new Promise((resolve) => {
      resolve(new Token(accessToken));
    });
  }

  async verify(accessToken) {
    const url = `/auth/realms/${this.config.realm}/protocol/openid-connect/userinfo`;
    await this.request.get(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return new Token(accessToken);
  }
}
