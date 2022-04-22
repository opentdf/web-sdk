import qs from 'query-string';

export default class AccessToken {
  constructor(cfg, request) {
    this.config = cfg;
    this.request = request;
  }

  async info(accessToken) {
    const url = `/auth/realms/${this.config.realm}/protocol/openid-connect/userinfo`;
    const response = await this.request.get(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return response.data;
  }

  async forceRefresh() {
    // If no token provided, force refresh of cached tokens
    // Auth mode can be `credentials` -> implies that we should have clientID and clientSecret
    // Auth mode can be `browser` -> implies that we're in a browser context, and only have refreshToken
    // Other modes TBD, but that covers the basics
    if (this.config.auth_mode === 'credentials') {
      this.data = undefined;
      await this.get();
      return this.data;
    }

    if (this.data && this.data.refresh_token) {
      return this.refresh(this.data.refresh_token);
    }

    throw new Error(
      "forceRefresh refreshes a preexisting cached tokenset, and none exists. Try 'refresh(myToken)' instead."
    );
  }

  async refresh(refreshToken) {
    const cfg = this.config;

    const args = {
      grant_type: 'refresh_token',
      client_id: cfg.client_id,
      refresh_token: refreshToken,
    };

    if (cfg.auth_mode === 'credentials') {
      args.client_secret = cfg.client_secret;
    }

    const url = `/auth/realms/${cfg.realm}/protocol/openid-connect/token`;
    const response = await this.request.post(url, qs.stringify(args));

    this.data = response.data;
    return response.data;
  }

  async exchangeJwt(jwtToken) {
    const cfg = this.config;
    const url = `/auth/realms/${cfg.realm}/protocol/openid-connect/token`;

    const args = {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: jwtToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      client_id: cfg.client_id,
      audience: cfg.client_id,
    };

    if (cfg.auth_mode === 'credentials') {
      args.client_secret = cfg.client_secret;
    }

    const response = await this.request.post(url, qs.stringify(args));
    this.data = response.data;
    return this.data;
  }

  async get() {
    const cfg = this.config;

    if (!this.data) {
      if (!cfg.client_id || !cfg.client_secret) {
        throw new Error(`to call get(), either client credentials must be provided in the config,
                          or a cached tokenset from a token refresh from a previous call to refresh() must exist`);
      }
      const url = `/auth/realms/${cfg.realm}/protocol/openid-connect/token`;
      const response = await this.request.post(
        url,
        qs.stringify({
          grant_type: 'client_credentials',
          client_id: cfg.client_id,
          client_secret: cfg.client_secret,
        })
      );
      this.data = response.data;

      return this.data.access_token;
    }
    try {
      await this.info(this.data.access_token);
      return this.data.access_token;
    } catch (err) {
      try {
        await this.refresh(this.data.refresh_token);
        return this.data.access_token;
      } catch (refreshErr) {
        delete this.data;
        //TODO PLAT-1142
        //Since this is a recursive call - we should add backoffs and retry limits here
        // (and to HTTP calls in this library generally)
        return this.get();
      }
    }
  }
}
