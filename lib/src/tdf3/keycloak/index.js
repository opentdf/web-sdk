import Axios from 'axios';
import UserManager from './UserManager.js';
import AccessToken from './AccessToken.js';
import Jwt from './Jwt.js';

export default (cfg) => {
  const request = Axios.create({
    baseURL: cfg.auth_server_url,
  });

  //Safety checks
  if (!cfg.client_id) {
    throw new Error('A Keycloak client identifier is currently required for all auth mechanisms');
  }

  if (cfg.auth_mode === 'credentials' && !cfg.client_secret) {
    throw new Error('When using client credentials, both clientId and clientSecret are required');
  }

  // In some scenarios (e.g. browser) it's simpler to refresh the claims
  // with the pubkey AFTER object construction/initial auth, as opposed to doing so on the initial auth.
  // So if `cfg.virtruClientPubkey` isn't set/is undefined here, that's fine.
  // Auth will succeed without Virtru's custom claims being bound to the token,
  // and consumers of this library can provide a pubkey and refresh their token (and their claims)
  // at a later point.
  if (cfg.virtru_client_pubkey) {
    request.defaults.headers.post['X-VirtruPubKey'] = cfg.virtru_client_pubkey;
  }

  const accessToken = new AccessToken(cfg, request);
  const users = new UserManager(cfg, request, accessToken);
  const jwt = new Jwt(cfg, request);

  // In some scenarios (e.g. browser) it's simpler to refresh the claims
  // with the pubkey after the initial auth, as opposed to doing so on the initial auth.
  // Auth will succeed without Virtru's custom claims being bound to the token,
  // and consumers of this library can provide a pubkey and refresh their token (and their claims)
  // at a later point.
  function setVirtruPubkey(publicKey) {
    cfg.virtru_client_pubkey = publicKey;
    request.defaults.headers.post['X-VirtruPubKey'] = cfg.virtru_client_pubkey;
  }

  return {
    jwt,
    users,
    accessToken,
    setVirtruPubkey,
  };
};
