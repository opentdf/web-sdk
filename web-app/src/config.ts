export type TDFConfig = {
  oidc: {
    // eg 'http://localhost:65432/auth/realms/opentdf'
    host: string;
    // eg browsertest
    clientId: string;
  };
  kas: string;
  reader: string;
};

function cfg(): TDFConfig {
  const { VITE_TDF_CFG } = import.meta.env;
  if (!VITE_TDF_CFG) {
    return {
      oidc: {
        // points to keycloak login otherwise iss won't match
        host: 'http://localhost:8888/auth/realms/opentdf',
        clientId: 'browsertest',
      },
      kas: 'http://localhost:65432/kas',
      reader: 'https://secure.virtru.com/start?htmlProtocol=1',
    };
  }
  return JSON.parse(VITE_TDF_CFG);
}

export const config = cfg();
