import { AuthProvider } from '@opentdf/sdk';
import { PlatformClient } from '@opentdf/sdk/platform';
import { ActiveStateEnum } from '@opentdf/sdk/platform/common/common_pb.js';
import { useState } from 'react';

interface ConnectRpcExampleProps {
  authProvider: AuthProvider;
}

export function ConnectRpcExample({ authProvider }: ConnectRpcExampleProps) {
  const [result, setResult] = useState('');

  const platform = new PlatformClient({
    authProvider,
    platformUrl: '/api',
  });

  const handleWellknown = async () => {
    const response = await platform.v1.wellknown.getWellKnownConfiguration({});
    setResult(JSON.stringify(response.configuration));
  };

  const handleKas = async () => {
    const response = await platform.v1.access.publicKey({});
    setResult(response.publicKey);
  };

  const handlePolicy = async () => {
    const request = {
      namespace: 'default',
      state: ActiveStateEnum.ACTIVE,
      pagination: {
        limit: 100,
        offset: 0,
      },
    };

    const response = await platform.v1.attributes.listAttributes(request);
    setResult(response.attributes.map((s) => `${s}`).join(','));
  };

  return (
    <>
      <fieldset>
        <legend>Connect RPC</legend>
        <button id="wellknown_config" onClick={handleWellknown}>
          Wellknown
        </button>
        <button id="public_kas_key" onClick={handleKas}>
          Public Key Kas
        </button>
        <button id="policy_list_attr" onClick={handlePolicy}>
          Policy List Attributes
        </button>
        <textarea id="connect_result" value={result} readOnly></textarea>
      </fieldset>
    </>
  );
}
