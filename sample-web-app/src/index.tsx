import React from 'react';
import ReactDOM from 'react-dom';
import { OidcProvider } from '@axa-fr/react-oidc-context';
import App from './App.jsx';
import './index.css';

const configuration = {
  client_id: 'abacus-web',
  redirect_uri: 'http://localhost:8080/authentication/callback',
  silent_redirect_uri: 'http://localhost:8080/authentication/silent-callback', // Optional activate silent-signin that use cookies between OIDC server and client javascript to restore the session
  scope: 'roles profile email',
  authority: 'http://localhost:65432/auth/realms/tdf',
  service_worker_relative_url: '/OidcServiceWorker.js',
  service_worker_only: true,
};

ReactDOM.render(
  <React.StrictMode>
    <OidcProvider configuration={configuration}>
      <App />
    </OidcProvider>
  </React.StrictMode>,
  document.getElementById('root')
);

// Hot Module Replacement (HMR) - Remove this snippet to remove HMR.
// Learn more: https://snowpack.dev/concepts/hot-module-replacement
if (import.meta.hot) {
  import.meta.hot.accept();
}
