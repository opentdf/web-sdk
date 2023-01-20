import { useState, useEffect, type ChangeEvent } from 'react';
import './App.css';
import { NanoTDFClient, AuthProviders } from '@opentdf/client';
import { type SessionInformation, OidcClient } from './session.js';

function toHex(a: Uint8Array) {
  return [...a].map((x) => x.toString(16).padStart(2, '0')).join('');
}

const oidcClient = new OidcClient(
  'http://localhost:65432/auth/realms/tdf',
  'browsertest',
  'otdf-sample-web-app'
);

function click(node: HTMLElement) {
  try {
    node.dispatchEvent(new MouseEvent('click'));
  } catch (e) {
    const evt = document.createEvent('MouseEvents');
    evt.initMouseEvent(
      'click',
      true,
      true,
      window,
      0,
      0,
      0,
      80,
      20,
      false,
      false,
      false,
      false,
      0,
      null
    );
    node.dispatchEvent(evt);
  }
}

function saver(blob: Blob, name: string) {
  const a = document.createElement('a');
  a.download = name;
  a.rel = 'noopener';
  a.href = URL.createObjectURL(blob);
  setTimeout(function () {
    URL.revokeObjectURL(a.href);
  }, 4e4); // 40s
  click(a);
}


function App() {
  const [cipherText, setCipherText] = useState<Uint8Array | undefined>();
  const [plainText, setPlainText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | undefined>();
  const [authState, setAuthState] = useState<SessionInformation>({ sessionState: 'start' });

  useEffect(() => {
    oidcClient
      .currentSession()
      .then((a) => {
        console.log(a);
        setAuthState(a);
      })
      .catch((e) => {
        console.error(e);
        // setAuthState({ sessionState: 'error' });
      });
  }, []);

  const changeHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.files?.length) {
      const [file] = target.files;
      setSelectedFile(file);
    }
  };

  const handleEncrypt = async () => {
    if (!selectedFile) {
      console.warn('PLEASE SELECT FILE');
      return true;
    }
    if (!authState?.user?.refreshToken) {
      console.warn('PLEASE LOG IN');
      return true;
    }
    console.info(`[THINKING about ${selectedFile.name}]`);
    const arrayBuffer = await selectedFile.arrayBuffer();
    const authProvider = await AuthProviders.refreshAuthProvider({
      exchange: 'refresh',
      clientId: oidcClient.clientId,
      oidcOrigin: oidcClient.host,
      oidcRefreshToken: authState.user.refreshToken,
    });
    const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
    const cipherText = new Uint8Array(await nanoClient.encrypt(arrayBuffer));
    console.log(`Ciphertext: ${toHex(cipherText)}`);
    setCipherText(cipherText);
    saver(new Blob([cipherText]), `${selectedFile.name}.ntdf`);
    return true;
  };

  const handleDecrypt = async () => {
    if (!selectedFile) {
      console.log('PLEASE SELECT FILE');
      return false;
    }
    if (!authState?.user?.refreshToken) {
      console.error('decrypt while logged out doesnt work');
      return false;
    }
    const authProvider = await AuthProviders.refreshAuthProvider({
      exchange: 'refresh',
      clientId: oidcClient.clientId,
      oidcOrigin: oidcClient.host,
      oidcRefreshToken: authState.user.refreshToken,
    });
    const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
    const plainText = new Uint8Array(await nanoClient.decrypt(await selectedFile.arrayBuffer()));
    setPlainText(`plain text: ${toHex(plainText)}`);
    saver(new Blob([plainText]), `${selectedFile.name}.decrypted`);
    return false;
  };

  const SessionInfo =
    authState.sessionState == 'start' ? (
      <button id="login_button" onClick={() => oidcClient.authViaRedirect()}>
        Log In
      </button>
    ) : authState.sessionState == 'error' ? (
      <h3 id="error">ERROR</h3>
    ) : authState.sessionState == 'redirecting' ? (
      <>
        <h3 id="error">redirecting???</h3>
        <button id="login_button" onClick={() => oidcClient.authViaRedirect()}>
          try again
        </button>
      </>
    ) : (
      <pre id="user_token">{JSON.stringify(authState?.user, null, ' ')}</pre>
    );

  return (
    <div className="App">
      <div className="header">
        <h2>
          Session State: <code id="sessionState">{authState.sessionState}</code>
        </h2>
        <span>&nbsp;</span>
        {SessionInfo}
      </div>
      <div className="body">
        <div className="input">
          {selectedFile ? (
            <div id="details">
              <h2>{selectedFile.name}</h2>
              <div id="contentType">Content Type: {selectedFile.type}</div>
              <div>Last Modified: {new Date(selectedFile.lastModified).toLocaleString()}</div>
              <div>Size: {new Intl.NumberFormat().format(selectedFile.size)} bytes</div>
              <button id="clearFile" onClick={() => setSelectedFile(undefined)} type="button">
                Clear file
              </button>
            </div>
          ) : (
            <>
              <label htmlFor="file-selector">Select file:</label>
              <input type="file" name="file" id="fileSelector" onChange={changeHandler} />
            </>
          )}
        </div>
        {selectedFile && (
          <div className="action">
            <form className="column">
              <h2>Encrypt</h2>
              <div className="card horizontal-flow">
                <button id="encryptButton" onClick={() => handleEncrypt()} type="button">
                  Encrypt
                </button>
              </div>
            </form>
            <form className="column">
              <h2>Decrypt</h2>
              <div className="card horizontal-flow">
                <button id="decryptButton" onClick={() => handleDecrypt()} type="button">
                  decrypt
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
