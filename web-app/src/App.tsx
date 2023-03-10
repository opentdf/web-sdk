import { useState, useEffect, type ChangeEvent } from 'react';
import './App.css';
import { Client as Tdf3Client, NanoTDFClient, AuthProviders } from '@opentdf/client';
import { type SessionInformation, OidcClient } from './session.js';

function decryptedFileName(encryptedFileName: string): string {
  const m = encryptedFileName.match(/^(.+)\.(\w+)\.(ntdf|tdf|tdf\.html)$/);
  if (!m) {
    console.warn(`Unable to extract raw file name from ${encryptedFileName}`);
    return `${encryptedFileName}.decrypted`;
  }
  return `${m[1]}.decrypted.${m[2]}`;
}

function decryptedFileExtension(encryptedFileName: string): string {
  const m = encryptedFileName.match(/^(.+)\.(\w+)\.(ntdf|tdf|tdf\.html)$/);
  if (!m) {
    console.warn(`Unable to extract raw file name from ${encryptedFileName}`);
    return `${encryptedFileName}.decrypted`;
  }
  return m[2];
}

const oidcClient = new OidcClient(
  'http://localhost:65432/auth/realms/tdf',
  'browsertest',
  'otdf-sample-web-app'
);

function saver(blob: Blob, name: string) {
  const a = document.createElement('a');
  a.download = name;
  a.rel = 'noopener';
  a.href = URL.createObjectURL(blob);
  setTimeout(function () {
    URL.revokeObjectURL(a.href);
  }, 4e4); // 40s
  a.dispatchEvent(new MouseEvent('click'));
}

type Containers = 'html' | 'tdf' | 'nano';

function App() {
  const [selectedFile, setSelectedFile] = useState<File | undefined>();
  const [authState, setAuthState] = useState<SessionInformation>({ sessionState: 'start' });
  const [decryptContainerType, setDecryptContainerType] = useState<Containers>('nano');
  const [encryptContainerType, setEncryptContainerType] = useState<Containers>('nano');
  const [downloadState, setDownloadState] = useState<string | undefined>();

  const handleRadioChange =
    (handler: typeof setDecryptContainerType) => (e: ChangeEvent<HTMLInputElement>) => {
      handler(e.target.value as Containers);
    };

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

  const makeProgressPair = (fileSize: number, type: 'Encrypt' | 'Decrypt') => {
    let bytesRead = 0;
    let bytesWritten = 0;
    return {
      reader: new TransformStream({
        async transform(chunk, controller) {
          bytesRead += chunk.length;
          const message = `Processed ${Math.round(
            100 * (bytesRead / fileSize)
          )}% input bytes (${bytesRead} / ${fileSize})`;
          console.log(message);
          controller.enqueue(chunk);
          setDownloadState(message);
        },
      }),
      writer: new TransformStream({
        async transform(chunk, controller) {
          bytesWritten += chunk.length;
          console.log(`Processed output bytes: ${bytesWritten}`);
          controller.enqueue(chunk);
        },
        flush() {
          setDownloadState(`${type} Complete`);
        },
      }),
    };
  };

  const handleEncrypt = async () => {
    if (!selectedFile) {
      console.warn('PLEASE SELECT FILE');
      return true;
    }
    const refreshToken = authState?.user?.refreshToken;
    if (!refreshToken) {
      console.warn('PLEASE LOG IN');
      return true;
    }
    console.info(`[THINKING about ${selectedFile.name}]`);
    const authProvider = await AuthProviders.refreshAuthProvider({
      exchange: 'refresh',
      clientId: oidcClient.clientId,
      oidcOrigin: oidcClient.host,
      refreshToken,
    });
    switch (encryptContainerType) {
      case 'nano': {
        const plainText = await selectedFile.arrayBuffer();
        const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
        console.log('allocated client', nanoClient);
        const cipherText = await nanoClient.encrypt(plainText);
        saver(new Blob([cipherText]), `${selectedFile.name}.ntdf`);
        break;
      }
      case 'html': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
          readerUrl: 'https://secure.virtru.com/start?htmlProtocol=1',
        });
        const source = selectedFile.stream() as unknown as ReadableStream<Uint8Array>;
        try {
          console.log('Encrypting with html');
          const cipherText = await client.encrypt({
            source,
            offline: true,
            asHtml: true,
          });
          console.log('Encrypt method complete');
          const downloadName = `${selectedFile.name}.tdf.html`;
          await cipherText.toFile(downloadName);
          console.log(`Encrypt toFile complete ${downloadName}`);
        } catch (e) {
          console.error('Encrypt Failed', e);
        }
        break;
      }
      case 'tdf': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
        });
        const source = selectedFile.stream() as unknown as ReadableStream<Uint8Array>;
        try {
          const cipherText = await client.encrypt({
            source,
            offline: true,
          });
          await cipherText.toFile(`${selectedFile.name}.tdf`);
        } catch (e) {
          console.error('Encrypt Failed', e);
        }
        break;
      }
    }
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
      refreshToken: authState.user.refreshToken,
    });
    switch (decryptContainerType) {
      case 'tdf': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
        });
        try {
          const plainText = await client.decrypt({
            source: { type: 'file-browser', location: selectedFile },
          });
          await plainText.toFile(decryptedFileName(selectedFile.name));
        } catch (e) {
          console.error('Decrypt Failed', e);
        }
        break;
      }
      case 'nano': {
        const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
        const plainText = await nanoClient.decrypt(await selectedFile.arrayBuffer());
        saver(new Blob([plainText]), decryptedFileName(selectedFile.name));
        break;
      }
    }
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
                <div>
                  <input
                    type="radio"
                    id="htmlEncrypt"
                    name="container"
                    value="html"
                    onChange={handleRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'html'}
                  />{' '}
                  <label htmlFor="html">HTML</label>
                  <br />
                  <input
                    type="radio"
                    id="zipEncrypt"
                    name="container"
                    value="tdf"
                    onChange={handleRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'tdf'}
                  />{' '}
                  <label htmlFor="zip">TDF</label>
                  <br />
                  <input
                    type="radio"
                    id="nanoEncrypt"
                    name="container"
                    value="nano"
                    onChange={handleRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'nano'}
                  />{' '}
                  <label htmlFor="nano">nano</label>
                </div>
                <button id="encryptButton" onClick={() => handleEncrypt()} type="button">
                  Encrypt
                </button>
              </div>
            </form>
            <form className="column">
              <h2>Decrypt</h2>
              <div className="card horizontal-flow">
                <div>
                  <input
                    type="radio"
                    id="tdfDecrypt"
                    name="container"
                    value="tdf"
                    onChange={handleRadioChange(setDecryptContainerType)}
                    checked={decryptContainerType === 'tdf'}
                  />{' '}
                  <label htmlFor="tdf">TDF</label>
                  <br />
                  <input
                    type="radio"
                    id="nanoDecrypt"
                    name="container"
                    value="nano"
                    onChange={handleRadioChange(setDecryptContainerType)}
                    checked={decryptContainerType === 'nano'}
                  />{' '}
                  <label htmlFor="nano">nano</label>
                </div>
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
