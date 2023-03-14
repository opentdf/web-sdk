import { useState, useEffect, type ChangeEvent } from 'react';
import './App.css';
import {
  Client as Tdf3Client,
  type DecryptSource,
  NanoTDFClient,
  AuthProviders,
} from '@opentdf/client';
import { type SessionInformation, OidcClient } from './session.js';

function decryptedFileName(encryptedFileName: string): string {
  // Groups: 1 file 'name' bit
  // 2: original file extension
  // [non-capture group] - match how safari and chrome insert counters before extension.
  //    I'm guessing this has some fascinating internationalizations but for now WFM is enough.
  // 3: TDF container type extension
  const m = encryptedFileName.match(/^(.+)\.(\w+)(?:-\d+| \(\d+\))?\.(ntdf|tdf|tdf\.html)$/);
  console.log(encryptedFileName, m);
  if (!m) {
    console.warn(`Unable to extract raw file name from ${encryptedFileName}`);
    return `${encryptedFileName}.decrypted`;
  }
  return `${m[1]}.decrypted.${m[2]}`;
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
type InputSource = { file: File } | { url: URL } | undefined;

function fileNameFor(inputSource: InputSource) {
  if (!inputSource) {
    return 'undefined.bin';
  }
  if ('file' in inputSource) {
    return inputSource.file.name;
  }
  const { pathname } = inputSource.url;
  const i = pathname.lastIndexOf('/');
  return pathname.slice(i + 1);
}

function App() {
  const [inputSource, setInputSource] = useState<InputSource>();
  const [authState, setAuthState] = useState<SessionInformation>({ sessionState: 'start' });
  const [decryptContainerType, setDecryptContainerType] = useState<Containers>('nano');
  const [encryptContainerType, setEncryptContainerType] = useState<Containers>('nano');

  const handleContainerFormatRadioChange =
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
      setInputSource({ file });
    } else if (target.value && target.validity.valid) {
      setInputSource({ url: new URL(target.value) });
    } else {
      setInputSource(undefined);
    }
  };

  const handleEncrypt = async () => {
    if (!inputSource) {
      console.warn('PLEASE SELECT FILE ∨ URL');
      return false;
    }
    const refreshToken = authState?.user?.refreshToken;
    if (!refreshToken) {
      console.warn('PLEASE LOG IN');
      return false;
    }
    const authProvider = await AuthProviders.refreshAuthProvider({
      exchange: 'refresh',
      clientId: oidcClient.clientId,
      oidcOrigin: oidcClient.host,
      refreshToken,
    });
    const inputFileName = fileNameFor(inputSource);
    console.log(`Encrypting [${inputFileName}] to ${encryptContainerType} container'`);
    switch (encryptContainerType) {
      case 'nano': {
        if (!('file' in inputSource)) {
          throw new Error('Unsupported : fetch the url I guess?');
        }
        const plainText = await inputSource.file.arrayBuffer();
        const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
        const cipherText = await nanoClient.encrypt(plainText);
        saver(new Blob([cipherText]), `${inputFileName}.ntdf`);
        break;
      }
      case 'html': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
          readerUrl: 'https://secure.virtru.com/start?htmlProtocol=1',
        });
        let source;
        if ('file' in inputSource) {
          source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
        } else {
          const fr = await fetch(inputSource.url);
          if (!fr.ok) {
            throw Error(
              `Error on fetch [${inputSource.url}]: ${fr.status} code received; [${fr.statusText}]`
            );
          }
          if (!fr.body) {
            throw Error(
              `Failed to fetch input [${inputSource.url}]: ${fr.status} code received; [${fr.statusText}]`
            );
          }
          source = fr.body;
        }
        try {
          const cipherText = await client.encrypt({
            source,
            offline: true,
            asHtml: true,
          });
          const downloadName = `${inputFileName}.tdf.html`;
          await cipherText.toFile(downloadName);
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
        let source;
        if ('file' in inputSource) {
          source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
        } else {
          const fr = await fetch(inputSource.url);
          if (!fr.ok) {
            throw Error(
              `Error on fetch [${inputSource.url}]: ${fr.status} code received; [${fr.statusText}]`
            );
          }
          if (!fr.body) {
            throw Error(
              `Failed to fetch input [${inputSource.url}]: ${fr.status} code received; [${fr.statusText}]`
            );
          }
          source = fr.body;
        }
        try {
          const cipherText = await client.encrypt({
            source,
            offline: true,
          });
          await cipherText.toFile(`${inputFileName}.tdf`);
        } catch (e) {
          console.error('Encrypt Failed', e);
        }
        break;
      }
    }
    return true;
  };

  const handleDecrypt = async () => {
    if (!inputSource) {
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
    const dfn = decryptedFileName(fileNameFor(inputSource));
    switch (decryptContainerType) {
      case 'tdf': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
        });
        try {
          let source: DecryptSource;
          if ('file' in inputSource) {
            source = { type: 'file-browser', location: inputSource.file };
          } else {
            source = { type: 'remote', location: inputSource.url.toString() };
          }
          const plainText = await client.decrypt({ source });
          await plainText.toFile(dfn);
        } catch (e) {
          console.error('Decrypt Failed', e);
        }
        break;
      }
      case 'nano': {
        if (!('file' in inputSource)) {
          throw new Error('Unsupported : fetch the url I guess?');
        }
        const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
        const plainText = await nanoClient.decrypt(await inputSource.file.arrayBuffer());
        saver(new Blob([plainText]), dfn);
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

  const hasFileInput = inputSource && 'file' in inputSource;
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
          {hasFileInput ? (
            <div id="details">
              <h2>{'file' in inputSource ? inputSource.file.name : inputSource.url.toString()}</h2>
              {'file' in inputSource && (
                <>
                  <div id="contentType">Content Type: {inputSource.file.type}</div>
                  <div>
                    Last Modified: {new Date(inputSource.file.lastModified).toLocaleString()}
                  </div>
                  <div>Size: {new Intl.NumberFormat().format(inputSource.file.size)} bytes</div>
                </>
              )}
              <button id="clearFile" onClick={() => setInputSource(undefined)} type="button">
                Clear file
              </button>
            </div>
          ) : (
            <>
              <label htmlFor="file-selector">Select file:</label>
              <input type="file" name="file" id="fileSelector" onChange={changeHandler} />
              <div>OR URL:</div>
              <input
                type="url"
                name="url"
                id="urlSelector"
                onChange={changeHandler}
                placeholder="http://localhost:8000/sample.tdf"
              />
            </>
          )}
        </div>
        {inputSource && (
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
                    onChange={handleContainerFormatRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'html'}
                  />{' '}
                  <label htmlFor="html">HTML</label>
                  <br />
                  <input
                    type="radio"
                    id="zipEncrypt"
                    name="container"
                    value="tdf"
                    onChange={handleContainerFormatRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'tdf'}
                  />{' '}
                  <label htmlFor="zip">TDF</label>
                  <br />
                  <input
                    type="radio"
                    id="nanoEncrypt"
                    name="container"
                    value="nano"
                    onChange={handleContainerFormatRadioChange(setEncryptContainerType)}
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
                    onChange={handleContainerFormatRadioChange(setDecryptContainerType)}
                    checked={decryptContainerType === 'tdf'}
                  />{' '}
                  <label htmlFor="tdf">TDF</label>
                  <br />
                  <input
                    type="radio"
                    id="nanoDecrypt"
                    name="container"
                    value="nano"
                    onChange={handleContainerFormatRadioChange(setDecryptContainerType)}
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
