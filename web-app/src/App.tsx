import { useState, useEffect, type ChangeEvent } from 'react';
import { showSaveFilePicker } from 'native-file-system-adapter';
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

async function getNewFileHandle(
  extension: string,
  suggestedName: string
): Promise<FileSystemFileHandle> {
  const options = {
    types: [
      {
        description: `${extension} files`,
        accept: {
          'application/octet-stream': [`.${extension}`],
        },
      },
    ],
    suggestedName,
  };
  return showSaveFilePicker(options);
}

type Containers = 'html' | 'tdf' | 'nano';
type CurrentDataController = AbortController | undefined;
type InputSource = { file: File } | { url: URL } | undefined;
type SinkType = 'file' | 'fsapi' | 'none';

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

function drain() {
  let byteCounter = 0;
  let startTime: number;
  let lastLogTime = 0;
  return new WritableStream({
    start() {
      startTime = Date.now();
    },
    write(chunk) {
      byteCounter += chunk.byteLength;
      const now = Date.now();
      if (now - lastLogTime > 1000) {
        console.log(
          `Dumped ${chunk.byteLength.toLocaleString()} of ${byteCounter.toLocaleString()}`
        );
        lastLogTime = now;
      }
    },
    close() {
      const elapsedSeconds = (Date.now() - startTime) / 1000;
      console.log(
        `Closed after ${byteCounter.toLocaleString()} bytes after ${elapsedSeconds.toLocaleString()} seconds`
      );
    },
  });
}

function App() {
  const [authState, setAuthState] = useState<SessionInformation>({ sessionState: 'start' });
  const [decryptContainerType, setDecryptContainerType] = useState<Containers>('tdf');
  const [downloadState, setDownloadState] = useState<string | undefined>();
  const [encryptContainerType, setEncryptContainerType] = useState<Containers>('tdf');
  const [inputSource, setInputSource] = useState<InputSource>();
  const [sinkType, setSinkType] = useState<SinkType>('file');
  const [streamController, setStreamController] = useState<CurrentDataController>();

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

  const makeProgressPair = (fileSize: number, type: 'Encrypt' | 'Decrypt') => {
    let bytesRead = 0;
    let lastLoggedRead = -1;
    let lastLoggedWritten = -1;
    let bytesWritten = 0;
    const logEveryBytes = fileSize && fileSize > 100 ? fileSize / 100 : 1000 * 1000 * 16;
    return {
      reader: new TransformStream({
        async transform(chunk, controller) {
          bytesRead += chunk.length;
          const message = `🤓 Processed ${Math.round(
            100 * (bytesRead / fileSize)
          )}% input bytes (${bytesRead} / ${fileSize})`;
          if (bytesRead - lastLoggedRead > logEveryBytes) {
            console.log(message);
            lastLoggedRead = bytesRead;
          }
          controller.enqueue(chunk);
          setDownloadState(message);
        },
        flush() {
          // NOTE AFAICT this is never called?
          // What is the contract here? I'm guessing if the input and output queues
          // are both empty this is not invoked? But how can the controller track state?
          // For example, imagine a 'wait one tick' transform, which always outputs
          // the previous transform input, but stores in an inner buffer?
          setDownloadState(`🤓 ${type} Complete`);
        },
      }),
      writer: new TransformStream({
        async transform(chunk, controller) {
          bytesWritten += chunk.length;
          if (bytesWritten - lastLoggedWritten > logEveryBytes) {
            console.log(`✍️ Processed output bytes: ${bytesWritten}`);
            lastLoggedWritten = bytesWritten;
          }
          controller.enqueue(chunk);
        },
        flush() {
          setDownloadState(`✍️ ${type} Complete`);
        },
      }),
    };
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
    const inputFileName = fileNameFor(inputSource);
    console.log(`Encrypting [${inputFileName}] as ${encryptContainerType} to ${sinkType}`);
    const authProvider = await AuthProviders.refreshAuthProvider({
      exchange: 'refresh',
      clientId: oidcClient.clientId,
      oidcOrigin: oidcClient.host,
      refreshToken,
    });
    switch (encryptContainerType) {
      case 'random': {
        // TODO generate random text of a given requested size in bytes (exponential slider)
        // TODO and type, e.g. 'html', 'uniform', 'textish'
      }
      break;
      case 'nano': {
        if (!('file' in inputSource)) {
          throw new Error('Unsupported : fetch the url I guess?');
        }
        const plainText = await inputSource.file.arrayBuffer();
        const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
        setDownloadState('Encrypting...');
        switch (sinkType) {
          case 'file':
            {
              const cipherText = await nanoClient.encrypt(plainText);
              saver(new Blob([cipherText]), `${inputFileName}.ntdf`);
            }
            break;
          case 'fsapi':
            {
              const file = await getNewFileHandle('ntdf', `${inputFileName}.ntdf`);
              const cipherText = await nanoClient.encrypt(plainText);
              const writable = await file.createWritable();
              try {
                await writable.write(cipherText);
                setDownloadState('Encrypt Complete');
              } catch (e) {
                setDownloadState(`Encrypt Failed: ${e}`);
              } finally {
                await writable.close();
              }
            }
            break;
          case 'none':
            break;
        }
        break;
      }
      case 'html': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
          readerUrl: 'https://secure.virtru.com/start?htmlProtocol=1',
        });
        let source: ReadableStream<Uint8Array>, size: number;
        const sc = new AbortController();
        setStreamController(sc);
        if ('file' in inputSource) {
          size = inputSource.file.size;
          source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
        } else {
          // NOTE: Attaching the signal to the pipeline (in pipeTo, below)
          // is insufficient (at least in Chrome) to abort the fetch itself.
          // So aborting a sink in a pipeline does *NOT* cancel its sources
          const fr = await fetch(inputSource.url, { signal: sc.signal });
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
          size = parseInt(fr.headers.get('Content-Length') || '-1');
          source = fr.body;
        }
        try {
          const downloadName = `${inputFileName}.tdf.html`;
          let f;
          if (sinkType == 'fsapi') {
            f = await getNewFileHandle('html', downloadName);
          }
          const progressTransformers = makeProgressPair(size, 'Encrypt');
          const cipherText = await client.encrypt({
            source: source.pipeThrough(progressTransformers.reader),
            offline: true,
            asHtml: true,
          });
          cipherText.stream = cipherText.stream.pipeThrough(progressTransformers.writer);
          switch (sinkType) {
            case 'file':
              await cipherText.toFile(downloadName, { signal: sc.signal });
              break;
            case 'fsapi':
              if (!f) {
                throw new Error();
              }
              const writable = await f.createWritable();
              await cipherText.stream.pipeTo(writable, { signal: sc.signal });
              break;
            case 'none':
              await cipherText.stream.pipeTo(drain(), { signal: sc.signal });
              break;
          }
        } catch (e) {
          setDownloadState(`Encrypt Failed: ${e}`);
          console.error('Encrypt Failed', e);
        }
        setStreamController(undefined);
        break;
      }
      case 'tdf': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
        });
        const sc = new AbortController();
        setStreamController(sc);
        let source: ReadableStream<Uint8Array>, size: number;
        if ('file' in inputSource) {
          size = inputSource.file.size;
          source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
        } else {
          const fr = await fetch(inputSource.url, { signal: sc.signal });
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
          size = parseInt(fr.headers.get('Content-Length') || '-1');
          source = fr.body;
        }
        try {
          let f;
          const downloadName = `${inputFileName}.tdf`;
          if (sinkType === 'fsapi') {
            f = await getNewFileHandle('tdf', downloadName);
          }
          const progressTransformers = makeProgressPair(size, 'Encrypt');
          const cipherText = await client.encrypt({
            source: source.pipeThrough(progressTransformers.reader),
            offline: true,
          });
          cipherText.stream = cipherText.stream.pipeThrough(progressTransformers.writer);
          switch (sinkType) {
            case 'file':
              await cipherText.toFile(downloadName, { signal: sc.signal });
              break;
            case 'fsapi':
              if (!f) {
                throw new Error();
              }
              const writable = await f.createWritable();
              await cipherText.stream.pipeTo(writable, { signal: sc.signal });
              break;
            case 'none':
              await cipherText.stream.pipeTo(drain(), { signal: sc.signal });
              break;
          }
        } catch (e) {
          setDownloadState(`Encrypt Failed: ${e}`);
          console.error('Encrypt Failed', e);
        }
        setStreamController(undefined);
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
    const dfn = decryptedFileName(fileNameFor(inputSource));
    console.log(
      `Decrypting ${decryptContainerType} ${JSON.stringify(inputSource)} to ${sinkType} ${dfn}`
    );
    const authProvider = await AuthProviders.refreshAuthProvider({
      exchange: 'refresh',
      clientId: oidcClient.clientId,
      oidcOrigin: oidcClient.host,
      refreshToken: authState.user.refreshToken,
    });
    let f;
    if (sinkType === 'fsapi') {
      f = await getNewFileHandle(decryptedFileExtension(fileNameFor(inputSource)), dfn);
    }
    switch (decryptContainerType) {
      case 'tdf': {
        const client = new Tdf3Client.Client({
          authProvider,
          kasEndpoint: 'http://localhost:65432/api/kas',
        });
        try {
          const sc = new AbortController();
          setStreamController(sc);
          let source: DecryptSource;
          let size: number;
          if ('file' in inputSource) {
            size = inputSource.file.size;
            source = { type: 'file-browser', location: inputSource.file };
          } else {
            const hr = await fetch(inputSource.url, { method: 'HEAD' });
            size = parseInt(hr.headers.get('Content-Length') || '-1');
            source = { type: 'remote', location: inputSource.url.toString() };
          }
          const progressTransformers = makeProgressPair(size, 'Decrypt');
          // XXX chunker doesn't have an equivalent 'stream' interaface
          // so we kinda fake it with percentages by tracking output, which should
          // strictly be smaller than the input file.
          const plainText = await client.decrypt({ source });
          plainText.stream = plainText.stream
            .pipeThrough(progressTransformers.reader)
            .pipeThrough(progressTransformers.writer);
          switch (sinkType) {
            case 'file':
              await plainText.toFile(dfn, { signal: sc.signal });
              break;
            case 'fsapi':
              if (!f) {
                throw new Error();
              }
              const writable = await f.createWritable();
              await plainText.stream.pipeTo(writable, { signal: sc.signal });
              break;
            case 'none':
              await plainText.stream.pipeTo(drain(), { signal: sc.signal });
              break;
          }
        } catch (e) {
          console.error('Decrypt Failed', e);
          setDownloadState(`Decrypt Failed: ${e}`);
        }
        setStreamController(undefined);
        break;
      }
      case 'nano': {
        if (!('file' in inputSource)) {
          throw new Error('Unsupported : fetch the url I guess?');
        }
        const nanoClient = new NanoTDFClient(authProvider, 'http://localhost:65432/api/kas');
        try {
          const plainText = await nanoClient.decrypt(await inputSource.file.arrayBuffer());
          switch (sinkType) {
            case 'file':
              saver(new Blob([plainText]), dfn);
              break;
            case 'fsapi':
              if (!f) {
                throw new Error();
              }
              const writable = await f.createWritable();
              try {
                await writable.write(plainText);
                setDownloadState('Decrypt Complete');
              } finally {
                await writable.close();
              }
              break;
            case 'none':
              break;
          }
        } catch (e) {
          console.error('Decrypt Failed', e);
          setDownloadState(`Decrypt Failed: ${e}`);
        }
        break;
      }
    }
    return false;
  };

  const handleScan = async () => {
    const searchTerm = 'service workers';
    // Chars to show either side of the result in the match
    const contextBefore = 30;
    const contextAfter = 30;
    const caseInsensitive = true;

    if (!inputSource) {
      console.warn('PLEASE SELECT FILE ∨ URL');
      return false;
    }
    let source;
    if ('file' in inputSource) {
      source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
    } else {
      const sc = new AbortController();
      setStreamController(sc);
      const fr = await fetch(inputSource.url, { cache: 'no-store', signal: sc.signal });
      console.log(`Received headers ${fr.headers}`);
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
    const reader = source.getReader();

    const decoder = new TextDecoder();
    const toMatch = caseInsensitive ? searchTerm.toLowerCase() : searchTerm;
    const bufferSize = Math.max(toMatch.length - 1, contextBefore);

    let bytesReceived = 0;
    let buffer = '';
    let matchFoundAt = -1;

    while (true) {
      const { value: chunk, done } = await reader.read();
      if (done) {
        console.log('Failed to find match');
        return;
      }
      bytesReceived += chunk.length;
      console.log(`Received ${bytesReceived.toLocaleString()} bytes of data so far`);
      buffer += decoder.decode(chunk, { stream: true });

      // already found match & just context-gathering?
      if (matchFoundAt === -1) {
        matchFoundAt = (caseInsensitive ? buffer.toLowerCase() : buffer).indexOf(toMatch);
      }

      if (matchFoundAt === -1) {
        buffer = buffer.slice(-bufferSize);
      } else if (buffer.slice(matchFoundAt + toMatch.length).length >= contextAfter) {
        console.log("Here's the match:");
        console.log(
          buffer.slice(
            Math.max(0, matchFoundAt - contextBefore),
            matchFoundAt + toMatch.length + contextAfter
          )
        );
        console.log('Cancelling fetch');
        reader.cancel();
        return;
      } else {
        console.log('Found match, but need more context…');
      }
    }
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
        <div className="config horizontal-flow">
          <fieldset className="input">
            <legend>Source</legend>
            {hasFileInput ? (
              <div id="details">
                <h2>
                  {'file' in inputSource ? inputSource.file.name : inputSource.url.toString()}
                </h2>
                {'file' in inputSource && (
                  <>
                    <div id="contentType">Content Type: {inputSource.file.type}</div>
                    <div>
                      Last Modified: {new Date(inputSource.file.lastModified).toLocaleString()}
                    </div>
                    <div>Size: {new Intl.NumberFormat().format(inputSource.file.size)} bytes</div>
                  </>
                )}
                <button
                  id="clearFile"
                  onClick={() => {
                    setInputSource(undefined);
                    setDownloadState(undefined);
                  }}
                  type="button"
                >
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
          </fieldset>

          <fieldset className="Output">
            <legend>Sink</legend>
            <div>
              <input
                type="radio"
                id="fileSink"
                name="sinkType"
                value="file"
                onChange={(e) => setSinkType(e.target.value as SinkType)}
                checked={sinkType === 'file'}
              />{' '}
              <label htmlFor="fileSink">Download</label>
              <br />
              <input
                type="radio"
                id="fsapiSink"
                name="sinkType"
                value="fsapi"
                onChange={(e) => setSinkType(e.target.value as SinkType)}
                checked={sinkType === 'fsapi'}
              />{' '}
              <label htmlFor="fsapiSink">Save As</label>
              <br />
              <input
                type="radio"
                id="noneSink"
                name="sinkType"
                value="none"
                onChange={(e) => setSinkType(e.target.value as SinkType)}
                checked={sinkType === 'none'}
              />{' '}
              <label htmlFor="noneSink">Dump</label>
            </div>
          </fieldset>
        </div>

        {streamController && (
          <div className="action">
            <button
              id="cancelStream"
              onClick={async () => {
                console.log(`Cancelling !!!!`);
                const p = streamController.abort();
                setStreamController(undefined);
                await p;
              }}
              type="button"
            >
              CANCEL
            </button>
          </div>
        )}
        {inputSource && !streamController && (
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
                  <label htmlFor="htmlEncrypt">HTML</label>
                  <br />
                  <input
                    type="radio"
                    id="zipEncrypt"
                    name="container"
                    value="tdf"
                    onChange={handleContainerFormatRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'tdf'}
                  />{' '}
                  <label htmlFor="zipEncrypt">TDF</label>
                  <br />
                  <input
                    type="radio"
                    id="nanoEncrypt"
                    name="container"
                    value="nano"
                    onChange={handleContainerFormatRadioChange(setEncryptContainerType)}
                    checked={encryptContainerType === 'nano'}
                  />{' '}
                  <label htmlFor="nanoEncrypt">nano</label>
                </div>
                <button id="encryptButton" onClick={() => handleEncrypt()} type="button">
                  Encrypt
                </button>
                <button id="scanButton" onClick={() => handleScan()} type="button">
                  DEMO
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
                  <label htmlFor="tdfDecrypt">TDF</label>
                  <br />
                  <input
                    type="radio"
                    id="nanoDecrypt"
                    name="container"
                    value="nano"
                    onChange={handleContainerFormatRadioChange(setDecryptContainerType)}
                    checked={decryptContainerType === 'nano'}
                  />{' '}
                  <label htmlFor="nanoDecrypt">nano</label>
                </div>
                <button id="decryptButton" onClick={() => handleDecrypt()} type="button">
                  decrypt
                </button>
              </div>
            </form>
            {downloadState && <div id="downloadState">{downloadState}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
