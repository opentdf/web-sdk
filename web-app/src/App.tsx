import { clsx } from 'clsx';
import { useState, useEffect, type ChangeEvent } from 'react';
import { showSaveFilePicker } from 'native-file-system-adapter';
import './App.css';
import { type Chunker, type DecryptSource, NanoTDFClient, TDF3Client } from '@opentdf/sdk';
import { type SessionInformation, OidcClient } from './session.js';
import { c } from './config.js';

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

const oidcClient = new OidcClient(c.oidc.host, c.oidc.clientId, 'otdf-sample-web-app');

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
  //@ts-expect-error //TS2739: not a complete file picker interface
  return showSaveFilePicker(options);
}

type Containers = 'html' | 'tdf' | 'nano';
type CurrentDataController = AbortController | undefined;
type FileInputSource = {
  type: 'file';
  file: File;
};
type UrlInputSource = {
  type: 'url';
  url: URL;
};

type RandomInputSource = {
  type: 'bytes';
  length: number;
};

type InputSource = FileInputSource | UrlInputSource | RandomInputSource;
type SinkType = 'file' | 'fsapi' | 'none';

function fileNameFor(inputSource: InputSource) {
  if (!inputSource) {
    return 'undefined.bin';
  }
  if ('file' in inputSource) {
    return inputSource.file.name;
  }
  if ('length' in inputSource) {
    return `random-${inputSource.type}-${inputSource.length}-bytes`;
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

function randomStream({ length }: RandomInputSource): ReadableStream<Uint8Array> {
  let counter = 0;
  const maxChunkSize = 65536;
  return new ReadableStream({
    async pull(controller) {
      const nextChunkSize = Math.min(length - counter, maxChunkSize);
      if (nextChunkSize <= 0) {
        controller.close();
        return;
      }
      const value = new Uint8Array(nextChunkSize);
      crypto.getRandomValues(value);
      controller.enqueue(value);
      counter += nextChunkSize;
    },
  });
}
function randomArrayBuffer({ length }: RandomInputSource): ArrayBuffer {
  const maxSize = 16 * 2 ** 20;
  if (length >= maxSize || length < 0) {
    throw new Error(`Invalid size for random buffer: [${length}]`);
  }
  const maxChunkSize = 65536;
  const value = new Uint8Array(length);
  for (let i = 0; i < length; i += maxChunkSize) {
    crypto.getRandomValues(value.slice(i, i + maxChunkSize));
  }
  return value;
}

function randomChunker({ length }: RandomInputSource): Chunker {
  const maxChunkSize = 2 ** 20;
  return async (byteStart?: number, byteEnd?: number) => {
    if (!byteStart) {
      byteStart = 0;
    } else if (byteStart < 0) {
      byteStart = length + byteStart;
    }
    if (!byteEnd) {
      byteEnd = length;
    } else if (byteEnd < 0) {
      byteEnd = length + byteEnd;
    }
    if (byteEnd > Number.MAX_SAFE_INTEGER) {
      throw new Error();
    }
    if (byteEnd - byteStart > maxChunkSize) {
      throw new Error();
    }
    const width = byteEnd - byteStart;
    const value = new Uint8Array(width);
    if (width < 0) {
      throw new Error();
    }
    if (!width) {
      return value;
    }
    // TODO use a seedable PRNG to make this make sense.
    crypto.getRandomValues(value);
    return value;
  };
}

function humanReadableDurationEstimate(ms: number) {
  if (ms < 1000 * 1.5) {
    return `${ms} ms`;
  }
  if (ms < 60_000 * 1.5) {
    return `${(ms / 1_000).toFixed(1)} s`;
  }
  if (ms < 3_600_000 * 1.5) {
    return `${(ms / 60_000).toFixed(1)} m`;
  }
  if (ms < 86_400_000 * 1.5) {
    return `${(ms / 3_600_000).toFixed(1)} h`;
  }
  return `${(ms / 86_400_000).toFixed(1)} d`;
}

function App() {
  const [authState, setAuthState] = useState<SessionInformation>({ sessionState: 'start' });
  const [decryptContainerType, setDecryptContainerType] = useState<Containers>('tdf');
  const [downloadState, setDownloadState] = useState<string | undefined>();
  const [encryptContainerType, setEncryptContainerType] = useState<Containers>('tdf');
  const [inputSource, setInputSource] = useState<InputSource | undefined>();
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

  const setFileHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.files?.length) {
      const [file] = target.files;
      setInputSource({ type: 'file', file });
    } else {
      setInputSource(undefined);
    }
  };
  const setRandomHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.value && target.validity.valid) {
      setInputSource({ type: 'bytes', length: parseInt(target.value) });
    } else {
      setInputSource(undefined);
    }
  };
  const setUrlHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.value && target.validity.valid) {
      setInputSource({ type: 'url', url: new URL(target.value) });
    } else {
      setInputSource(undefined);
    }
  };

  const makeProgressPair = (fileSize: number, type: 'Encrypt' | 'Decrypt') => {
    let bytesRead = 0;
    let lastLoggedRead = -1;
    let lastLoggedWritten = -1;
    let bytesWritten = 0;
    let startTime = Date.now();
    const logEveryBytes = fileSize && fileSize > 100 ? fileSize / 100 : 1000 * 1000 * 16;
    return {
      reader: new TransformStream({
        start() {
          const n = Date.now();
          const d = n - startTime;
          if (d > 1000) {
            console.log(`Started ${d.toLocaleString()} milliseconds after initialized`);
          }
          startTime = n;
        },
        async transform(chunk, controller) {
          bytesRead += chunk.length;
          const message = `🤓 ${type}ed ${Math.round(
            100 * (bytesRead / fileSize)
          )}% input bytes (${bytesRead.toLocaleString()} / ${fileSize.toLocaleString()})`;
          if (bytesRead - lastLoggedRead > logEveryBytes) {
            const d = Date.now() - startTime;
            const totalTimeEstimate = (d * fileSize) / bytesRead;
            const timeRemainingEstimate = totalTimeEstimate - d;
            console.log(
              `${message}, about ${humanReadableDurationEstimate(
                timeRemainingEstimate
              )} remaining of ${totalTimeEstimate.toLocaleString()}ms`
            );
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
            console.log(`✍️ ${type}ed output bytes: ${bytesWritten.toLocaleString()}`);
            lastLoggedWritten = bytesWritten;
          }
          controller.enqueue(chunk);
        },
        flush() {
          const d = Date.now() - startTime;
          console.log(`✍️ ${type} Complete after ${d.toLocaleString()} milliseconds`);
          setDownloadState(`✍️ ${type} Complete`);
        },
      }),
    };
  };

  const handleEncrypt = async () => {
    if (!inputSource) {
      console.warn('No input source selected');
      return false;
    }
    const refreshToken = authState?.user?.refreshToken;
    if (!refreshToken) {
      console.warn('PLEASE LOG IN');
      return false;
    }
    const inputFileName = fileNameFor(inputSource);
    console.log(`Encrypting [${inputFileName}] as ${encryptContainerType} to ${sinkType}`);
    switch (encryptContainerType) {
      case 'nano': {
        if ('url' in inputSource) {
          throw new Error('Unsupported : fetch the url I guess?');
        }
        const plainText =
          'file' in inputSource
            ? await inputSource.file.arrayBuffer()
            : randomArrayBuffer(inputSource);
        const nanoClient = new NanoTDFClient({
          authProvider: oidcClient,
          kasEndpoint: c.kas,
          dpopKeys: oidcClient.getSigningKey(),
        });
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
        const client = new TDF3Client({
          authProvider: oidcClient,
          dpopKeys: oidcClient.getSigningKey(),
          kasEndpoint: c.kas,
          readerUrl: c.reader,
        });
        let source: ReadableStream<Uint8Array>, size: number;
        const sc = new AbortController();
        setStreamController(sc);
        switch (inputSource.type) {
          case 'file':
            size = inputSource.file.size;
            source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
            break;
          case 'bytes':
            size = inputSource.length;
            source = randomStream(inputSource);
            break;
          case 'url':
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
            break;
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
        const client = new TDF3Client({
          authProvider: oidcClient,
          dpopKeys: oidcClient.getSigningKey(),
          kasEndpoint: c.kas,
        });
        const sc = new AbortController();
        setStreamController(sc);
        let source: ReadableStream<Uint8Array>, size: number;
        switch (inputSource.type) {
          case 'file':
            size = inputSource.file.size;
            source = inputSource.file.stream() as unknown as ReadableStream<Uint8Array>;
            break;
          case 'bytes':
            size = inputSource.length;
            source = randomStream(inputSource);
            break;
          case 'url':
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
            break;
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
    let f;
    if (sinkType === 'fsapi') {
      f = await getNewFileHandle(decryptedFileExtension(fileNameFor(inputSource)), dfn);
    }
    switch (decryptContainerType) {
      case 'tdf': {
        const client = new TDF3Client({
          authProvider: oidcClient,
          dpopKeys: oidcClient.getSigningKey(),
          kasEndpoint: c.kas,
        });
        try {
          const sc = new AbortController();
          setStreamController(sc);
          let source: DecryptSource;
          let size: number;
          switch (inputSource.type) {
            case 'file':
              size = inputSource.file.size;
              source = { type: 'file-browser', location: inputSource.file };
              break;
            case 'bytes':
              size = inputSource.length;
              source = { type: 'chunker', location: randomChunker(inputSource) };
              break;
            case 'url':
              const hr = await fetch(inputSource.url, { method: 'HEAD' });
              size = parseInt(hr.headers.get('Content-Length') || '-1');
              source = { type: 'remote', location: inputSource.url.toString() };
              break;
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
        if ('url' in inputSource) {
          throw new Error('Unsupported : fetch the url I guess?');
        }
        const nanoClient = new NanoTDFClient({
          authProvider: oidcClient,
          kasEndpoint: c.kas,
          dpopKeys: oidcClient.getSigningKey(),
        });
        try {
          const cipherText =
            'file' in inputSource
              ? await inputSource.file.arrayBuffer()
              : randomArrayBuffer(inputSource);
          const plainText = await nanoClient.decrypt(cipherText);
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
                <h2>{'file' in inputSource ? inputSource.file.name : '[rand]'}</h2>
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
                <label htmlFor="fileSelector">Select file:</label>
                <input type="file" name="file" id="fileSelector" onChange={setFileHandler} />
                <div>OR</div>
                <div className={clsx({ selected: inputSource && 'url' in inputSource })}>
                  <label htmlFor="urlSelector">Load from URL:</label>
                  <input
                    id="urlSelector"
                    name="url"
                    onChange={setUrlHandler}
                    placeholder="http://localhost:8000/sample.tdf"
                    type="url"
                  />
                </div>
                <div>OR:</div>
                <div className={clsx({ selected: inputSource && 'length' in inputSource })}>
                  <label htmlFor="randomSelector">Random Bytes:</label>
                  <input
                    id="randomSelector"
                    name="randomSelector"
                    min="0"
                    max={2 ** 34}
                    onChange={setRandomHandler}
                    placeholder={`${2 ** 20} bytes`}
                    type="number"
                  />
                </div>
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
