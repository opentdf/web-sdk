import { clsx } from 'clsx';
import { useState, useEffect, type ChangeEvent } from 'react';
import streamsaver from 'streamsaver';
import { showSaveFilePicker } from 'native-file-system-adapter';
import './App.css';
import {
  type Chunker,
  type DecoratedStream,
  type KasPublicKeyAlgorithm,
  type KeyAccessType,
  type Manifest,
  type Source,
  OpenTDF,
} from '@opentdf/sdk';
import { type SessionInformation, OidcClient } from './session.js';
import { config } from './config.js';
import {
  actualWrapQualifier,
  algorithmSlug,
  decryptedFileExtension,
  decryptedFileName,
  expectedKaoType,
} from './fileNames.js';

async function toFile(
  stream: ReadableStream<Uint8Array>,
  filepath = 'download.tdf',
  options?: StreamPipeOptions
): Promise<void> {
  const fileStream = streamsaver.createWriteStream(filepath, {
    writableStrategy: { highWaterMark: 1 },
    readableStrategy: { highWaterMark: 1 },
  });

  return stream.pipeTo(fileStream, options);
}

const oidcClient = new OidcClient(config.oidc.host, config.oidc.clientId, 'otdf-sample-web-app');

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
type DecryptReadTuning = {
  segmentBatchSize?: number;
  maxConcurrentSegmentBatches?: number;
};
const MAX_SEGMENT_BATCH_SIZE = 500;
const MAX_CONCURRENT_SEGMENT_BATCHES = 3;

function readPositiveIntSearchParam(params: URLSearchParams, name: string): number | undefined {
  const raw = params.get(name);
  if (!raw) {
    return undefined;
  }
  if (!/^\d+$/.test(raw)) {
    console.warn(`Ignoring invalid ${name} query param: ${raw}`);
    return undefined;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1) {
    console.warn(`Ignoring invalid ${name} query param: ${raw}`);
    return undefined;
  }
  return parsed;
}

function getDecryptReadTuningFromLocation(): DecryptReadTuning {
  const params = new URLSearchParams(window.location.search);
  const parsedSegmentBatchSize = readPositiveIntSearchParam(params, 'segmentBatchSize');
  const parsedMaxConcurrentSegmentBatches = readPositiveIntSearchParam(
    params,
    'maxConcurrentSegmentBatches'
  );
  const segmentBatchSize =
    parsedSegmentBatchSize !== undefined
      ? Math.min(parsedSegmentBatchSize, MAX_SEGMENT_BATCH_SIZE)
      : undefined;
  const maxConcurrentSegmentBatches =
    parsedMaxConcurrentSegmentBatches !== undefined
      ? Math.min(parsedMaxConcurrentSegmentBatches, MAX_CONCURRENT_SEGMENT_BATCHES)
      : undefined;

  return {
    ...(segmentBatchSize !== undefined && { segmentBatchSize }),
    ...(maxConcurrentSegmentBatches !== undefined && { maxConcurrentSegmentBatches }),
  };
}

type KaoMetadata = {
  kid: string;
  type: KeyAccessType;
  url: string;
  protocol: string;
  wrappedKeyBytes: number;
};

function decodedBase64Length(value: string): number {
  const paddingLength = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return Math.floor((value.length * 3) / 4) - paddingLength;
}

function kaoMetadataFrom(manifest: Manifest): KaoMetadata[] {
  return manifest.encryptionInformation.keyAccess.map((kao) => {
    const wrappedKeyBytes = kao.wrappedKey ? decodedBase64Length(kao.wrappedKey) : 0;
    return {
      kid: kao.kid ?? '(no kid)',
      type: kao.type,
      url: kao.url,
      protocol: kao.protocol,
      wrappedKeyBytes,
    } satisfies KaoMetadata;
  });
}

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
  const [downloadState, setDownloadState] = useState<string | undefined>();
  const [inputSource, setInputSource] = useState<InputSource | undefined>();
  const [sinkType, setSinkType] = useState<SinkType>('file');
  const [encapAlgorithm, setEncapAlgorithm] = useState<KasPublicKeyAlgorithm>('ec:secp256r1');
  const [rewrapAlgorithm, setRewrapAlgorithm] = useState<KasPublicKeyAlgorithm>('rsa:2048');
  const [kaoMetadata, setKaoMetadata] = useState<KaoMetadata[] | undefined>();
  // Kept out of downloadState because the progress transformers overwrite that
  // several times a second; a warning parked there would never be read.
  const [algorithmWarning, setAlgorithmWarning] = useState<string | undefined>();
  const [streamController, setStreamController] = useState<CurrentDataController>();

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

  // The output panel describes whatever was last encrypted or decrypted, so any
  // change of source invalidates it. Retire it here rather than in each handler:
  // url and bytes sources have no `Clear file` button to hang the reset off, and
  // an inspector left over from the previous file claims something untrue about
  // the new one.
  const selectInputSource = (next: InputSource | undefined) => {
    setInputSource(next);
    setDownloadState(undefined);
    setKaoMetadata(undefined);
    setAlgorithmWarning(undefined);
  };

  const setFileHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.files?.length) {
      const [file] = target.files;
      selectInputSource({ type: 'file', file });
    } else {
      selectInputSource(undefined);
    }
  };
  const setRandomHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.value && target.validity.valid) {
      selectInputSource({ type: 'bytes', length: parseInt(target.value) });
    } else {
      selectInputSource(undefined);
    }
  };
  const setUrlHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.value && target.validity.valid) {
      selectInputSource({ type: 'url', url: new URL(target.value) });
    } else {
      selectInputSource(undefined);
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
    console.log(`Encrypting [${inputFileName}] as ZTDF to ${sinkType}`);

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

    const client = new OpenTDF({
      authProvider: oidcClient,
      defaultCreateOptions: {
        defaultKASEndpoint: config.kas,
      },
      dpopKeys: oidcClient.getSigningKey(),
    });
    setDownloadState('Encrypting...');
    setKaoMetadata(undefined);
    setAlgorithmWarning(undefined);
    let f: FileSystemFileHandle | undefined;
    // Tag the container with the wrap algorithm so a folder full of demo output
    // says which encapsulation produced which file. This is only the algorithm
    // we asked for: the Save As picker has to open while the click activation is
    // still live, which is before the KAS has told us what it actually used. The
    // download sink corrects the name below; for `fsapi` the user has already
    // named the file, so there we can only warn.
    const requestedName = `${inputFileName}-${algorithmSlug(encapAlgorithm)}.tdf`;
    if (sinkType === 'fsapi') {
      f = await getNewFileHandle('tdf', requestedName);
    }
    const progressTransformers = makeProgressPair(size, 'Encrypt');

    let cipherText: DecoratedStream;
    try {
      cipherText = await client.createZTDF({
        autoconfigure: false,
        source: { type: 'stream', location: source.pipeThrough(progressTransformers.reader) },
        wrappingKeyAlgorithm: encapAlgorithm,
      });
    } catch (e) {
      setDownloadState(`Encrypt Failed: ${e}`);
      console.error('Encrypt Failed', e);
      return;
    }
    // Surface the key access objects we just wrote, so the wrap algorithm choice
    // is visible without having to decrypt first. createZTDF attaches an
    // already-resolved promise, so awaiting it costs a microtask and does not
    // hold up the download.
    let downloadName = requestedName;
    if (!cipherText.manifest) {
      console.error('encrypt produced no manifest; cannot show key access objects');
      setAlgorithmWarning('Encrypted, but the SDK returned no manifest to inspect.');
    } else {
      try {
        const kaos = kaoMetadataFrom(await cipherText.manifest);
        setKaoMetadata(kaos);
        // What we asked for is not necessarily what wrapped the DEK: fetchKasPubKey
        // prefers the platform base key and drops the requested algorithm, and the
        // SDK only console.warns when the two disagree. Name the file after what
        // actually happened rather than letting it assert something untrue.
        const [kao] = kaos;
        if (kao && kao.type !== expectedKaoType(encapAlgorithm)) {
          downloadName = `${inputFileName}${actualWrapQualifier(kao.type, kao.kid)}.tdf`;
          setAlgorithmWarning(
            `Requested ${encapAlgorithm}, but the KAS wrapped with ${kao.type} (kid ${kao.kid}). ` +
              (sinkType === 'fsapi'
                ? 'The name you chose does not reflect this.'
                : `Saved as ${downloadName}.`)
          );
        }
      } catch (e) {
        console.warn('failed to read manifest after encrypt', e);
        setAlgorithmWarning(`Encrypted, but could not read the manifest to inspect it: ${e}`);
      }
    }
    const cipherTextWithProgress = cipherText.pipeThrough(progressTransformers.writer);
    try {
      switch (sinkType) {
        case 'file':
          await toFile(cipherTextWithProgress, downloadName, { signal: sc.signal });
          break;
        case 'fsapi':
          if (!f) {
            throw new Error();
          }
          const writable = await f.createWritable();
          await cipherTextWithProgress.pipeTo(writable, { signal: sc.signal });
          break;
        case 'none':
          await cipherTextWithProgress.pipeTo(drain(), { signal: sc.signal });
          break;
      }
    } catch (e) {
      setDownloadState(`Encrypt Failed: ${e}`);
      console.error('Encrypt Failed', e);
    }
    setStreamController(undefined);
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
    const dfn = decryptedFileName(fileNameFor(inputSource), rewrapAlgorithm);
    console.log(`Decrypting ${JSON.stringify(inputSource)} to ${sinkType} ${dfn}`);
    // Drop anything left over from a previous encrypt or decrypt so the panel
    // always reflects the file we're reading now.
    setKaoMetadata(undefined);
    setAlgorithmWarning(undefined);
    let f: FileSystemFileHandle | undefined;
    if (sinkType === 'fsapi') {
      f = await getNewFileHandle(decryptedFileExtension(fileNameFor(inputSource)), dfn);
    }
    const decryptReadTuning = getDecryptReadTuningFromLocation();
    if (Object.keys(decryptReadTuning).length > 0) {
      console.info(`Using decrypt read tuning ${JSON.stringify(decryptReadTuning)}`);
    }
    const client = new OpenTDF({
      authProvider: oidcClient,
      defaultReadOptions: {
        allowedKASEndpoints: [config.kas],
        wrappingKeyAlgorithm: rewrapAlgorithm,
        ...decryptReadTuning,
      },
      dpopKeys: oidcClient.getSigningKey(),
    });

    let source: Source;
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

    const sc = new AbortController();
    setStreamController(sc);
    // XXX chunker doesn't have an equivalent 'stream' interaface
    // so we kinda fake it with percentages by tracking output, which should
    // strictly be smaller than the input file.
    try {
      const reader = client.open({ source });
      try {
        const manifest = await reader.manifest();
        setKaoMetadata(kaoMetadataFrom(manifest));
      } catch (e) {
        console.warn('failed to read manifest for KAO inspection', e);
        setKaoMetadata(undefined);
      }
      const plainText = await reader.decrypt();
      const plainTextStream = plainText
        .pipeThrough(progressTransformers.reader)
        .pipeThrough(progressTransformers.writer);
      switch (sinkType) {
        case 'file':
          await toFile(plainTextStream, dfn, { signal: sc.signal });
          break;
        case 'fsapi':
          if (!f) {
            throw new Error();
          }
          const writable = await f.createWritable();
          await plainTextStream.pipeTo(writable, { signal: sc.signal });
          break;
        case 'none':
          await plainTextStream.pipeTo(drain(), { signal: sc.signal });
          break;
      }
      const { fqns: requiredObligations } = await reader.obligations();
      console.log(
        `Found required obligations count: ${requiredObligations.length}. ${requiredObligations.length ?? JSON.stringify(requiredObligations)}`
      );
    } catch (e) {
      console.error('Decrypt Failed', e);
      setDownloadState(`Decrypt Failed: ${e}`);
    }
    setStreamController(undefined);
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
        <section className="step">
          <div className="step-body">
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
                  <button id="clearFile" onClick={() => selectInputSource(undefined)} type="button">
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
        </section>

        {streamController && (
          <section className="step">
            <div className="step-body card">
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
          </section>
        )}
        {inputSource && !streamController && (
          <div className="actions">
            {/* Encrypt and decrypt are alternatives rather than sequential steps,
                so they sit side by side when there is room and stack when there
                isn't. Each carries the options that affect it to its right. */}
            <section className="step">
              <h2>Encrypt</h2>
              <div className="step-body card">
                <button id="encryptButton" onClick={() => handleEncrypt()} type="button">
                  Encrypt
                </button>
                <fieldset className="options">
                  <legend>Options</legend>
                  <label htmlFor="encapAlgorithm">Wrap key algorithm</label>{' '}
                  <select
                    id="encapAlgorithm"
                    value={encapAlgorithm}
                    onChange={(e) => setEncapAlgorithm(e.target.value as KasPublicKeyAlgorithm)}
                  >
                    <option value="ec:secp256r1">EC P-256</option>
                    <option value="rsa:2048">RSA-2048</option>
                    <option value="mlkem:768">ML-KEM-768</option>
                    <option value="mlkem:1024">ML-KEM-1024</option>
                  </select>
                </fieldset>
              </div>
            </section>
            <section className="step">
              <h2>Decrypt</h2>
              <div className="step-body card">
                <button id="decryptButton" onClick={() => handleDecrypt()} type="button">
                  decrypt
                </button>
                <fieldset className="options">
                  <legend>Options</legend>
                  <label htmlFor="rewrapAlgorithm">Rewrap key algorithm</label>{' '}
                  <select
                    id="rewrapAlgorithm"
                    value={rewrapAlgorithm}
                    onChange={(e) => setRewrapAlgorithm(e.target.value as KasPublicKeyAlgorithm)}
                  >
                    <option value="ec:secp256r1">EC P-256</option>
                    <option value="rsa:2048">RSA-2048</option>
                    <option value="mlkem:768">ML-KEM-768</option>
                    <option value="mlkem:1024">ML-KEM-1024</option>
                  </select>
                </fieldset>
              </div>
            </section>
          </div>
        )}
        {(!!downloadState || !!kaoMetadata?.length || !!algorithmWarning) && (
          <section className="step">
            <h2>Output</h2>
            <div className="step-body">
              {downloadState && (
                <div id="downloadState" className="status">
                  {downloadState}
                </div>
              )}
              {algorithmWarning && (
                <div id="algorithmWarning" className="status warning" role="alert">
                  ⚠️ {algorithmWarning}
                </div>
              )}
              {kaoMetadata?.length ? (
                <fieldset className="inspector">
                  <legend>Manifest Inspector</legend>
                  {/* Label/value rows rather than a wide table: one key access
                      object is the common case, and this stays readable when the
                      viewport is too narrow for six columns. */}
                  <ol id="kaoMetadata" className="kao-list">
                    {kaoMetadata.map((kao, idx) => (
                      <li key={idx} id={`kao-row-${idx}`} className="kao">
                        <h3>Key access object {idx}</h3>
                        <dl>
                          <dt>kid</dt>
                          <dd id={`kao-kid-${idx}`}>{kao.kid}</dd>
                          <dt>type</dt>
                          <dd id={`kao-type-${idx}`}>{kao.type}</dd>
                          <dt>protocol</dt>
                          <dd id={`kao-protocol-${idx}`}>{kao.protocol}</dd>
                          {/* Unit is in the label so the value stays a bare number. */}
                          <dt>wrappedKey bytes</dt>
                          <dd id={`kao-wrapped-bytes-${idx}`}>{kao.wrappedKeyBytes}</dd>
                          <dt>kas url</dt>
                          <dd id={`kao-url-${idx}`}>{kao.url}</dd>
                        </dl>
                      </li>
                    ))}
                  </ol>
                </fieldset>
              ) : null}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default App;
