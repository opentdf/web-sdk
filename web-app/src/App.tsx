import { useState, type ChangeEvent } from 'react';
import './App.css';
import { NanoTDFClient } from '@opentdf/client/nano';

function toHex(a: Uint8Array) {
  return [...a].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function App() {
  const [count, setCount] = useState(0);
  const [isFilePicked, setIsFilePicked] = useState(false);
  const [segments, setSegments] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | undefined>();

  const changeHandler = (event: ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.files?.length) {
      const [file] = target.files;
      setSelectedFile(file);
      setIsFilePicked(true);
      setSegments('');
    }
  };

  const handleSubmission = async () => {
    if (!selectedFile) {
      setSegments('PLEASE SELECT FILE');
      return false;
    }
    setSegments(`[THINKING about ${selectedFile.name}]`);
    const size = selectedFile.size;
    const arrayBuffer = await selectedFile.arrayBuffer();
    const buf = new Uint8Array(arrayBuffer.slice(0, Math.min(32, size)));
    console.log('Success:', buf);
    setSegments(`Starting file bytes: ${toHex(buf)}`);
    return false;
  };

  return (
    <div className="App">
      <header className="App-header">
        {/* <p>client {`${new NanoTDFClient(null, 'http://localhost:65432/api/kas')}`}</p> */}
        <p>
          Page has been open for <code>{count}</code> seconds.
        </p>
      </header>
      <p>Select a file and submit to slice it.</p>
      <div>
        <label htmlFor="file-selector">Select file:</label>
        <input type="file" name="file" id="file-selector" onChange={changeHandler} />
        {selectedFile ? (
          <div id="details">
            <h2>{selectedFile.name}</h2>
            <div>Content Type: {selectedFile.type}</div>
            <div>Last Modified: {new Date(selectedFile.lastModified).toLocaleString()}</div>
            <div>Size: {new Intl.NumberFormat().format(selectedFile.size)} bytes</div>
          </div>
        ) : (
          <p>Select a file to show details</p>
        )}
        {segments.length ? (
          <h3 id="segments">{segments}</h3>
        ) : (
          <div>
            <button id="process" disabled={!isFilePicked} onClick={handleSubmission}>
              Process
            </button>
          </div>
        )}
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button id="clicker" onClick={() => setCount((count) => count + 1)}>
          Click count is {count}
        </button>
      </div>
    </div>
  );
}

export default App;
