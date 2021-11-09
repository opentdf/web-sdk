import React, { useState, useEffect } from 'react';
import './App.css';

import { NanoTDFClient } from '@opentdf/client';

function toHex(a: Uint8Array) {
  return [...a].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function App() {
  const [selectedFile, setSelectedFile] = useState<File | undefined>();
  const [isFilePicked, setIsFilePicked] = useState(false);
  const [segments, setSegments] = useState('');

  const changeHandler = (event: React.ChangeEvent<HTMLInputElement>) => {
    const target = event.target as HTMLInputElement;
    if (target.files?.length) {
      const [file] = target.files;
      setSelectedFile(file);
      setIsFilePicked(true);
    }
  };

  const handleSubmission = async () => {
    if (!selectedFile) {
      return false;
    }
    setSegments('[THINKING]');
    const arrayBuffer = await selectedFile.arrayBuffer();
    const buf = new Uint8Array(arrayBuffer);
    console.log('Success:', buf);
    setSegments(`found: ${toHex(buf)}`);
    return false;
  };

  // Create the count state.
  const [count, setCount] = useState(0);
  // Create the counter (+1 every second).
  useEffect(() => {
    const timer = setTimeout(() => setCount(count + 1), 1000);
    return () => clearTimeout(timer);
  }, [count, setCount]);
  // Return the App component.
  return (
    <div className="App">
      <header className="App-header">
        <p>client {`${new NanoTDFClient({})}`}</p>
        <p>
          Page has been open for <code>{count}</code> seconds.
        </p>
      </header>
      <p>Select a file and submit to slice it.</p>
      <div>
        <label htmlFor="file-selector">Select file:</label>
        <input type="file" name="file" id="file-selector" onChange={changeHandler} />
        {selectedFile ? (
          <div>
            <h2>{selectedFile.name}</h2>
            <div>Content Type: {selectedFile.type}</div>
            <div>Last Modified: {new Date(selectedFile.lastModified).toLocaleString()}</div>
            <div>Size: {new Intl.NumberFormat().format(selectedFile.size)} bytes</div>
          </div>
        ) : (
          <p>Select a file to show details</p>
        )}
        {segments.length ? (
          <h3>{segments}</h3>
        ) : (
          <div>
            <button disabled={!isFilePicked} onClick={handleSubmission}>
              Process
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
