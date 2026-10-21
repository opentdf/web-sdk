import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.js';
import { registerDownloadWorker } from './downloadSink.js';
import './index.css';

registerDownloadWorker();

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
