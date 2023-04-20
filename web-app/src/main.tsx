import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.js';
import './index.css';

navigator.serviceWorker.register('./sw.js');

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
