import { inBrowser } from './utils/index.js';

export const version = '0.4.0';
export const clientType = inBrowser() ? 'tdf3-js-client' : 'tdf3-js-node';
