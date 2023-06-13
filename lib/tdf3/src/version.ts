import { inBrowser } from './utils/index.js';

export const version = '1.0.0';
export const clientType = inBrowser() ? 'tdf3-js-client' : 'tdf3-js-node';
