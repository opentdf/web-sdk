/* globals window */
/**
 * This file is used for:
 *
 * - es5 browser version of nanoTDF and add it to the window as NanoTDF
 *
 * This is not used for:
 *
 * - es6 web development (use node modules)
 * - node applications
 */
import { NanoTDF } from '.';

declare global {
  interface Window {
    NanoTDF: typeof NanoTDF;
  }
}

window.NanoTDF = NanoTDF;
