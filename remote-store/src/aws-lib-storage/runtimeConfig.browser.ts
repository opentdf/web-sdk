import { ClientSharedValues } from './runtimeConfig.shared.js';

/**
 * @internal
 */
export const ClientDefaultValues = {
  ...ClientSharedValues,
  runtime: 'browser',
};
