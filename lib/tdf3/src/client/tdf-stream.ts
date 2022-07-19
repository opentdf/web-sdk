import { type BrowserTdfStreamInterface } from './BrowserTdfStream';
import { type NodeTdfStreamInterface } from './NodeTdfStream';

// @ts-ignore: webpack alias, check webpack.config.js file
import SomeStream from '@tdfStream';

type PT = BrowserTdfStreamInterface | NodeTdfStreamInterface;

export const PlaintextStream: PT = SomeStream as PT;
