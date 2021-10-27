import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { sum } from '@opentdf/client/sum.js';

export const handleArgs = (args: string[]) => {
  return yargs(args)
    .options({
      action: { choices: ['encrypt', 'decrypt'] },
    })
    .parseSync();
};

export type mainArgs = ReturnType<typeof handleArgs>;
export const main = (args: mainArgs) => {
  console.log(`"action" is [${args.action}]. sum(1,1) is [${sum(1, 1)}]`);
};

const a = handleArgs(hideBin(process.argv));
main(a);
