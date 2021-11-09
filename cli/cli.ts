import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { NanoTDFClient } from '@opentdf/client';

export const handleArgs = (args: string[]) => {
  return yargs(args)
    .options({
      action: { choices: ['encrypt', 'decrypt'] },
    })
    .parseSync();
};

export type mainArgs = ReturnType<typeof handleArgs>;
export const main = (args: mainArgs) => {
  const client = new NanoTDFClient();
  // switch (args.action) {
  //   case 'encrypt':
  //     break;
  // }
  console.log(`"action" is [${args.action}].`, client);
};

const a = handleArgs(hideBin(process.argv));
main(a);
