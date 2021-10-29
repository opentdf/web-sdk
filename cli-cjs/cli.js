const yargs = require('yargs/yargs')
const { hideBin } = require('yargs/helpers')
const { sum } = require('@opentdf/client');

const handleArgs = (args) => {
  return yargs(args)
    .options({
      action: { choices: ['encrypt', 'decrypt'] },
    })
    .parseSync();
};

const main = (args) => {
  console.log(`"action" is [${args.action}]. sum(1,1) is [${sum.sum(1, 1)}]`);
};

const a = handleArgs(hideBin(process.argv));
main(a);

module.exports = {
  handleArgs,
  main,
}