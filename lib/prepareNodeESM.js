import FileHound from 'filehound';
import fs from 'node:fs';

const __dirname = new URL('.', import.meta.url).pathname;

(async () => {
  const files = await FileHound.create()
    .paths([__dirname + '/dist/esm/src', __dirname + '/dist/esm/tdf3', __dirname + '/dist/types'])
    .discard('node_modules')
    .ext(['js', 'ts'])
    .find((err, files) => {
      if (err || !files.length) {
        console.error('There is no ESM build folder.');
      }
      return files;
    });

  files.forEach((filepath) => {
    fs.readFile(filepath, 'utf8', (err, data) => {
      if (!data.match(/(?:import|export) .* from/g)) {
        return;
      }
      let newData = data;
      if (err) throw err;

      fs.writeFile(filepath, newData, function (err) {
        if (err) {
          throw err;
        }
      });
    });
  });
})();
