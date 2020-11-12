var fs = require('fs');
var path = require('path');

const modules = {};
var loaded = false;

exports.loadModules = function (rootPath) {
  if (loaded) {
    return modules;
  }

  loaded = true;

  const stat = fs.lstatSync(rootPath);

  if (!stat.isDirectory()) {
    throw new Error(`'${rootPath}' is not a direcory`);
  }

  const dirs = fs.readdirSync(rootPath);

  for (const modDir of dirs) {
    const stat2 = fs.lstatSync(`${rootPath}/${modDir}`);

    const modPath = path.join(rootPath, modDir, 'index.js');
    if (stat2.isDirectory()) {
      if (fs.existsSync(modPath)) {
        modules[modDir] = require(modPath);
      }
    }
  }

  return modules;
};