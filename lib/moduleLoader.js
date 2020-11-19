const fs = require('fs');
const path = require('path');

const modules = {};
let loaded = false;

exports.loadModules = function (root_path) {
  if (loaded) {
    return modules;
  }

  loaded = true;

  const stat = fs.lstatSync(root_path);

  if (!stat.isDirectory()) {
    throw new Error(`'${root_path}' is not a direcory`);
  }

  const dirs = fs.readdirSync(root_path);

  for (const mod_dir of dirs) {
    const stat2 = fs.lstatSync(`${root_path}/${mod_dir}`);

    const mod_path = path.join(root_path, mod_dir, 'index.js');
    if (stat2.isDirectory()) {
      if (fs.existsSync(mod_path)) {
        modules[mod_dir] = require(mod_path);
      }
    }
  }

  return modules;
};
