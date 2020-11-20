const fs = require('fs');
const path = require('path');

const plugins = {};
let loaded = false;

exports.loadPlugins = function () {
  if (loaded) {
    return plugins;
  }

  loaded = true;

  const root_path = path.resolve('./plugins');
  if (!fs.existsSync(root_path)) {
    return plugins;
  }

  const stat = fs.lstatSync(root_path);
  if (!stat.isDirectory()) {
    throw new Error(`'${root_path}' is not a direcory`);
  }

  const dirs = fs.readdirSync(root_path);
  for (const plug_dir of dirs) {
    const stat2 = fs.lstatSync(`${root_path}/${plug_dir}`);

    const plug_path = path.join(root_path, plug_dir, 'index.js');
    if (stat2.isDirectory()) {
      if (fs.existsSync(plug_path)) {
        plugins[plug_dir] = require(plug_path);
      }
    }
  }

  return plugins;
};
