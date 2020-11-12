const { Sequelize } = require('sequelize');
const database = require('../../../config').database;
const logs = require('../../../config').debug;
const debug = require('debug')('spid:models');

// Use BBDD Mysql
const sequelize = new Sequelize(database.database, database.username, database.password, {
  host: database.host,
  dialect: database.dialect,
  logging: logs,
  port: database.port !== 'default' ? database.port : undefined
});


sequelize
  .authenticate()
  .then(() => {
    debug('Connection has been established successfully');
  })
  .catch((err) => {
    debug('Unable to connect to the database: ', err);
  });

const spid = sequelize.import('./spid_credentials.js');

exports.spid_credentials = spid;
