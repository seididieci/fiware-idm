const { spid_credentials } = require('./models/models.js');
const spidRoute = require('./routes/spidRoutes.js');
const spidAppRoute = require('./routes/spidAppRoutes.js');
const debug = require('debug')('spid:module');

exports.install = function (app, config) {
  if (config.spid.enabled) {
    app.use((req, res, next) => {
      var regex = /\/idm\/applications\/(.*)\/step\/avatar/gim;
      var groups = regex.exec(req.path);

      if (groups && groups.length > 1) {
        // Qui mi devo gestire la configurazione dello SPID
        const appId = groups[1];

        // Sto salvando l'avatar che è l'ultimo dei moicani e quindi ho già fatto lo step SPID
        if (req.method === 'POST') {
          next();
          return;
        }

        debug('Found step avatar in application', groups[1]);

        res.redirect('/idm/applications/' + appId + '/step/spid');
        return;
      }
      next();
    });

    app.use('/spid', spidRoute);

    app.use('/idm/applications', spidAppRoute);

    // Crea la tabella o la aggiorna
    spid_credentials.sync({ alter: true });
  }
};
