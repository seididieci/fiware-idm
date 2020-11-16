const { spid_credentials } = require('./models/models.js');
const spidRoute = require('./routes/spidRoutes.js');
const spidAppRoute = require('./routes/spidAppRoutes.js');
const debug = require('debug')('spid:module');

exports.install = function (app, config) {
  if (config.spid.enabled) {
    app.use((req, res, next) => {
      // Se devo saltare lo spid
      if (req.session.skipSPID) {
        next();
        return;
      }

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

// Method to see users permissions to do some actions
// - 1 Get and assign all internal application roles
// - 2 Manage the application
// - 3 Manage roles
// - 4 Manage authorizations
// - 5 Get and assign all public application roles
// - 6 Get and assign only public owned roles
exports.check_user_action = function (application, path, method, permissions) {
  if (path.includes('step/spid') && method === 'POST') {
    if (permissions.includes('2')) {
      return true;
    }
  }

  return false;
};
