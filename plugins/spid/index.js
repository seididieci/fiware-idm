const { spid_credentials } = require('./models/models.js');
const spid_route = require('./routes/spidRoutes.js');
const spid_controller = require('./controllers/spidController');
const express = require('express');
const path = require('path');

exports.install = function (app, config) {
  if (config.spid.enabled) {
    app.use('/static/plugins/spid', express.static(path.join(__dirname, 'public')));

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
  // FIXME: Weak control over path...
  if (path.endsWith('/configure_spid') && method === 'POST') {
    if (permissions.includes('2')) {
      return true;
    }
  }

  return false;
};

exports.app_new_steps = ['/spid/applications/:application_id/configure_spid'];
exports.app_show_handler = spid_controller.application_details_spid;
exports.app_oauth_login_button = spid_controller.application_login_button_spid;
exports.router = spid_route;
