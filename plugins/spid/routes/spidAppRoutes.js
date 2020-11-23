const express = require('express');
const router = express.Router();
// const debug = require('debug')('idm:saml_model');
const spid_controller = require('../controllers/spidController');
const index_controller = require('../../../controllers/web/index');
const csrf = require('csurf');
const csrf_protection = csrf({ cookie: true });

router.param('application_id', index_controller.applications.load_application);

// Routes for SPID application creation
router.get(
  '/:application_id/step/spid',
  index_controller.sessions.login_required,
  index_controller.sessions.password_check_date,
  index_controller.check_permissions.owned_permissions,
  csrf_protection,
  spid_controller.application_step_spid
);

router.post(
  '/:application_id/step/spid',
  index_controller.sessions.login_required,
  index_controller.sessions.password_check_date,
  index_controller.check_permissions.owned_permissions,
  csrf_protection,
  spid_controller.application_save_spid
);

module.exports = router;