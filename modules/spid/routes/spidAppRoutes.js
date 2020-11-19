const express = require('express');
const router = express.Router();
// const debug = require('debug')('idm:saml_model');
const spid_controller = require('../controllers/spidController');
const index_controller = require('../../../controllers/web/index');
const csrf = require('csurf');
const csrf_protection = csrf({ cookie: true });
const i18n = require('i18n-express');
const path = require('path');

router.param('application_id', index_controller.applications.load_application);

// Routes for SPID application creation
router.get(
  '/:application_id/step/spid',
  index_controller.sessions.login_required,
  index_controller.sessions.password_check_date,
  index_controller.check_permissions.owned_permissions,
  i18n({
    translationsPath: path.join(__dirname, '../translations'), // eslint-disable-line snakecase/snakecase
    siteLangs: ['en', 'es', 'ja', 'ko'], // eslint-disable-line snakecase/snakecase
    textsVarName: 'translation', // eslint-disable-line snakecase/snakecase
    browserEnable: true, // eslint-disable-line snakecase/snakecase
    defaultLang: 'en' // eslint-disable-line snakecase/snakecase
  }),
  csrf_protection,
  spid_controller.application_step_spid
);

// Questa va messa (copiata dalle rotte originarie) altrimenti la rotta qui sotto viene risolta prima...
router.get('/new', csrf_protection, index_controller.applications.new);

router.get(
  '/:application_id',
  i18n({
    translationsPath: path.join(__dirname, '../translations'), // eslint-disable-line snakecase/snakecase
    siteLangs: ['en', 'es', 'ja', 'ko'], // eslint-disable-line snakecase/snakecase
    textsVarName: 'spid_translation', // eslint-disable-line snakecase/snakecase
    browserEnable: true, // eslint-disable-line snakecase/snakecase
    defaultLang: 'en' // eslint-disable-line snakecase/snakecase
  }),
  spid_controller.application_details_spid
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
