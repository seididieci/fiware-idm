const express = require('express');
const router = express.Router();
const debug = require('debug')('idm:saml_model');
const spid_controller = require('../controllers/spidController');
const index_controller = require('../../../controllers/web/index');
const csrf = require('csurf');
const csrf_protection = csrf({ cookie: true });

router.param('application_id', index_controller.applications.load_application);

// Routes for SPID application creation/manipulation
router.get(
  '/applications/:application_id/configure_spid',
  index_controller.sessions.login_required,
  index_controller.sessions.password_check_date,
  index_controller.check_permissions.owned_permissions,
  csrf_protection,
  spid_controller.application_step_spid
);
router.post(
  '/applications/:application_id/configure_spid',
  index_controller.sessions.login_required,
  index_controller.sessions.password_check_date,
  index_controller.check_permissions.owned_permissions,
  csrf_protection,
  spid_controller.application_save_spid
);

// Routes for SPID
router.get('/:clientId/metadata', spid_controller.get_metadata);
router.post('/login', spid_controller.spid_login);
router.post('/:clientId/acs', spid_controller.validateResponse);

// catch 404 and forward to error handler
router.use(function (req, res) {
  const err = new Error('Path not Found');

  err.status = 404;
  if (req.useragent.isDesktop) {
    res.locals.error = err;
    res.render('errors/not_found');
  } else {
    res.status(404).json(err.message);
  }
});

// Error handler
/* eslint-disable no-unused-vars */
router.use(function (err, req, res, next) {
  /* eslint-enable no-unused-vars */
  debug(err);

  err.status = err.status || 500;
  // set locals, only providing error in development
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  // render the error page
  res.status(err.status);
  res.render('errors/generic');
});

module.exports = router;
