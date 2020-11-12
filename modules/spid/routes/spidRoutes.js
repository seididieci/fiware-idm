const express = require('express');
const router = express.Router();
const debug = require('debug')('idm:saml_model');
const spid_controller = require('../controllers/spidController');

// Routes for SPID
router.get('/login', spid_controller.spid_login);

router.post('/acs', spid_controller.validateResponse);

// Create xml metadata
router.get("/metadata", spid_controller.get_metadata);

// catch 404 and forward to error handler
router.use(function(req, res) {
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
router.use(function(err, req, res, next) {
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
