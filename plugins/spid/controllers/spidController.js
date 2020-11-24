const fs = require('fs');
const debug = require('debug')('idm:spid_controller');
// eslint-disable-next-line snakecase/snakecase
const { ServiceProvider } = require('../lib/spid.js');
const image = require('../../../lib/image.js');
const models = require('../../../models/models.js');
const spid_models = require('../models/models.js');
const path = require('path');
const exec = require('child_process').exec;
const config_service = require('../../../lib/configService.js');
const config = config_service.get_config();
const gravatar = require('gravatar');
// const { render } = require('ejs');

// Keep request in-memory
// TODO: This should be moved in the db if we have to restart the server or make the service h-scalable
const requests = {};

exports.get_metadata = async (req, res) => {
  debug('--> spid_metadata');
  const credentials = await spid_models.spid_credentials.findOne({
    where: { application_id: req.params.clientId }
  });

  const sp_options = get_sp_options(credentials);

  const sp = new ServiceProvider(sp_options);
  const metadata = sp.genersate_metadata();

  res.send(metadata);
};

exports.spid_login = async (req, res, next) => {
  debug('--> spid_login');

  //FIXME: se popolata la form di inserimento credenziali, il dato arriva qui (ma non è una soluzione pulita...)

  try {
    const credentials = await spid_models.spid_credentials.findOne({
      where: { application_id: req.query.client_id }
    });

    if (credentials) {
      // idp scelto dall'utente
      const idp = config.spid.idp_list.find((i) => i.id === req.query.idp);
      if (!idp) {
        throw new Error('Invalid SPID IDP');
      }

      //crete service Provider
      const sp_options = get_sp_options(credentials);

      const sp = new ServiceProvider(sp_options);
      const auth_req = sp.create_authn_request();
      const url = await sp.get_request_url(auth_req.xml);

      requests[auth_req.id] = {
        client_id: credentials.application_id,
        state: req.query.state,
        response_type: req.query.response_type,
        redirect_uri: req.query.redirect_uri
      };

      // Redirect to SPID IdP
      res.redirect(302, url);
    } else {
      next();
    }
  } catch (err) {
    debug(err);
    req.next(err);
  }
};

exports.validateResponse = async (req, res, next) => {
  debug('--> spid_response');

  try {
    const credentials = await spid_models.spid_credentials.findOne({
      where: { application_id: req.params.clientId }
    });

    const sp_options = get_sp_options(credentials);

    const sp = new ServiceProvider(sp_options);
    const resp_data = await sp.validate_response(req.body);

    // The name_id will change at avery login (it is forced to be transinet by SPID regultaions)
    //  so we will check the user by fiscalNumber that should not change (at least if the user does not change his identity)
    // const name_id = resp_data.user.name_id;

    // SPID Has a session_index that will be needed for logout user from his sesssion
    // const session_index = resp_data.user.session_index;

    // Checking response_to that should be one of my requests
    const response_to = resp_data.response_header.in_response_to;
    if (!requests[response_to]) {
      throw new Error('Unknow authentication request!');
    }

    const spid_profile = {};
    for (const key in resp_data.user.attributes) {
      if (Object.prototype.hasOwnProperty.call(resp_data.user.attributes, key)) {
        spid_profile[key] = resp_data.user.attributes[key][0];
      }
    }
    const user = await create_user(spid_profile);

    let image = '/img/logos/small/user.png';
    if (user.email && user.gravatar) {
      image = gravatar.url(user.email, { s: 25, r: 'g', d: 'mm' }, { protocol: 'https' });
    } else if (user.image !== 'default') {
      image = '/img/users/' + user.image;
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      image,
      oauth_sign_in: true
    };

    const path =
      `/oauth2/authorize` +
      `?response_type=${requests[response_to].response_type.split(' ').join('%20')}` +
      `&client_id=${requests[response_to].client_id}` +
      `&state=${(requests[response_to].state ?? 'xyz').split(' ').join('%20')}` +
      `&redirect_uri=${requests[response_to].redirect_uri.split(' ').join('%20')}`;

    res.redirect(path);
  } catch (err) {
    debug(err);
    next(err);
  }
};

// GET: /spid/applications/:application_id/step
exports.application_step_spid = (req, res) => {
  res.render('../plugins/spid/views/step_spid.ejs', {
    spid_enabled: false,
    application: req.application,
    spid_credentials: [],
    errors: [],
    csrf_token: req.csrfToken()
  });
};

// POST: /idm/applications/:id/step/spid
exports.application_save_spid = async (req, res) => {
  if (!req.body.spid_enabled) {
    return res.redirect('/idm/applications/' + req.application.id + '/next_step');
  }

  const credentials = req.body.spid_credentials;

  let new_value = await spid_models.spid_credentials.findOne({
    where: { application_id: req.application.id }
  });

  if (!new_value) {
    new_value = spid_models.spid_credentials.build();
    new_value.application_id = req.application.id;
  }

  new_value.auth_context_comparison = credentials.comparison;
  new_value.auth_context_cref = credentials.level;
  new_value.organization_name = credentials.organization_name;
  new_value.organization_display_name = credentials.organization_display_name;
  new_value.organization_url = credentials.organization_url;
  new_value.attributes_list = {
    name: credentials.attributes_name,
    values: credentials.attributes_list.split(', ')
  };

  try {
    await new_value.validate();
    await new_value.save();
    await generate_app_certificates(req.application.id, new_value);
    return res.redirect('/idm/applications/' + req.application.id + '/next_step');
  } catch (error) {
    debug('Error: ', error);

    const name_errors = [];

    if (error.errors && error.errors.length) {
      for (const i in error.errors) {
        name_errors.push(error.errors[i].message);
      }
    }

    res.locals.message = {
      text: ' Fail creating SPID credentials.',
      type: 'warning'
    };

    return res.render('../plugins/spid/views/step_spid.ejs', {
      spid_enabled: req.body.spid_enabled,
      application: req.application,
      spid_credentials: new_value,
      errors: name_errors,
      csrf_token: req.csrfToken()
    });
  }
};

// GET: /oauth2/authorize
exports.application_login_button_spid = async (req, res, next) => {
  const credentials = await spid_models.spid_credentials.findOne({
    where: { application_id: req.application.id }
  });

  if (!res.locals.plugin_parts) {
    res.locals.plugin_parts = [];
  }

  if (credentials) {
    res.locals.spid_idp_list = config.spid.idp_list;
    res.locals.plugin_parts.push(path.resolve('./plugins/spid/views/spid_button.ejs'));
    res.locals.spid_auth = {
      login_button_label: 'SPID Login',
      enabled: true
    };
  }

  next();
};

// GET: /idm/applications/:id
exports.application_details_spid = async (req, res, next) => {
  const credentials = await spid_models.spid_credentials.findOne({
    where: { application_id: req.params.application_id }
  });

  if (!res.locals.plugin_parts) {
    res.locals.plugin_parts = [];
  }

  if (credentials) {
    res.locals.spid_credentials = credentials;
    res.locals.spid_metadata = `${config.spid.gateway_host}/spid/${credentials.application_id}/metadata`;
    res.locals.plugin_parts.push(path.resolve('./plugins/spid/views/spid_details.ejs'));
  }

  next();
};

function get_sp_options(credentials) {
  return {
    signature_algorithm: 'sha512',
    sp: {
      entity_id: `${config.spid.gateway_host}/spid/${credentials.application_id}/metadata`,
      private_key: fs.readFileSync(`./certs/applications/spid/${credentials.application_id}-key.pem`, 'utf-8'),
      certificate: fs.readFileSync(`./certs/applications/spid/${credentials.application_id}-cert.pem`, 'utf-8'),
      assert_endpoint: `${config.spid.gateway_host}/spid/${credentials.application_id}/acs`,

      // alt_private_keys: [],
      // alt_certs: [],
      force_authn: false,
      auth_context: {
        comparison: credentials.auth_context_comparison,
        class_refs: [credentials.auth_context_cref]
      },
      nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
      sign_get_request: true,
      allow_unencrypted_assertion: true,
      // Custom
      organization: {
        name: credentials.organization_name,
        display_name: credentials.displayName,
        url: credentials.organization_url
      },
      // eslint-disable-next-line snakecase/snakecase
      attributeConsumingServiceIndex: 1,
      attributes: {
        name: credentials.attributes_list.name,
        values: credentials.attributes_list.values
      }
    },
    idp: {
      //TODO: cambia con i security provider
      sso_login_url: 'http://localhost:8088/sso',
      sso_logout_url: 'http://localhost:8088/slo',
      certificates: [
        `MIIC+zCCAeOgAwIBAgIUeYWcwo2OxQ7mdjwhb3FsSylBs/EwDQYJKoZIhvcNAQEL
         BQAwDTELMAkGA1UEBhMCSVQwHhcNMjAxMDI4MTEzNjIxWhcNMjAxMTI3MTEzNjIx
         WjANMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
         ANIz6ELcW42s8tit/+5XiZn4eknpywvPPx1PoJYavZFdL8limDbIOTPwkbEqXJ0g
         nMOmTkF+5RsS5jQAVuendWoZcW2HDD1bT8RZME5GdpxMDvljtfQS709BdAlLuzE5
         W7PFGhKr8pgzwhhd4W6DUb1UqUsC/egWkXCw7khgdwsUX/vHK5WeIinGyD10B+Kt
         9I+TKUuyvhdldzdArqdQKFMK2PYLJLHiNU0R5kqiM/joBZYwjjNz+4kRFoc/CS7A
         2binzz6QVYZ+F+GXSGeUnoBxIchWghrmVnLckIBGq2GThoHoLzj0vSq2x2OYMS7b
         9Duumathd0QTDOpqmXxguRkCAwEAAaNTMFEwHQYDVR0OBBYEFHNd9zKL4d+yM+we
         yqIVag9T6xS9MB8GA1UdIwQYMBaAFHNd9zKL4d+yM+weyqIVag9T6xS9MA8GA1Ud
         EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAM5g1Cdj1MfZDAv447ROmAfw
         ts9Jx5qiE4vwP8mGBvumkHJNbeDLtWA5HQtmxfOms0BPu0LfVLG0Ci9V/zErSkg/
         TwazpgPMy9NBEVXgTnCwX/aaaKqs7DikA3f7pJOWfs1Mh/F6GNFR9TKXq5HYc2N0
         kEbhpC3iWdwCxqrpa7lDUvJ/GCRPT8j65a6ZbfYloemjd6QflCRN9EvjFMLYd7oJ
         T9kLq09OvFeyuzcE0HpZIu++D4zOmjsNdcaktmXuVZEWTRQOcmX24V9AhQY46rju
         31q/xjpkyW8r0CmAGdBAVY2ILKXtqe9LMlvqOKhzkU8ct9DwYLKH30lcFhhaQps=`
      ],
      force_authn: false,
      sign_get_request: true,
      allow_unencrypted_assertion: true,
      entity_id: config.spid.node_host
    }
  };
}

async function create_user(spid_profile) {
  let image_name = 'default';

  const file_name = await image.toImage(spid_profile.currentPhoto, 'public/img/users');

  if (file_name) {
    image_name = file_name;
    delete spid_profile.currentPhoto;
  }
  // Using fiscalNumber as uinque constranint should be more accureate than e-mail...
  const user = await models.user.findOne({ where: { eidas_id: spid_profile.fiscalNumber } });

  if (!user) {
    // Se non esiste lo creo nuovo
    const userdata = {
      username: spid_profile.name + ' ' + spid_profile.familyName,
      eidas_id: spid_profile.fiscalNumber,
      email: spid_profile.email ? spid_profile.email : null,
      image: image_name !== 'default' ? image_name : 'default',
      extra: {
        spid_profile,
        visible_attributes: ['username', 'description', 'website', 'identity_attributes', 'image', 'gravatar']
      },
      enabled: true
    };

    return await models.user.build(userdata).save();
  }
  // Aggiorno il profilo SPID
  const actual_spid_profile_keys = Object.keys(user.extra.spid_profile);
  const new_spid_profile_keys = Object.keys(spid_profile);

  const difference = new_spid_profile_keys.filter((x) => !actual_spid_profile_keys.includes(x));
  const new_attributes = user.extra.spid_profile;

  for (let i = 0; i < difference.length; i++) {
    new_attributes[difference[i]] = spid_profile[difference[i]];
  }
  const user_extra = user.extra;
  Object.assign(user_extra.spid_profile, new_attributes);
  if (!user_extra.visible_attributes) {
    user_extra.visible_attributes = ['username', 'description', 'website', 'identity_attributes', 'image', 'gravatar'];
  }

  user.extra = user_extra;
  user.email = spid_profile.email && !user.email ? spid_profile.email : user.email;
  user.username =
    spid_profile.name + ' ' + spid_profile.familyName !== user.username
      ? spid_profile.name + ' ' + spid_profile.familyName
      : user.username;

  // Se esiste già una foto da SPID, distruggo la precedente (se esiste) e ne creo una nuova
  const image_old = image_name !== 'default' ? user.image : 'default';
  user.image = image_name !== 'default' ? image_name : user.image;

  await image.destroy('public/img/users/' + image_old);

  return user.save({
    fields: ['extra', 'email', 'image']
  });
}

// Function to generate SAML certifiactes
function generate_app_certificates(app_id, spid_credentials) {
  debug('--> generate_app_certificates');

  return new Promise((resolve, reject) => {
    // Create certs folder if nor exists
    if (!fs.existsSync(path.resolve('certs/applications/spid'))) {
      fs.mkdirSync(path.resolve('certs/applications/spid'), { recursive: true });
    }

    const key_name = 'certs/applications/spid/' + app_id + '-key.pem';
    const csr_name = 'certs/applications/spid/' + app_id + '-csr.pem';
    const cert_name = 'certs/applications/spid/' + app_id + '-cert.pem';

    // Do not recreate if exists
    if (fs.existsSync(key_name) && fs.existsSync(cert_name)) {
      return;
    }

    const key = 'openssl genrsa -out ' + key_name + ' 2048';
    const csr =
      'openssl req -new -sha256 -key ' +
      key_name +
      ' -out ' +
      csr_name +
      ' -subj "/C=ES/ST=Madrid/L=Madrid/' +
      'O=' +
      spid_credentials.organization_name +
      '/OU=' +
      spid_credentials.organization_display_name +
      '/CN=' +
      spid_credentials.organization_url.replace(/(^\w+:|^)\/\//, '') +
      '"';

    const cert = 'openssl x509 -days 1095 -req -in ' + csr_name + ' -signkey ' + key_name + ' -out ' + cert_name;

    const create_certificates = key + ' && ' + csr + ' && ' + cert;
    exec(create_certificates, function (error) {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}
