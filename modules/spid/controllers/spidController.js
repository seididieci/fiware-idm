const fs = require('fs');
const debug = require('debug')('idm:spid_controller');
const { ServiceProvider } = require('../lib/spid.js');
const image = require('../../../lib/image.js');
const models = require('../../../models/models.js');
const spidModels = require('../models/models.js');
const path = require('path');
const exec = require('child_process').exec;

const requests_app_ids = {};

// TODO: Queste vanno rese configurabili
const options = {
  signatureAlgorithm: 'sha512',
  sp: {
    entity_id: 'https://localhost/idm/applications/9e5d1f6e-5000-4125-9f50-54d0aaec2996/saml2/metadata',
    private_key: fs.readFileSync('./certs/applications/9e5d1f6e-5000-4125-9f50-54d0aaec2996-key.pem', 'utf-8'),
    certificate: fs.readFileSync('./certs/applications/9e5d1f6e-5000-4125-9f50-54d0aaec2996-cert.pem', 'utf-8'),
    assert_endpoint: 'http://localhost:3000/spid/acs',
    // alt_private_keys: [],
    // alt_certs: [],
    force_authn: false,
    auth_context: {
      comparison: 'exact',
      class_refs: ['https://www.spid.gov.it/SpidL1']
    },
    nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    sign_get_request: true,
    allow_unencrypted_assertion: true,
    // Custom
    organization: {
      name: 'TeamDev',
      displayName: 'TeamDev s.r.l.',
      URL: 'https://teamdev.it'
    },
    attributeConsumingServiceIndex: 1,
    attributes: {
      name: 'Required attributes',
      values: ['fiscalNumber', 'name', 'familyName', 'email']
    }
  },
  idp: {
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
    entity_id: 'http://localhost:8088'
  }
};

// const sp_states = {};

exports.get_metadata = (req, res, nest) => {
  debug('--> spid_metadata');

  const sp = new ServiceProvider(options);
  const metadata = sp.generateMetadata();

  res.send(metadata);
};

exports.spid_login = async (req, res, nest) => {
  debug('--> spid_login');

  try {
    const sp = new ServiceProvider(options);
    const auth_req = sp.create_authn_request();

    requests_app_ids[auth_req.id] = req.application.id;

    const url = await sp.getRequestUrl(auth_req.xml);

    // Redirect to SPID IdP
    res.redirect(302, url);
  } catch (err) {
    debug(err);
    req.next(err);
  }
};

exports.validateResponse = async (req, res, next) => {
  debug('--> spid_response');

  try {
    const sp = new ServiceProvider(options);
    const respData = await sp.validateResponse(req.body);

    // id transiente dell'uetnte (cambia ad ogni login)
    const name_id = respData.user.name_id;
    // id della sessione spid
    const session_index = respData.user.session_index;

    // Dovrebbe essere pari all'id della richiesta
    // TODO: Implementare il controllo sul responseto
    const response_to = respData.response_header.in_response_to;

    if (!requests_app_ids[response_to]) {
    }

    const spid_profile = {};

    for (const key in respData.user.attributes) {
      // if (saml_response.user.attributes.hasOwnProperty(key)) {
      if (Object.prototype.hasOwnProperty.call(respData.user.attributes, key)) {
        spid_profile[key] = respData.user.attributes[key][0];
      }
    }

    const user = await create_user(name_id, spid_profile);

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

    // const state = sp_states[response_to] ? sp_states[response_to] : 'xyz';

    // const redirect_uri = sp_redirect_uris[response_to]
    //   ? sp_redirect_uris[response_to]
    //   : req.application.redirect_uri.split(',')[0];

    //TODO: Vanno recuperati i dati dell'applicazione che ha fatto la richiesta..
    const path =
      '/oauth2/authorize?' +
      'response_type=code&' +
      'client_id=' +
      '9e5d1f6e-5000-4125-9f50-54d0aaec2996' +
      '&' +
      'state=' +
      'xyz' +
      '&' +
      'redirect_uri=' +
      'http://localhost:8080/auth_callback.html';

    res.redirect(path);
  } catch (err) {
    debug(err);
    next(err);
  }
};

// GET: /idm/applications/:id/step/spid
exports.application_step_spid = (req, res) => {
  res.render('../modules/spid/views/step_spid.ejs', {
    application: req.application,
    spid_credentials: [],
    errors: [],
    csrf_token: req.csrfToken()
  });
};

// POST: /idm/applications/:id/step/spid
exports.application_save_spid = async (req, res) => {
  const credentials = req.body.spid_credentials;

  const newValue = spidModels.spid_credentials.build();0
  newValue.application_id = req.application.id;
  newValue.auth_context_comparison = credentials.comparison;
  newValue.auth_context_cref = credentials.level;
  newValue.organization_name = credentials.organization_name;
  newValue.organization_display_name = credentials.organization_display_name;
  newValue.organization_url = credentials.organization_url;
  newValue.attributes_list = {
    name: credentials.attributes_name,
    values: credentials.attributes_list.split(', ')
  };

  try {
    await newValue.validate();
    await newValue.save();
    await generate_app_certificates(req.application.id, newValue);
    req.session.skipSPID = true;
    return res.redirect('/idm/applications/' + req.application.id + '/step/avatar');
  } catch (err) {
    debug(err);
    next(err);
  }
};

async function create_user(name_id, spid_profile) {
  let image_name = 'default';

  const file_name = await image.toImage(spid_profile.currentPhoto, 'public/img/users');

  if (file_name) {
    image_name = file_name;
    delete spid_profile.currentPhoto;
  }
  const user = await models.user.findOne({ where: { email: spid_profile.email } });

  if (!user) {
    // Se non esiste lo creo nuovo
    const userdata = {
      username: spid_profile.name + ' ' + spid_profile.familyName,
      eidas_id: name_id,
      email: spid_profile.email ? spid_profile.email : null,
      image: image_name !== 'default' ? image_name : 'default',
      extra: {
        spid_profile: spid_profile,
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
  if (!user_extra.visible_attributes)
    user_extra.visible_attributes = ['username', 'description', 'website', 'identity_attributes', 'image', 'gravatar'];

  user.extra = user_extra;
  user.email = spid_profile.email && !user.email ? spid_profile.email : user.email;
  user.username =
    spid_profile.name + ' ' + spid_profile.familyName != user.username
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
