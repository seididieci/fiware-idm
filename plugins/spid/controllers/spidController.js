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
const xmldom = require('xmldom');


// Keep request in-memory
// TODO: This should be moved in the db if we have to restart the server or make the service h-scalable
const requests = {};

exports.get_metadata = async (req, res) => {
  debug('--> spid_metadata');
  const credentials = await spid_models.spid_credentials.findOne({
    where: { application_id: req.params.clientId }
  });

  const sp_options = get_sp_options(credentials);

  const sp = new ServiceProvider({sp: sp_options});
  const metadata = sp.generate_metadata();

  res.send(metadata);
}

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
      const idp_options = await get_idp_options(idp);

      const sp = new ServiceProvider({
        sp: sp_options,
        idp: idp_options,
        signature_algorithm: 'sha512',
      });
      const auth_req = sp.create_authn_request();
      const url = await sp.get_request_url(auth_req.xml);

      requests[auth_req.id] = {
        client_id: credentials.application_id,
        state: req.query.state,
        response_type: req.query.response_type,
        redirect_uri: req.query.redirect_uri,
        idp_id: req.query.idp
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
}

exports.validateResponse = async (req, res, next) => {
  debug('--> spid_response');

  try {
    const credentials = await spid_models.spid_credentials.findOne({
      where: { application_id: req.params.clientId }
    });
    const sp_options = get_sp_options(credentials);

    // Recupero il documento xml
    const xml = Buffer.from(req.body.SAMLResponse, 'base64').toString('utf8');
    const parser = new xmldom.DOMParser();
    const doc = parser.parseFromString(xml);

    // Checking response_to that should be one of my requests
    const response_to = doc.documentElement.getAttributeNode("InResponseTo").value;
    if (!requests[response_to]) {
      throw new Error('Unknow authentication request!');
    }
    
    // idp scelto dall'utente
    const idp = config.spid.idp_list.find((i) => i.id === requests[response_to].idp_id);
    if (!idp) {
      throw new Error('Invalid SPID IDP');
    }
    const idp_options = await get_idp_options(idp);
    
    const sp = new ServiceProvider({
      sp: sp_options,
      idp: idp_options,
      signature_algorithm: 'sha512',
    });
    

    const resp_data = await sp.validate_response(req.body);

    // The name_id will change at avery login (it is forced to be transinet by SPID regultaions)
    //  so we will check the user by fiscalNumber that should not change (at least if the user does not change his identity)
    // const name_id = resp_data.user.name_id;

    // SPID Has a session_index that will be needed for logout user from his sesssion
    // const session_index = resp_data.user.session_index;
    

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
}

async function get_idp_options(idp) {

    const client = require((idp.meta_url.startsWith("https"))?'https':'http')
    
    let response = await new Promise((res, rej) => {
      
      let output = '';
      
      const req = client.get(idp.meta_url, response => {

        if(response.statusCode != 200){
          throw new Error('Error in idp connection');
        }
        
        response.on('data', chunk => {     
          output+=chunk;
        })

        response.on('end', function () {
          res(output);
        });
      })
      
      req.on('error', error => {
        console.error(error)
      })
      
      req.end()
    });


    // Recupero il documento xml
    const xml = response.toString('utf8');
    const parser = new xmldom.DOMParser();
    const doc = parser.parseFromString(xml);

    // L'elemento <IDPSSODescriptor> specifico che contraddistingue l’entità di tipo Identity Provider
    const idp_sso_descriptor = doc.getElementsByTagName("md:IDPSSODescriptor");

    // WantAuthnRequestSigned: attributo con valore booleano che impone ai Service Provider che fanno 
    // uso di questo Identity provider l’obbligo della firma delle richieste di autenticazione;
    const sign_get_request = (idp_sso_descriptor[0].getAttributeNode('WantAuthnRequestsSigned')?.value === 'true');


    // l’elemento <KeyDescriptor> che contiene l’elenco dei certificati e delle corrispondenti chiavi pubbliche dell’entità, utili per 
    // la verifica della firma dei messaggi prodotti da tale entità nelle sue interazioni con le altre (SAMLMetadata, par. 2.4.1.1)
    var key_descriptor_coll = searchTree(idp_sso_descriptor[0], 'md:KeyDescriptor');
    if(!key_descriptor_coll || !key_descriptor_coll[0]){
      throw new Error('Invalid SSO certificates');
    }
    const key_descriptor_singning_coll = key_descriptor_coll.filter((i) => (!i.getAttributeNode("use") || i.getAttributeNode("use").value != 'encryption'));
    if(!key_descriptor_singning_coll || !key_descriptor_singning_coll[0]){
      throw new Error('Invalid SSO certificates');
    }

    const certificates = [];
    key_descriptor_singning_coll.forEach(element => {
      Array.prototype.push.apply(certificates, searchTree(element, 'ds:X509Certificate').map(i => i.textContent));
    });
    



    //uno o più elementi <SingleSignOnService> che specificano l’indirizzo del Single Sign-On Service riportanti i seguenti attributi:
    //Location URL endpoint del servizio per la ricezione delle richieste
    //Binding che può assumere uno dei valori
    //urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
    //urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
    const sso_login_url_coll = searchTree(idp_sso_descriptor[0], "md:SingleSignOnService")
    if(!sso_login_url_coll){
        throw new Error('Invalid SSO Login url');
    }
    const sso_login_url_node = sso_login_url_coll.find(i => i.getAttributeNode('Binding')?.nodeValue=="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
    if(!sso_login_url_node){
      throw new Error('Invalid SSO Login url');
    }
    const sso_login_url = sso_login_url_node.getAttributeNode('Location').nodeValue;

    // uno o più elementi <SingleLogoutService> che specificano l’indirizzo del Single Logout Service riportanti i seguenti attributi:
    // Location URL endpoint del servizio per la ricezione delle richieste di Single Logout;
    // Binding che può assumere uno dei valori
    // urn:oasis:names:tc:SAML:2.0:bindings:SOAP
    // urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
    // urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
    const sso_logout_url_coll = searchTree(idp_sso_descriptor[0], "md:SingleLogoutService")
    if(!sso_logout_url_coll){
      throw new Error('Invalid Single Logout url');
    }
    const sso_logout_url_node = sso_logout_url_coll.find(i => i.getAttributeNode('Binding')?.nodeValue=="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
    if(!sso_login_url_node){
      throw new Error('Invalid SSO Logout url');
    }      
    const sso_logout_url = sso_logout_url_node.getAttributeNode('Location').nodeValue;

    return {
      sso_login_url: sso_login_url,
      sso_logout_url: sso_logout_url,
      certificates: certificates,
      force_authn: false,
      sign_get_request: sign_get_request,//FIXME: deve essere gestito all'interno della libreria 
      allow_unencrypted_assertion: true,
      entity_id: idp.entity_id
    };
};

function searchTree(element, matchingTitle){
  if(element.nodeName == matchingTitle){
       return [element];
  }else if (element.childNodes != null){
       var i;
       var result = [];
       for(i=0; i < element.childNodes.length; i++){
            let rec = searchTree(element.childNodes[i], matchingTitle);
            if(rec){
              Array.prototype.push.apply(result, rec);
            }
       }
       return result;
  }
  return null;
}

function get_sp_options(credentials) {
  return {
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
      //sign_get_request: true, 
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
