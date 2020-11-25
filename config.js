const config = {};

config.port = 3000;
config.host = 'http://localhost:3000';

config.debug = false;

// HTTPS enable
config.https = {
  enabled: false,
  cert_file: 'certs/idm-2018-cert.pem',
  key_file: 'certs/idm-2018-key.pem',
  ca_certs: [],
  port: 3443
};

// Config email list type to use domain filtering
config.email_list_type = null; // whitelist or blacklist

// Enable 2fa authentication
config.enable_2fa = process.env.IDM_ENABLE_2FA || false;

// Secret for user sessions in web
config.session = {
  secret: require('crypto').randomBytes(20).toString('hex'), // Must be changed
  expires: 60 * 60 * 1000 // 1 hour
};

// Key to encrypt user passwords
config.password_encryption = {
  key: 'nodejs_idm' // Must be changed
};

// Enable CORS
config.cors = {
  enabled: true,
  options: {
    /* eslint-disable snakecase/snakecase */
    origin: ['*'],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    allowedHeaders: '*',
    exposedHeaders: undefined,
    credentials: true,
    maxAge: undefined,
    preflightContinue: false,
    optionsSuccessStatus: 204
    /* eslint-enable snakecase/snakecase */
  }
};

// Config oauth2 parameters
config.oauth2 = {
  authorization_code_lifetime: 5 * 60, // Five minutes
  access_token_lifetime: 60 * 60, // One hour
  ask_authorization: true, // Prompt a message to users to allow the application to read their details
  refresh_token_lifetime: 60 * 60 * 24 * 14, // Two weeks
  unique_url: false // This parameter allows to verify that an application with the same url
  // does not exist when creating or editing it. If there are already applications
  // with the same URL, they should be changed manually
};

// Config api parameters
config.api = {
  token_lifetime: 60 * 60 // One hour
};

// Configure Policy Decision Point (PDP)
//  - IdM can perform basic policy checks (HTTP verb + path)
//  - AuthZForce can perform basic policy checks as well as advanced
// If authorization level is advanced you can create rules, HTTP verb+resource and XACML advanced. In addition
// you need to have an instance of authzforce deployed to perform advanced authorization request from a Pep Proxy.
// If authorization level is basic, only HTTP verb+resource rules can be created
config.authorization = {
  level: 'basic', // basic|advanced
  authzforce: {
    enabled: false,
    host: 'localhost',
    port: 8080
  }
};

// Enable usage control and configure where is the Policy Translation Point
config.usage_control = {
  enabled: false,
  ptp: {
    host: 'localhost',
    port: 8081
  }
};

// Database info
config.database = {
  host: 'localhost',
  password: '123456/AP',
  username: 'root',
  database: 'idm',
  dialect: 'mysql',
  port: 3306
};

// External user authentication
config.external_auth = {
  enabled: false,
  id_prefix: 'external_',
  password_encryption: 'sha1', // bcrypt and sha1 supported
  password_encryption_key: undefined,
  database: {
    host: 'localhost',
    port: undefined,
    database: 'db_name',
    username: 'db_user',
    password: 'db_pass',
    user_table: 'user_view',
    dialect: 'mysql'
  }
};

// External user authentication with LDAP
// Testing credentials from https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
config.external_auth_ldap = {
  enabled: false,
  id_prefix: 'external_ldap_',
  database: {
    /* eslint-disable snakecase/snakecase */
    host: 'ldap.forumsys.com',
    port: 389,
    reader_dn: 'cn=read-only-admin,dc=example,dc=com',
    reader_password: 'password',
    suffix: 'dc=example,dc=com',
    idAttribute: 'uid',
    usernameAttribute: 'uid',
    emailAttribute: 'mail'
    /* eslint-enable snakecase/snakecase */
  }
};

// Email configuration
config.mail = {
  host: 'localhost',
  port: 25,
  from: 'noreply@localhost'
};

// Config themes
config.site = {
  title: 'Identity Manager',
  theme: 'default'
};

// Config eIDAS Authentication
config.eidas = {
  enabled: true,
  gateway_host: 'localhost',
  node_host: 'http://localhost:8088/',
  metadata_expiration: 60 * 60 * 24 * 365 // One year
};

// Config SPID Authentication
config.spid = {
  enabled: true,
  gateway_host: 'http://localhost:3000',
  idp_list: [
    {
      id: 'testid',
      entity_id: 'http://localhost:8088',
      name: 'SPID di test',
      meta_url:"http://localhost:8088/metadata",
    },
    {
      id: 'arubaid',
      entity_id: 'https://loginspid.aruba.it',
      name: 'Aruba ID',
      meta_url:"https://loginspid.aruba.it/metadata",
    },
    {
      id: 'infocertid',
      entity_id: 'https://identity.infocert.it',
      name: 'Infocert ID',
      meta_url:"https://identity.infocert.it/metadata/metadata.xml",
    },
    {
      id: 'intesaid',
      entity_id: 'https://spid.intesa.it',
      name: 'Intesa ID',
      meta_url:"https://spid.intesa.it/metadata/metadata.xml",
    },
    {
      id: 'lepidaid',
      entity_id: 'https://id.lepida.it/idp/shibboleth',
      name: 'Lepida ID',
      meta_url:"https://id.lepida.it/idp/shibboleth",
    },
    {
      id: 'namirialid',
      entity_id: 'https://idp.namirialtsp.com/idp',
      name: 'Namirial ID',
      meta_url:"https://idp.namirialtsp.com/idp/metadata",
    },
    {
      id: 'posteid',
      entity_id: 'https://posteid.poste.it',
      name: 'Poste ID',
      meta_url:"https://posteid.poste.it/jod-fs/metadata/metadata.xml",
    },
    {
      id: 'sielteid',
      entity_id: 'https://identity.sieltecloud.it',
      name: 'Sielte ID',
      meta_url:"https://identity.sieltecloud.it/simplesaml/metadata.xml",
    },
    {
      id: 'spiditalia',
      entity_id: 'https://spid.register.it',
      name: 'SPIDItalia Register.it',
      meta_url:"https://spid.register.it/login/metadata",
    },
    {
      id: 'timid',
      entity_id: 'https://login.id.tim.it/affwebservices/public/saml2sso',
      name: 'Tim ID',
      meta_url:"https://login.id.tim.it/spid-services/MetadataBrowser/idp",
    }
  ]
};

// Enables the possibility of adding identity attributes in users' profile
config.identity_attributes = {
  /* eslint-disable snakecase/snakecase */
  enabled: false,
  attributes: [
    {
      name: 'Vision',
      key: 'vision',
      type: 'number',
      minVal: '0',
      maxVal: '100'
    },
    {
      name: 'Color Perception',
      key: 'color',
      type: 'number',
      minVal: '0',
      maxVal: '100'
    },
    {
      name: 'Hearing',
      key: 'hearing',
      type: 'number',
      minVal: '0',
      maxVal: '100'
    },
    {
      name: 'Vocal Capability',
      key: 'vocal',
      type: 'number',
      minVal: '0',
      maxVal: '100'
    },
    {
      name: 'Manipulation Strength',
      key: 'manipulation',
      type: 'number',
      minVal: '0',
      maxVal: '100'
    },
    { name: 'Reach', key: 'reach', type: 'number', minVal: '0', maxVal: '100' },
    {
      name: 'Cognition',
      key: 'cognition',
      type: 'number',
      minVal: '0',
      maxVal: '100'
    }
  ]
  /* eslint-enable snakecase/snakecase */
};

module.exports = config;
