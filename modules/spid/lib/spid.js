// 'use strict';
const url = require('url');
const zlib = require('zlib');
const crypto = require('crypto');
const xmldom = require('xmldom');
const saml2 = require('saml2-js');
const xmlbuilder = require('xmlbuilder');
const querystring = require('querystring');

// eslint-disable-next-line snakecase/snakecase
class ServiceProvider {
  constructor(options) {
    this.options = options;
  }

  genersate_metadata() {
    const options = this.options.sp;

    if (!options.certificate) {
      throw new Error('Missing certificate while generating metadata for decrypting service provider');
    }

    let cert = options.certificate.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
    cert = cert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
    cert = cert.replace(/\r\n/g, '\n');

    let metadata = xmlbuilder
      .create('EntityDescriptor')
      .att('xmlns', 'urn:oasis:names:tc:SAML:2.0:metadata')
      .att('xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#')
      .att('entityID', options.entity_id)
      .att('ID', options.entity_id.replace(/\W/g, '_'))
      .ele('SPSSODescriptor')
      .att('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol')
      .att('AuthnRequestsSigned', true)
      .att('WantAssertionsSigned', true)
      .ele('KeyDescriptor')
      .att('use', 'signing')
      .ele('ds:KeyInfo')
      .ele('ds:X509Data')
      .ele('ds:X509Certificate', cert)
      .up()
      .up()
      .up()
      .up()
      .ele('SingleLogoutService')
      .att('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
      .att('Location', options.assert_endpoint)
      .up()
      .ele('NameIDFormat', options.nameid_format)
      .up()
      .ele('AssertionConsumerService')
      .att('index', options.attributeConsumingServiceIndex)
      .att('isDefault', 'true')
      .att('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
      .att('Location', options.assert_endpoint)
      .up();

    if (options.attributes) {
      metadata = metadata
        .ele('AttributeConsumingService')
        .att('index', options.attributeConsumingServiceIndex)
        .ele('ServiceName', options.attributes.name)
        .att('xml:lang', 'it')
        .up();

      options.attributes.values.map((item) => {
        metadata = metadata
          .ele('RequestedAttribute')
          .att('Name', item)
          .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic')
          .att('FriendlyName', this.get_friendly_name(item))
          .up();
        return true;
      });
    }

    if (options.organization) {
      metadata = metadata
        .root()
        .ele('Organization')
        .ele('OrganizationName', options.organization.name)
        .att('xml:lang', 'it')
        .up()
        .ele('OrganizationDisplayName', options.organization.display_name)
        .att('xml:lang', 'it')
        .up()
        .ele('OrganizationURL', options.organization.url)
        .att('xml:lang', 'it');
    }

    const xml = metadata.end({
      pretty: true,
      indent: '  ',
      newline: '\n'
    });

    return xml.replace('<?xml version="1.0"?>', '');
  }

  get_friendly_name(name) {
    const friendly_names = {
      name: 'Nome',
      // eslint-disable-next-line snakecase/snakecase
      familyName: 'Cognome',
      // eslint-disable-next-line snakecase/snakecase
      fiscalNumber: 'Codice fiscale',
      email: 'Email'
    };

    return friendly_names[name];
  }

  create_authn_request() {
    const sp = this.options.sp;
    const idp = this.options.idp;

    // ID della richiseta... va memorizzato da qualche parte per poi riverificarlo...
    const id = '_' + crypto.randomBytes(21).toString('hex');

    let xml = xmlbuilder
      .create('samlp:AuthnRequest')
      .att('xmlns:samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
      .att('xmlns:saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
      .att('ID', id)
      .att('Version', '2.0')
      .att('IssueInstant', new Date().toISOString())
      .att('Destination', idp.sso_login_url)
      .att('AssertionConsumerServiceURL', sp.assert_endpoint)
      .att('ProtocolBinding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
      .att('ForceAuthn', sp.force_authn)
      .att('AttributeConsumingServiceIndex', sp.attributeConsumingServiceIndex)
      .ele('saml:Issuer', sp.entity_id)
      .att('NameQualifier', sp.entity_id)
      .att('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity')
      .up()
      .ele('samlp:NameIDPolicy')
      .att('Format', sp.nameid_format || 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
      .up()
      .ele('samlp:RequestedAuthnContext')
      .att('Comparison', sp.auth_context.comparison)
      .ele('saml:AuthnContextClassRef', sp.auth_context.class_refs[0])
      .up()
      .end({
        pretty: true,
        indent: '  ',
        newline: '\n'
      });

    xml = xml.replace('<?xml version="1.0"?>', '');

    return {
      id,
      xml
    };
  }

  get_request_url(request, logout = false) {
    return new Promise((res, rej) => {
      const sp = this.options.sp;
      const idp = this.options.idp;

      zlib.deflateRaw(request, (err, buffer) => {
        if (err) {
          rej(err);
          return;
        }

        const base64 = buffer.toString('base64');
        let target = url.parse(idp.sso_login_url, true);

        if (logout) {
          if (idp.sso_logout_url) {
            target = url.parse(idp.sso_logout_url, true);
          }
        }

        const saml_message = {
          // eslint-disable-next-line snakecase/snakecase
          SAMLRequest: base64
        };

        // Se ho un certificato firmo la richiesta.
        if (sp.private_key) {
          try {
            // sets .SigAlg and .Signature
            this.sign_request(saml_message);
          } catch (ex) {
            rej(ex);
            return;
          }
        }

        Object.keys(saml_message).forEach(function (k) {
          target.query[k] = saml_message[k];
        });

        delete target.search;

        res(url.format(target));
      });
    });
  }

  sign_request(saml_message) {
    const sp = this.options.sp;
    // const idp = this.options.idp;

    let signer;
    const saml_message_to_sign = {};
    switch (this.options.signature_algorithm) {
      case 'sha256':
        saml_message.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        signer = crypto.createSign('RSA-SHA256');
        break;
      case 'sha512':
        saml_message.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
        signer = crypto.createSign('RSA-SHA512');
        break;
      default:
        throw new Error('Algorithm "' + this.options.signature_algorithm + '" is not valid');
    }

    if (saml_message.SAMLRequest) {
      saml_message_to_sign.SAMLRequest = saml_message.SAMLRequest;
    }

    if (saml_message.RelayState) {
      saml_message_to_sign.RelayState = saml_message.RelayState;
    }

    if (saml_message.SigAlg) {
      saml_message_to_sign.SigAlg = saml_message.SigAlg;
    }

    signer.update(querystring.stringify(saml_message_to_sign));
    saml_message.Signature = signer.sign(sp.private_key, 'base64');
  }

  validate_response(saml_message) {
    const sp = new saml2.ServiceProvider(this.options.sp);
    const idp = new saml2.IdentityProvider(this.options.idp);

    return new Promise((res, rej) => {
      sp.post_assert(
        idp,
        { request_body: saml_message, allow_unencrypted_assertion: true, audience: this.options.sp.entity_id },
        (err, resp) => {
          if (err) {
            rej(err);
          } else {
            // Alcune verifiche vanno fatte a manina

            if (resp.response_header.destination !== this.options.sp.assert_endpoint) {
              rej(new Error('Invalid response destination'));
              return;
            }

            // Recupero il documento xml
            const xml = Buffer.from(saml_message.SAMLResponse, 'base64').toString('utf8');
            const parser = new xmldom.DOMParser();
            const doc = parser.parseFromString(xml);

            // Validazione ResponseData
            const confirm_data = doc.getElementsByTagNameNS(
              'urn:oasis:names:tc:SAML:2.0:assertion',
              'SubjectConfirmationData'
            );

            if (confirm_data.length === 0) {
              rej('No confirmation data');
            }
            if (confirm_data.item(0).getAttribute('Recipient') !== this.options.sp.assert_endpoint) {
              rej(new Error('Incorrect ResponseData recipient.'));
              return;
            }

            // Validazione Issuer
            const assertion = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion').item(0);
            if (!assertion) {
              rej(new Error('Assertion element is missing'));
              return;
            }
            const issuer = assertion.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer').item(0);
            if (!issuer || issuer.childNodes[0].data !== this.options.idp.entity_id) {
              if (!issuer) {
                rej(new Error('Assertion issuer not specified'));
              } else {
                rej(new Error('Invalid assertion issuer'));
              }
              return;
            }

            res(resp);
          }
        }
      );
    });
  }
}

// eslint-disable-next-line snakecase/snakecase
module.exports = { ServiceProvider };
