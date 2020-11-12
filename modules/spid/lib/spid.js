'use strict';
var url = require('url');
var zlib = require('zlib');
var crypto = require('crypto');
var xmldom = require('xmldom');
var saml2 = require('saml2-js');
var xmlbuilder = require('xmlbuilder');
var querystring = require('querystring');

class ServiceProvider {
  constructor(options) {
    this.options = options;
  }

  generateMetadata() {
    const options = this.options.sp;

    if (!options.certificate) {
      throw new Error('Missing certificate while generating metadata for decrypting service provider');
    }

    var cert = options.certificate.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
    cert = cert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
    cert = cert.replace(/\r\n/g, '\n');


    var metadata = xmlbuilder
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
            .ele("ds:KeyInfo")
              .ele('ds:X509Data')
                .ele('ds:X509Certificate', cert).up()
              .up()
            .up()
          .up()
          .ele('SingleLogoutService')
            .att('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
            .att('Location', options.assert_endpoint)
          .up()
          .ele('NameIDFormat', options.nameid_format).up()
          .ele("AssertionConsumerService")
            .att('index', options.attributeConsumingServiceIndex)
            .att('isDefault', 'true')
            .att('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
            .att('Location', options.assert_endpoint)
          .up();

    if (options.attributes) {
      function getFriendlyName(name) {
        const friendlyNames = {
          name: 'Nome',
          familyName: 'Cognome',
          fiscalNumber: 'Codice fiscale',
          email: 'Email'
        };

        return friendlyNames[name];
      }

      metadata = metadata.ele("AttributeConsumingService")
        .att('index', options.attributeConsumingServiceIndex)
        .ele('ServiceName', options.attributes.name)
          .att('xml:lang', 'it')
        .up()

      options.attributes.values.map(function (item) {
        metadata = metadata
          .ele("RequestedAttribute")
            .att('Name', item)
            .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic')
            .att('FriendlyName', getFriendlyName(item))
          .up();
      });
    }

    if (options.organization) {
      metadata = metadata.root()
      .ele("Organization")
      .ele('OrganizationName', options.organization.name)
        .att('xml:lang', 'it')
      .up()
      .ele('OrganizationDisplayName', options.organization.displayName)
        .att('xml:lang', 'it')
      .up()
      .ele('OrganizationURL', options.organization.URL)
        .att('xml:lang', 'it')
    }

    const xml = metadata.end({
      pretty: true,
      indent: '  ',
      newline: '\n'
    });

    return xml.replace('<?xml version="1.0"?>', '');

    // var sig = new xmlCrypto.SignedXml();
    // sig.signingKey = this.options.privateCert;
    // sig.keyInfoProvider = new MyKeyInfo(decryptionCert);
    // sig.addReference(
    //   "//*[local-name(.)='EntityDescriptor']",
    //   ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    //   'http://www.w3.org/2001/04/xmlenc#sha512'
    // );
    // sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    // sig.computeSignature(xml);

    // const signed = sig.getSignedXml();
    // return signed.replace('<?xml version="1.0"?>', '');
  }

  create_authn_request() {
    const sp = this.options.sp;
    const idp = this.options.idp;

    // ID della richiseta... va memorizzato da qualche parte per poi riverificarlo...
    let id = '_' + crypto.randomBytes(21).toString('hex');

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
        .ele('saml:Issuer',sp.entity_id)
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

  getRequestUrl(request, logout = false) {
    return new Promise((res, rej) => {
      const sp = this.options.sp;
      const idp = this.options.idp;

      zlib.deflateRaw(request || response, (err, buffer) => {
        if (err) {
          rej(err);
          return;
        }

        var base64 = buffer.toString('base64');
        var target = url.parse(idp.sso_login_url, true);

        if (logout) {
          if (idp.sso_logout_url) {
            target = url.parse(idp.sso_logout_url, true);
          }
        }

        var samlMessage = {
          SAMLRequest: base64
        };

        // Se ho un certificato firmo la richiesta.
        if (sp.private_key) {
          try {
            // sets .SigAlg and .Signature
            this.signRequest(samlMessage);
          } catch (ex) {
            rej(ex);
            return;
          }
        }

        Object.keys(samlMessage).forEach(function (k) {
          target.query[k] = samlMessage[k];
        });

        delete target.search;

        res(url.format(target));
      });
    });
  }

  signRequest(samlMessage) {
    const sp = this.options.sp;
    const idp = this.options.idp;

    var signer;
    var samlMessageToSign = {};
    switch (this.options.signatureAlgorithm) {
      case 'sha256':
        samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        signer = crypto.createSign('RSA-SHA256');
        break;
      case 'sha512':
        samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
        signer = crypto.createSign('RSA-SHA512');
        break;
      default:
        throw new Error('Algorithm "' + this.options.signatureAlgorithm + '" is not valid');
    }

    if (samlMessage.SAMLRequest) {
      samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
    }

    if (samlMessage.RelayState) {
      samlMessageToSign.RelayState = samlMessage.RelayState;
    }

    if (samlMessage.SigAlg) {
      samlMessageToSign.SigAlg = samlMessage.SigAlg;
    }

    signer.update(querystring.stringify(samlMessageToSign));
    samlMessage.Signature = signer.sign(sp.private_key, 'base64');
  }

  async validateResponse(samlMessage) {
    var sp = new saml2.ServiceProvider(this.options.sp);
    var idp = new saml2.IdentityProvider(this.options.idp);

    return new Promise((res, rej) => {
      sp.post_assert(
        idp,
        { request_body: samlMessage, allow_unencrypted_assertion: true, audience: this.options.sp.entity_id },
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
            const xml = Buffer.from(samlMessage.SAMLResponse, 'base64').toString('utf8');
            const parser = new xmldom.DOMParser();
            const doc = parser.parseFromString(xml);

            // Validazione ResponseData
            const confirmData = doc.getElementsByTagNameNS(
              'urn:oasis:names:tc:SAML:2.0:assertion',
              'SubjectConfirmationData'
            );
            if (confirmData.length === 0) rej('No confirmation data');
            if (confirmData.item(0).getAttribute('Recipient') !== this.options.sp.assert_endpoint) {
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

module.exports = { ServiceProvider };
