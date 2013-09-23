/**
 * Module dependencies.
 */
var AuthorizationError = require('oauth2orize').AuthorizationError;

/**
 * Parse request parameters defined by OpenID Connect.
 *
 * This module is a wildcard parser that parses authorization requests for
 * extensions parameters defined by OpenID Connect.
 *
 * Examples:
 *
 *     server.grant(openid.extensions());
 *
 * References:
 *  - [OpenID Connect Basic Client Profile 1.0 - draft 28](http://openid.net/specs/openid-connect-basic-1_0.html)
 *  - [OpenID Connect Implicit Client Profile 1.0 - draft 11](http://openid.net/specs/openid-connect-implicit-1_0.html)
 *  - [OpenID Connect Messages 1.0 - draft 20](http://openid.net/specs/openid-connect-messages-1_0.html)
 *
 * @return {Object} module
 * @api public
 */
module.exports = function() {
  
  function request(req) {
    var q = req.query
      , ext = {};
    
    ext.nonce = q.nonce;
    ext.display = q.display || 'page';
    if (q.prompt) { ext.prompt = q.prompt.split(' '); }
    if (q.max_age) { ext.maxAge = parseInt(q.max_age); }
    if (q.ui_locales) { ext.uiLocales = q.ui_locales.split(' '); }
    if (q.claims_locales) { ext.claimsLocales = q.claims_locales.split(' '); }
    ext.idTokenHint = q.id_token_hint;
    ext.loginHint = q.login_hint;
    if (q.acr_values) { ext.acrValues = q.acr_values.split(' '); }
    
    // TODO: Add support for "claims" parameter
    // TODO: Add support for "registration" parameter
    // TODO: Add support for "request" parameter
    // TODO: Add support for "request_uri" parameter
    
    if (ext.prompt && ext.prompt.length > 1) {
      if (ext.prompt.indexOf('none') != -1) { throw new AuthorizationError('Prompt includes none with other values', 'invalid_request'); }
    }
    
    return ext;
  }
  
  var mod = {};
  mod.name = '*';
  mod.request = request;
  return mod;
}
