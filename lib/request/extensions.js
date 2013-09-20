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
    
    // TODO: If prompt contains `none` and any other value, throw an error
    
    if (q.max_age) { ext.maxAge = parseInt(q.max_age); }
    if (q.ui_locales) { ext.uiLocales = q.ui_locales.split(' '); }
    if (q.claims_locales) { ext.claimsLocales = q.claims_locales.split(' '); }
    ext.idTokenHint = q.id_token_hint;
    ext.loginHint = q.login_hint;
    if (q.acr_values) { ext.acrValues = q.acr_values.split(' '); }
    
    
    
    return ext;
  }
  
  var mod = {};
  mod.name = '*';
  mod.request = request;
  return mod;
}
