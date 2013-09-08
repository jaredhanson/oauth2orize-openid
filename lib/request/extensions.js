module.exports = function() {
  
  function request(req) {
    var q = req.query
      , ext = {};
    
    if (q.nonce) { ext.nonce = q.nonce; }
    
    ext.display = q.display || 'page';
    if (q.prompt) { ext.prompt = q.prompt.split(' '); }
    
    // TODO: If prompt contains `none` and any other value, throw an error
    
    if (q.max_age) { ext.maxAge = q.max_age; }
    if (q.ui_locales) { ext.uiLocales = q.ui_locales.split(' '); }
    if (q.claims_locales) { ext.claimsLocales = q.claims_locales.split(' '); }
    if (q.id_token_hint) { ext.idTokenHint = q.id_token_hint; }
    if (q.login_hint) { ext.loginHint = q.login_hint; }
    if (q.acr_values) { ext.acrValues = q.acrValues; }
    
    return ext;
  }
  
  var mod = {};
  mod.name = '*';
  mod.request = request;
  return mod;
}
