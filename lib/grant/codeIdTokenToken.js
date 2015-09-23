/**
 * Module dependencies.
 */
var url = require('url')
  , qs = require('querystring')
  , merge = require('utils-merge')
  , AuthorizationError = require('oauth2orize').AuthorizationError;


/**
 * Handles requests to obtain a response with an access token, authorization
 * code, and ID token.
 *
 * References:
 *  - [OpenID Connect Standard 1.0 - draft 21](http://openid.net/specs/openid-connect-standard-1_0.html)
 *  - [OpenID Connect Messages 1.0 - draft 20](http://openid.net/specs/openid-connect-messages-1_0.html)
 *  - [OAuth 2.0 Multiple Response Type Encoding Practices - draft 08](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Object} module
 * @api public
 */
module.exports = function(options, issueToken, issueCode, issueIDToken) {
  if (typeof options == 'function') {
    issueIDToken = issueCode;
    issueCode = issueToken;
    issueToken = options;
    options = undefined;
  }
  options = options || {};
  
  if (!issueToken) throw new TypeError('oauth2orize-openid.codeIDTokenToken grant requires an issueToken callback');
  if (!issueCode) throw new TypeError('oauth2orize-openid.codeIDTokenToken grant requires an issueCode callback');
  if (!issueIDToken) throw new TypeError('oauth2orize-openid.codeIDTokenToken grant requires an issueIDToken callback');
  
  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }
  
  
  /* Parse requests that request `code id_token token` as `response_type`.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
  function request(req) {
    var clientID = req.query['client_id']
      , redirectURI = req.query['redirect_uri']
      , scope = req.query['scope']
      , state = req.query['state'];
      
    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }
    
    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }
      
      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }
    
    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    }
  }
  
  /* Sends responses to transactions that request `code id_token token` as `response_type`.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  function response(txn, res, next) {
    if (!txn.redirectURI) { return next(new Error('Unable to issue redirect for OAuth 2.0 transaction')); }
    if (!txn.res.allow) {
      var err = {};
      err['error'] = 'access_denied';
      if (txn.req && txn.req.state) { err['state'] = txn.req.state; }
      
      var parsed = url.parse(txn.redirectURI);
      parsed.hash = qs.stringify(err);
      
      var location = url.format(parsed);
      return res.redirect(location);
    }
    
    function doIssueIDToken(tok) {
      function issued(err, idToken) {
        if (err) { return next(err); }
        if (!idToken) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }
      
        tok['id_token'] = idToken;
      
        var parsed = url.parse(txn.redirectURI);
        parsed.hash = qs.stringify(tok);
      
        var location = url.format(parsed);
        return res.redirect(location);
      }
    
      try {
        // NOTE: To facilitate code reuse, the `issueIDToken` callback should
        //       interoperate with the `issue` callback implemented by
        //       `oauth2orize-openid.grant.idToken`.
        
        var arity = issueIDToken.length;
        if (arity == 4) {
          // TODO: Pass any additional arguments that may be needed to issue an access token.
          //issueIDToken(txn.client, txn.user, scope, issued);
          //issueIDToken(txn.client, txn.user, scope, req, issued);
        } else { // arity == 3
          issueIDToken(txn.client, txn.user, issued);
        }
      } catch (ex) {
        return next(ex);
      }
    }
    
    function doIssueCode(tok) {
      function issued(err, code) {
        if (err) { return next(err); }
        if (!code) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }
      
        tok['code'] = code;
      
        doIssueIDToken(tok);
      }
      
      try {
        // NOTE: To facilitate code reuse, the `issueCode` callback should
        //       interoperate with the `issue` callback implemented by
        //       `oauth2orize.grant.code`.
        
        var arity = issueCode.length;
        if (arity == 5) {
          issueCode(txn.client, txn.req.redirectURI, txn.user, txn.res, issued);
        } else { // arity == 4
          issueCode(txn.client, txn.req.redirectURI, txn.user, issued);
        }
      } catch (ex) {
        return next(ex);
      }
    }
    
    function doIssueToken() {
      function issued(err, accessToken, params) {
        if (err) { return next(err); }
        if (!accessToken) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }
      
        var tok = {};
        tok['access_token'] = accessToken;
        if (params) { merge(tok, params); }
        tok['token_type'] = tok['token_type'] || 'Bearer';
        if (txn.req && txn.req.state) { tok['state'] = txn.req.state; }
      
        doIssueCode(tok);
      }
      
      try {
        // NOTE: To facilitate code reuse, the `issueToken` callback should
        //       interoperate with the `issue` callback implemented by
        //       `oauth2orize.grant.token`.
        
        var arity = issueToken.length;
        if (arity == 4) {
          issueToken(txn.client, txn.user, txn.res, issued);
        } else { // arity == 3
          issueToken(txn.client, txn.user, issued);
        }
      } catch (ex) {
        return next(ex);
      }
    }
    
    doIssueToken();
  }
  
  
  /**
   * Return `code id_token token` grant module.
   */
  var mod = {};
  mod.name = 'code id_token token';
  mod.request = request;
  mod.response = response;
  return mod;
}
