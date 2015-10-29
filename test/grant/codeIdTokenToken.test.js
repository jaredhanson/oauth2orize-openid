var chai = require('chai')
  , codeIdTokenToken = require('../../lib/grant/codeIdTokenToken');
  
  
describe('grant.codeIdTokenToken', function() {
  
  describe('module', function() {
    var mod = codeIdTokenToken(function(){}, function(){}, function(){});
    
    it('should be named code token', function() {
      expect(mod.name).to.equal('code id_token token');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });
  
  it('should throw if constructed without a issueToken callback', function() {
    expect(function() {
      codeIdTokenToken();
    }).to.throw(TypeError, 'oauth2orize-openid.codeIDTokenToken grant requires an issueToken callback');
  });
  
  it('should throw if constructed without a issueCode callback', function() {
    expect(function() {
      codeIdTokenToken(function(){});
    }).to.throw(TypeError, 'oauth2orize-openid.codeIDTokenToken grant requires an issueCode callback');
  });
  
  it('should throw if constructed without a issueIDToken callback', function() {
    expect(function() {
      codeIdTokenToken(function(){}, function(){});
    }).to.throw(TypeError, 'oauth2orize-openid.codeIDTokenToken grant requires an issueIDToken callback');
  });
  
});
