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
  
  describe('request parsing', function() {
    function issueToken(){}
    function issueCode(){}
    function issueIDToken(){}
    
    describe('request', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(codeIdTokenToken(issueToken, issueCode, issueIDToken))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.state = 'f1o1o1';
          })
          .parse(function(e, o) {
            err = e;
            out = o;
            done();
          })
          .authorize();
      });
      
      it('should not error', function() {
        expect(err).to.be.null;
      });
      
      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.undefined;
        expect(out.state).to.equal('f1o1o1');
      });
    });
  });
  
});
