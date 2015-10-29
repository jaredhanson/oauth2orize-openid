var chai = require('chai')
  , codeToken = require('../../lib/grant/codeToken');
  
  
describe('grant.codeToken', function() {
  
  describe('module', function() {
    var mod = codeToken(function(){}, function(){});
    
    it('should be named code token', function() {
      expect(mod.name).to.equal('code token');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });
  
  it('should throw if constructed without a issueToken callback', function() {
    expect(function() {
      codeToken();
    }).to.throw(TypeError, 'oauth2orize-openid.codeToken grant requires an issueToken callback');
  });
  
  it('should throw if constructed without a issueCode callback', function() {
    expect(function() {
      codeToken(function(){});
    }).to.throw(TypeError, 'oauth2orize-openid.codeToken grant requires an issueCode callback');
  });
  
  describe('request parsing', function() {
    function issueToken(){}
    function issueCode(){}
    
    describe('request', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(codeToken(issueToken, issueCode))
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
