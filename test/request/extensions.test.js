var chai = require('chai')
  , extensions = require('../../lib/request/extensions');


describe('authorization request extensions', function() {
  
  describe('module', function() {
    var mod = extensions();
    
    it('should be wildcard', function() {
      expect(mod.name).to.equal('*');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.undefined;
    });
  });
  
  describe('request parsing', function() {
    
    describe('request with all parameters', function() {
      var err, ext;
      
      before(function(done) {
        chai.grant(extensions())
          .req(function(req) {
            req.query = {};
            req.query.nonce = 'a1b2c3';
            req.query.display = 'touch';
            req.query.prompt = 'none';
            req.query.max_age = '600';
            req.query.ui_locales = 'en-US';
            req.query.claims_locales = 'en';
            req.query.id_token_hint = 'HEADER.PAYLOAD.SIGNATURE';
            req.query.login_hint = 'bob@example.com';
            req.query.acr_values = '0';
          })
          .parse(function(e, o) {
            err = e;
            ext = o;
            done();
          })
          .authorize();
      });
      
      it('should not error', function() {
        expect(err).to.be.null;
      });
      
      it('should parse request', function() {
        expect(ext.nonce).to.equal('a1b2c3');
        expect(ext.display).to.equal('touch');
        expect(ext.prompt).to.be.an('array');
        expect(ext.prompt).to.have.length(1);
        expect(ext.prompt[0]).to.equal('none');
        expect(ext.maxAge).to.equal(600);
        expect(ext.uiLocales).to.be.an('array');
        expect(ext.uiLocales).to.have.length(1);
        expect(ext.uiLocales[0]).to.equal('en-US');
        expect(ext.claimsLocales).to.be.an('array');
        expect(ext.claimsLocales).to.have.length(1);
        expect(ext.claimsLocales[0]).to.equal('en');
        expect(ext.idTokenHint).to.equal('HEADER.PAYLOAD.SIGNATURE');
        expect(ext.loginHint).to.equal('bob@example.com');
        expect(ext.acrValues).to.be.an('array');
        expect(ext.acrValues).to.have.length(1);
        expect(ext.acrValues[0]).to.equal('0');
      });
    });
    
  });

});