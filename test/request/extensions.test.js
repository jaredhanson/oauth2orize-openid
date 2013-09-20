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

});