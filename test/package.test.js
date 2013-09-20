var openid = require('..');
  

describe('oauth2orize-openid', function() {
  
  it('should export extensions', function() {
    expect(openid.extensions).to.be.a('function');
  });
  
});
