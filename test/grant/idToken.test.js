var chai = require('chai')
  , idToken = require('../../lib/grant/idToken');
  
  
describe('grant.idToken', function() {
  
  describe('module', function() {
    var mod = idToken(function(){});
    
    it('should be named id_token', function() {
      expect(mod.name).to.equal('id_token');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });
  
  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      idToken();
    }).to.throw(TypeError, 'oauth2orize-openid.idToken grant requires an issue callback');
  });
  
  describe('request parsing', function() {
    function issue(){}
    
    describe('request', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issue))
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
    
    describe('request with scope', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issue))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.scope = 'read';
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
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(1);
        expect(out.scope[0]).to.equal('read');
        expect(out.state).to.equal('f1o1o1');
      });
    });
    
    describe('request with list of scopes', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issue))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.scope = 'read write';
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
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });
    
    describe('request with list of scopes using scope separator option', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken({ scopeSeparator: ',' }, issue))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.scope = 'read,write';
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
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });
    
    describe('request with list of scopes separated by space using multiple scope separator option', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken({ scopeSeparator: [' ', ','] }, issue))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.scope = 'read write';
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
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });
    
    describe('request with list of scopes separated by comma using multiple scope separator option', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken({ scopeSeparator: [' ', ','] }, issue))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.scope = 'read,write';
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
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });
    
    describe('request with missing client_id parameter', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issue))
          .req(function(req) {
            req.query = {};
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
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Missing required parameter: client_id');
        expect(err.code).to.equal('invalid_request');
      });
    });
    
    describe('request with scope parameter that is not a string', function() {
       var err, out;
      
       before(function(done) {
         chai.oauth2orize.grant(idToken(issue))
           .req(function(req) {
             req.query = {};
             req.query.client_id = 'c123';
             req.query.redirect_uri = 'http://example.com/auth/callback';
             req.query.state = 'f1o1o1';
             req.query.scope = ['read', 'write'];
           })
           .parse(function(e, o) {
             err = e;
             out = o;
             done();
           })
           .authorize();
       });
      
       it('should error', function() {
         expect(err).to.be.an.instanceOf(Error);
         expect(err.constructor.name).to.equal('AuthorizationError');
         expect(err.message).to.equal('Invalid parameter: scope must be a string');
         expect(err.code).to.equal('invalid_request');
       });
     });
  });
  
  describe('decision handling', function() {
    
    describe('transaction', function() {
      function issueIDToken(client, user, areq, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://www.example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback#id_token=idtoken');
      });
    });
    
    describe('transaction with request state', function() {
      function issueIDToken(client, user, areq, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://www.example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj',
              state: 'f1o1o1'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback#id_token=idtoken&state=f1o1o1');
      });
    });
    
    describe('disallowed transaction', function() {
      function issueIDToken(client, user, areq, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://www.example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: false };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback#error=access_denied');
      });
    });
    
    describe('disallowed transaction with request state', function() {
      function issueIDToken(client, user, areq, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idToken(issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://www.example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj',
              state: 'f1o1o1'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: false };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback#error=access_denied&state=f1o1o1');
      });
    });
    
  });
  
});
