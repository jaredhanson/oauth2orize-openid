var chai = require('chai')
  , idTokenToken = require('../../lib/grant/idTokenToken');
  
  
describe('grant.idTokenToken', function() {
  
  describe('module', function() {
    var mod = idTokenToken(function(){}, function(){});
    
    it('should be named id_token token', function() {
      expect(mod.name).to.equal('id_token token');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });
  
  it('should throw if constructed without a issueToken callback', function() {
    expect(function() {
      idTokenToken();
    }).to.throw(TypeError, 'oauth2orize-openid.idTokenToken grant requires an issueToken callback');
  });
  
  it('should throw if constructed without a issueIDToken callback', function() {
    expect(function() {
      idTokenToken(function(){});
    }).to.throw(TypeError, 'oauth2orize-openid.idTokenToken grant requires an issueIDToken callback');
  });
  
  describe('request parsing', function() {
    function issueToken(){}
    function issueIDToken(){}
    
    describe('request', function() {
      var err, out;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken({ scopeSeparator: ',' }, issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken({ scopeSeparator: [' ', ','] }, issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken({ scopeSeparator: [' ', ','] }, issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
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
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .req(function(req) {
            req.query = {};
            req.query.client_id = 'c123';
            req.query.redirect_uri = 'http://example.com/auth/callback';
            req.query.scope = ['read', 'write'];
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
        expect(err.message).to.equal('Invalid parameter: scope must be a string');
        expect(err.code).to.equal('invalid_request');
      });
    });
  });
  
  describe('issuing an access token', function() {
    
    describe('based on client, user, and authorization response', function() {
      function issueToken(client, user, ares, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(ares.scope).to.equal('foo');
        
        return done(null, 'xyz');
      }
    
      function issueIDToken(client, user, areq, done) {
        return done(null, 'idtoken');
      }
      
      var response;
    
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true, scope: 'foo' };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
    
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&id_token=idtoken');
      });
    });
    
    describe('based on client, user, and authorization response, that adds additional parameters', function() {
      function issueToken(client, user, ares, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(ares.scope).to.equal('foo');
        
        return done(null, 'xyz', { 'expires_in': 3600 });
      }
    
      function issueIDToken(client, user, areq, done) {
        return done(null, 'idtoken');
      }
      
      var response;
    
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true, scope: 'foo' };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
    
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&expires_in=3600&token_type=Bearer&id_token=idtoken');
      });
    });
    
    describe('based on client, user, and authorization response, while preserving state', function() {
      function issueToken(client, user, ares, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(ares.scope).to.equal('foo');
        
        return done(null, 'xyz');
      }
    
      function issueIDToken(client, user, areq, done) {
        return done(null, 'idtoken');
      }
      
      var response;
    
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj',
              state: 'f1o1o1'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true, scope: 'foo' };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
    
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&state=f1o1o1&id_token=idtoken');
      });
    });
    
    describe('based on client, user, authorization request, authorization response, and transaction locals', function() {
      function issueToken(client, user, ares, areq, locals, done) {
        expect(client.id).to.equal('c123');
        expect(client.name).to.equal('Example');
        expect(user.id).to.equal('u123');
        expect(user.name).to.equal('Bob');
        expect(ares.allow).to.equal(true);
        expect(areq.redirectURI).to.equal('http://example.com/auth/callback');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(locals.foo).to.equal('bar');

        return done(null, 'xyz');
      }
      
      function issueIDToken(client, user, ares, areq, opts, done) {
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
            txn.locals = { foo: 'bar' };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&id_token=idtoken');
      });
    });
    
  });
  
  describe('issuing an ID token', function() {
    
    describe('based on client, user, and authorization request', function() {
      function issueToken(client, user, ares, done) {
        return done(null, 'xyz');
      }
      
      function issueIDToken(client, user, areq, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
            txn.locals = { foo: 'bar' };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&id_token=idtoken');
      });
    });
    
    describe('based on client, user, authorization response, authorization request, and bound parameters', function() {
      function issueToken(client, user, ares, done) {
        return done(null, 'xyz');
      }
      
      function issueIDToken(client, user, ares, areq, bound, done) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(ares.allow).to.equal(true);
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(bound.accessToken).to.equal('xyz');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              nonce: 'n-0S6_WzA2Mj'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
            txn.locals = { foo: 'bar' };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&id_token=idtoken');
      });
    });
    
  });
  
  describe('decision handling', function() {
    
    describe('transaction that adds params including token_type to response', function() {
      function issueToken(client, user, done) {
        if (client.id == 'c323' && user.id == 'u123') {
          return done(null, 'xyz', { 'token_type': 'foo', 'expires_in': 3600 });
        }
        return done(new Error('something is wrong'));
      }
      
      function issueIDToken(client, user, ares, areq, opts, done) {
        expect(client.id).to.equal('c323');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(opts.accessToken).to.equal('xyz');
        
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c323', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
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
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=foo&expires_in=3600&id_token=idtoken');
      });
    });
    
    describe('disallowed transaction', function() {
      function issueToken(client, user, done) {
        if (client.id == 'c123' && user.id == 'u123') {
          return done(null, 'xyz');
        }
        return done(new Error('something is wrong'));
      }
      
      function issueIDToken(client, user, areq, accessToken, done) {
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback'
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
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#error=access_denied');
      });
    });
    
    describe('disallowed transaction with request state', function() {
      function issueToken(client, user, done) {
        if (client.id == 'c123' && user.id == 'u123') {
          return done(null, 'xyz');
        }
        return done(new Error('something is wrong'));
      }
      
      function issueIDToken(client, user, areq, accessToken, done) {
        return done(null, 'idtoken');
      }
      
      
      var response;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback',
              state: 'f2o2o2'
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
        expect(response.getHeader('Location')).to.equal('http://example.com/auth/callback#error=access_denied&state=f2o2o2');
      });
    });
    
    describe('unauthorized client', function() {
      function issueToken(client, user, done) {
        if (client.id == 'cUNAUTHZ') {
          return done(null, false);
        }
        return done(new Error('something is wrong'));
      }
      
      function issueIDToken(client, user, areq, accessToken, done) {
        return done(null, 'idtoken');
      }
      
      
      var err;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'cUNAUTHZ', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
          })
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Request denied by authorization server');
        expect(err.code).to.equal('access_denied');
        expect(err.status).to.equal(403);
      });
    });
    
    describe('encountering an error while issuing token', function() {
      function issueToken(client, user, done) {
        if (client.id == 'cUNAUTHZ') {
          return done(null, false);
        }
        return done(new Error('something is wrong'));
      }
      
      function issueIDToken(client, user, areq, accessToken, done) {
        return done(null, 'idtoken');
      }
      
      
      var err;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'cERROR', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
          })
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something is wrong');
      });
    });
    
    describe('throwing an error while issuing token', function() {
      function issueToken(client, user, done) {
        if (client.id == 'cTHROW') {
          throw new Error('something was thrown');
        }
        return done(new Error('something is wrong'));
      }

      function issueIDToken(client, user, areq, accessToken, done) {
        return done(null, 'idtoken');
      }
      
      var err;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'cTHROW', name: 'Example' };
            txn.redirectURI = 'http://example.com/auth/callback';
            txn.req = {
              redirectURI: 'http://example.com/auth/callback'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
          })
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something was thrown');
      });
    });
    
    describe('transaction without redirect URL', function() {
      function issueToken(client, user, done) {
        if (client.id == 'c123' && user.id == 'u123') {
          return done(null, 'xyz');
        }
        return done(new Error('something is wrong'));
      }
      
      function issueIDToken(client, user, areq, accessToken, done) {
        return done(null, 'idtoken');
      }
      
      
      var err;
      
      before(function(done) {
        chai.oauth2orize.grant(idTokenToken(issueToken, issueIDToken))
          .txn(function(txn) {
            txn.client = { id: 'c123', name: 'Example' };
            txn.req = {
              redirectURI: 'http://example.com/auth/callback'
            };
            txn.user = { id: 'u123', name: 'Bob' };
            txn.res = { allow: true };
          })
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('Unable to issue redirect for OAuth 2.0 transaction');
      });
    });
  });

});