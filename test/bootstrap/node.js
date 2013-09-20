var chai = require('chai')
  , grant = require('chai-oauth2orize-grant');

chai.use(grant);

global.expect = chai.expect;
